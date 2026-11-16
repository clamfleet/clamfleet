// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// backup.go: a consistent copy of the database with VACUUM INTO (milestone 6,
// plan 4.4 and 4.5), published without ever exposing a partial file.
//
// Protocol (the numbers are the rows of the plan's stage table; the test seam
// `backupHook` is called at the ENTRY of each stage, and an error it returns
// fails that stage, so a test can fail every stage in turn):
//  1. directory checks and the lock;
//  2. VACUUM INTO a fresh temporary file on a dedicated connection;
//  3. fsync the file;
//  4. optionally verify the copy (integrity_check and the schema version);
//  5. link the temporary file to its final name (no replace);
//  6. remove the temporary name;
//  7. fsync the directory;
//  8. prune old backups.
//
// A failure before stage 5 leaves no final file and no temporary file. After
// stage 5 the backup is published and is never deleted by a later failure.
//
// Why VACUUM INTO and not a file copy: it reads through SQLite, so the copy is
// transactionally consistent while the server keeps writing (WAL), and it is
// compact. Why a dedicated connection: the writer is a single connection that
// ingest needs, and the read pool is query_only, which VACUUM INTO may refuse.
//
// Secrets: a backup holds every row, including paths beyond retention, sealed
// secrets and password hashes, so everything here is 0600 and the directory
// must be 0700 and owned by the user running the backup. The key file is not in
// the database and is not copied.
package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// BackupKind selects the file name and the --keep family.
type BackupKind int

const (
	// BackupRegular writes clamfleet-<UTC stamp>-v<schema>.db.
	BackupRegular BackupKind = iota
	// BackupPreMigrate writes pre-migrate-v<from>-to-v<to>-<UTC stamp>.db and
	// keeps the newest preMigrateKeep of its own family.
	BackupPreMigrate
)

// preMigrateKeep is how many pre-migrate backups survive (plan 4.5).
const preMigrateKeep = 3

// ErrBackupBusy: another backup holds the lock.
var ErrBackupBusy = errors.New("another backup is running")

// BackupOptions configures Backup.
type BackupOptions struct {
	// Dir is the backup directory: an existing real directory (not a symlink)
	// owned by the effective user with mode 0700, or a missing one that is created.
	Dir  string
	Kind BackupKind
	// Verify opens the copy read-only and checks integrity_check and the schema version.
	Verify bool
	// Keep: for BackupRegular, keep this many newest backups (0 = all). Only files
	// that match the exact name pattern are ever deleted.
	Keep int
	// LockWait is how long to wait for the lock; 0 fails at once with ErrBackupBusy.
	LockWait time.Duration
	// Now is the clock for the file name (UTC). Required.
	Now func() time.Time
}

// BackupResult says what was published. Path is set whenever the backup file
// exists, also when a later stage (directory sync, --keep) reported an error.
type BackupResult struct {
	Path     string
	Size     int64
	Warnings []string
}

var (
	regularBackupRE    = regexp.MustCompile(`^clamfleet-(\d{8}T\d{6}Z)-v\d+\.db$`)
	preMigrateBackupRE = regexp.MustCompile(`^pre-migrate-v\d+-to-v\d+-(\d{8}T\d{6}Z)\.db$`)
)

const stampLayout = "20060102T150405Z"

// Backup writes a backup per the protocol in the file comment. Side effects: a
// lock file, a temporary file, the published backup, and deleted old backups.
func (s *Store) Backup(ctx context.Context, o BackupOptions) (BackupResult, error) {
	var res BackupResult
	if o.Now == nil {
		return res, errors.New("backup: no clock")
	}
	hook := func(stage int) error {
		if s.backupHook == nil {
			return nil
		}
		return s.backupHook(stage)
	}

	// Stage 1: directory checks, lock, free space.
	if err := hook(1); err != nil {
		return res, err
	}
	if err := s.checkBackupDir(o.Dir); err != nil {
		return res, err
	}
	unlock, err := lockBackupDir(ctx, o.Dir, o.LockWait)
	if err != nil {
		return res, err
	}
	defer unlock()
	removeStaleTemps(o.Dir, o.Now())
	from, err := s.SchemaVersion(ctx)
	if err != nil {
		return res, err
	}
	if err := s.checkFreeSpace(o.Dir); err != nil {
		return res, err
	}

	// Stage 2: VACUUM INTO a fresh temporary file. The file is created here, 0600
	// and empty, because SQLite creates its own target with the process umask
	// (0644 under the usual 022): a copy of every secret must never be group- or
	// world-readable, not even for the moment before a chmod. VACUUM INTO accepts
	// an existing empty file.
	tmp, err := newTempName(o.Dir)
	if err != nil {
		return res, err
	}
	published := false
	defer func() {
		if !published {
			os.Remove(tmp)
		}
	}()
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return res, fmt.Errorf("backup: create %s: %w", tmp, err)
	}
	f.Close()
	if err := hook(2); err != nil {
		return res, err
	}
	if err := s.vacuumInto(ctx, tmp); err != nil {
		return res, err
	}

	// Stage 3: fsync the data, and fchmod once more in case the file system lied.
	if err := hook(3); err != nil {
		return res, err
	}
	if err := syncFile(tmp); err != nil {
		return res, fmt.Errorf("backup: sync copy: %w", err)
	}

	// Stage 4: verify.
	if err := hook(4); err != nil {
		return res, err
	}
	if o.Verify {
		if err := verifyCopy(ctx, tmp, from); err != nil {
			return res, fmt.Errorf("backup failed verification: %w", err)
		}
	}

	// Stage 5: publish with a hard link, which fails with EEXIST instead of
	// replacing: an existing backup is never overwritten. A taken name moves to
	// the next second's.
	if err := hook(5); err != nil {
		return res, err
	}
	var final string
	for i := 0; ; i++ {
		if i == 5 {
			return res, fmt.Errorf("backup: no free file name in %s after 5 tries", o.Dir)
		}
		name := s.backupName(o, from, o.Now().UTC().Add(time.Duration(i)*time.Second))
		final = filepath.Join(o.Dir, name)
		err := os.Link(tmp, final)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return res, fmt.Errorf("backup: publish %s: %w", final, err)
		}
	}
	published = true
	res.Path = final

	// Stage 6: remove the temporary name. A failure only leaves a stale temp file
	// (the next run removes it) and is a warning: the backup is published.
	if err := hook(6); err != nil {
		res.Warnings = append(res.Warnings, "could not remove the temporary file "+filepath.Base(tmp)+": "+err.Error())
	} else if err := os.Remove(tmp); err != nil {
		res.Warnings = append(res.Warnings, "could not remove the temporary file "+filepath.Base(tmp)+": "+err.Error())
	}
	if fi, err := os.Stat(final); err == nil {
		res.Size = fi.Size()
	}

	// Stage 7: the new name must survive a power cut.
	err = hook(7)
	if err == nil {
		err = syncDir(o.Dir)
	}
	if err != nil {
		return res, fmt.Errorf("backup published as %s; directory sync failed: %w", final, err)
	}

	// Stage 8: --keep, still under the lock, so it never sees a backup in progress.
	err = hook(8)
	if err == nil {
		err = keepNewest(o)
	}
	if err != nil {
		return res, fmt.Errorf("backup published as %s; keeping only the newest failed: %w", final, err)
	}
	return res, nil
}

func (s *Store) backupName(o BackupOptions, from int64, at time.Time) string {
	stamp := at.Format(stampLayout)
	if o.Kind == BackupPreMigrate {
		return fmt.Sprintf("pre-migrate-v%d-to-v%d-%s.db", from, s.newestEmbedded(), stamp)
	}
	return fmt.Sprintf("clamfleet-%s-v%d.db", stamp, from)
}

// checkBackupDir enforces what a directory of personal data needs: a real
// directory (not a symlink someone could point elsewhere), owned by the user
// running the backup, with no group or other permission bits. A missing
// directory is created 0700, but never by a user who does not own its parent
// (a root-run backup would create a directory the server user cannot use).
func (s *Store) checkBackupDir(dir string) error {
	euid := os.Geteuid()
	if s.backupEUID != nil {
		euid = s.backupEUID()
	}
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		pfi, perr := os.Stat(filepath.Dir(dir))
		if perr != nil {
			return fmt.Errorf("backup directory %s: %w", dir, perr)
		}
		if owner, ok := fileOwner(pfi); ok && int(owner) != euid {
			return fmt.Errorf("refusing to create the backup directory %s as uid %d: its parent is owned by uid %d; run this as the server user (sudo -u clamfleet-server clamfleet-server backup)", dir, euid, owner)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			return fmt.Errorf("create backup directory: %w", err)
		}
		return os.Chmod(dir, 0o700) // Mkdir applies the umask
	}
	if err != nil {
		return fmt.Errorf("backup directory %s: %w", dir, err)
	}
	if !fi.IsDir() { // Lstat: a symlink is not a directory here
		return fmt.Errorf("backup directory %s is not a real directory (a symlink or a file is refused)", dir)
	}
	if owner, ok := fileOwner(fi); ok && int(owner) != euid {
		return fmt.Errorf("backup directory %s is owned by uid %d, not by the user running the backup (uid %d)", dir, owner, euid)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("backup directory %s has mode %04o: backups hold personal data and sealed secrets, so it must not be accessible to group or others; run `chmod 0700 %s`", dir, fi.Mode().Perm(), dir)
	}
	return nil
}

func fileOwner(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// lockBackupDir takes an exclusive flock on DIR/.lock. A second backup fails at
// once (wait 0); the backup before a migration waits, because the migration must
// not run without one.
func lockBackupDir(ctx context.Context, dir string, wait time.Duration) (unlock func(), err error) {
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("backup lock: %w", err)
	}
	deadline := time.Now().Add(wait) // a real-time wait for another process, not a stored timestamp
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
		}
		if err != syscall.EWOULDBLOCK {
			f.Close()
			return nil, fmt.Errorf("backup lock: %w", err)
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, ErrBackupBusy
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// removeStaleTemps deletes .tmp-*.db files older than an hour: leftovers of a
// crash between link and remove. Under the lock, so it never meets a live one.
func removeStaleTemps(dir string, now time.Time) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), ".tmp-") || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() && now.Sub(fi.ModTime()) > time.Hour {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

func newTempName(dir string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return filepath.Join(dir, ".tmp-"+hex.EncodeToString(b)+".db"), nil
}

// checkFreeSpace refuses a backup that cannot fit: free space must be at least
// 1.1 times the database file, so a full disk fails before anything is written
// (plan 4.5).
func (s *Store) checkFreeSpace(dir string) error {
	fi, err := os.Stat(s.path)
	if err != nil {
		return fmt.Errorf("backup: stat database: %w", err)
	}
	var free uint64
	if s.backupFree != nil {
		free = s.backupFree()
	} else {
		var st syscall.Statfs_t
		if err := syscall.Statfs(dir, &st); err != nil {
			return fmt.Errorf("backup: statfs %s: %w", dir, err)
		}
		free = st.Bavail * uint64(st.Bsize)
	}
	need := uint64(float64(fi.Size()) * 1.1)
	if free < need {
		return fmt.Errorf("not enough free space for a backup in %s: %d bytes free, %d needed (1.1 x the database)", dir, free, need)
	}
	return nil
}

// vacuumInto runs VACUUM INTO on a connection of its own: not the writer, which
// ingest needs, and not the query_only pool [A8]. The file name is a bound
// parameter, never concatenated.
func (s *Store) vacuumInto(ctx context.Context, target string) error {
	db, err := sql.Open("sqlite", dsn(s.path, ""))
	if err != nil {
		return fmt.Errorf("backup: open: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, target); err != nil {
		return fmt.Errorf("backup: VACUUM INTO: %w", err)
	}
	return nil
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	return f.Sync()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// verifyCopy opens the copy read-only and checks it is a sound database at the
// source's schema version.
func verifyCopy(ctx context.Context, path string, wantVersion int64) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var res string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&res); err != nil {
		return fmt.Errorf("integrity_check: %w", err)
	}
	if res != "ok" {
		return fmt.Errorf("integrity_check: %s", res)
	}
	var v sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&v); err != nil {
		return fmt.Errorf("schema version of the copy: %w", err)
	}
	if v.Int64 != wantVersion {
		return fmt.Errorf("the copy is at schema version %d, the database at %d", v.Int64, wantVersion)
	}
	return nil
}

// keepNewest deletes the oldest backups of this kind beyond the limit. Rule:
// only files whose name matches the exact pattern are candidates; a notes.txt or
// a hand-made clamfleet-x.db is never touched.
func keepNewest(o BackupOptions) error {
	re, keep := regularBackupRE, o.Keep
	if o.Kind == BackupPreMigrate {
		re, keep = preMigrateBackupRE, preMigrateKeep
	}
	if keep <= 0 {
		return nil
	}
	ents, err := os.ReadDir(o.Dir)
	if err != nil {
		return err
	}
	type bk struct{ stamp, name string }
	var all []bk
	for _, e := range ents {
		if m := re.FindStringSubmatch(e.Name()); m != nil && e.Type().IsRegular() {
			all = append(all, bk{m[1], e.Name()})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].stamp != all[j].stamp {
			return all[i].stamp > all[j].stamp // newest first
		}
		return all[i].name > all[j].name
	})
	var errs []error
	for _, b := range all[min(keep, len(all)):] {
		if err := os.Remove(filepath.Join(o.Dir, b.name)); err != nil {
			errs = append(errs, fmt.Errorf("could not delete %s: %w", b.name, err))
		}
	}
	return errors.Join(errs...)
}
