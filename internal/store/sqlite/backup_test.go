// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

func backupDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func bopts(dir string) BackupOptions {
	return BackupOptions{Dir: dir, Verify: true, Now: func() time.Time { return t0 }}
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if e.Name() != ".lock" {
			out = append(out, e.Name())
		}
	}
	return out
}

func seedReports(t *testing.T, s *Store, n int) {
	t.Helper()
	h, err := s.HostByName(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		record(t, s, h.ID, rep("a", t0.Add(time.Duration(i)*time.Second), "1"), t0)
	}
}

// The copy opens, passes integrity_check, carries the same rows and schema
// version, is 0600 and is named by the injected clock and the schema.
func TestBackupCopyIsConsistentAndPrivate(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	seedReports(t, s, 20)
	dir := backupDir(t)
	res, err := s.Backup(ctx, bopts(dir))
	if err != nil {
		t.Fatal(err)
	}
	v, _ := s.SchemaVersion(ctx)
	if want := filepath.Join(dir, fmt.Sprintf("clamfleet-20261112T100000Z-v%d.db", v)); res.Path != want {
		t.Fatalf("path %s, want %s", res.Path, want)
	}
	fi, err := os.Stat(res.Path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
	db, err := sql.Open("sqlite", "file:"+res.Path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM reports`).Scan(&n); err != nil || n != 20 {
		t.Fatalf("copy has %d reports, %v", n, err)
	}
	if got := names(t, dir); len(got) != 1 {
		t.Fatalf("directory holds %v: a temporary file was left", got)
	}
}

// Every stage of the plan's table is failed in turn, and the outcome of each is
// asserted: nothing final before stage 5; no temporary file after stages 2-5; the
// backup kept after 6 and 7; foreign files untouched after 8.
func TestBackupStageFailures(t *testing.T) {
	boom := errors.New("injected")
	for _, c := range []struct {
		stage         int
		wantErr       bool
		wantPublished bool
	}{
		{1, true, false}, {2, true, false}, {3, true, false}, {4, true, false}, {5, true, false},
		{6, false, true}, {7, true, true}, {8, true, true},
	} {
		t.Run(fmt.Sprint("stage", c.stage), func(t *testing.T) {
			s := openTemp(t)
			addHost(t, s, "a")
			dir := backupDir(t)
			if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o600); err != nil {
				t.Fatal(err)
			}
			s.backupHook = func(stage int) error {
				if stage == c.stage {
					return boom
				}
				return nil
			}
			o := bopts(dir)
			o.Keep = 1
			res, err := s.Backup(context.Background(), o)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v", err)
			}
			if (res.Path != "") != c.wantPublished {
				t.Fatalf("path %q, published want %v", res.Path, c.wantPublished)
			}
			var final, temps int
			for _, n := range names(t, dir) {
				switch {
				case strings.HasPrefix(n, "clamfleet-"):
					final++
				case strings.HasPrefix(n, ".tmp-"):
					temps++
				}
			}
			if (final == 1) != c.wantPublished {
				t.Fatalf("final files %d with published=%v: %v", final, c.wantPublished, names(t, dir))
			}
			if c.stage >= 2 && c.stage <= 5 && temps != 0 {
				t.Fatalf("a temporary file was left after stage %d", c.stage)
			}
			if c.stage == 6 && (temps != 1 || len(res.Warnings) != 1) {
				t.Fatalf("stage 6: %d temp files, warnings %v", temps, res.Warnings)
			}
			if b, err := os.ReadFile(filepath.Join(dir, "notes.txt")); err != nil || string(b) != "mine" {
				t.Fatal("a foreign file was touched")
			}
		})
	}
}

// Rule: the copy is never group- or world-readable, not even for a moment. SQLite
// creates its own VACUUM INTO target with the process umask; the store precreates
// the file 0600 instead of relying on it. The hook stats the temporary file right
// after VACUUM INTO returned, under a permissive umask.
func TestBackupTempFileIsPrivateFromTheFirstByte(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	s := openTemp(t)
	addHost(t, s, "a")
	dir := backupDir(t)
	var mode os.FileMode
	var size int64
	s.backupHook = func(stage int) error {
		if stage == 3 { // entry of stage 3: VACUUM INTO has returned
			ents, _ := os.ReadDir(dir)
			for _, e := range ents {
				if strings.HasPrefix(e.Name(), ".tmp-") {
					fi, err := os.Stat(filepath.Join(dir, e.Name()))
					if err != nil {
						return err
					}
					mode, size = fi.Mode().Perm(), fi.Size()
				}
			}
		}
		return nil
	}
	if _, err := s.Backup(context.Background(), bopts(dir)); err != nil {
		t.Fatal(err)
	}
	if size == 0 {
		t.Fatal("the hook did not see the filled temporary file")
	}
	if mode != 0o600 {
		t.Fatalf("temporary file mode %04o after VACUUM INTO", mode)
	}
}

// Rule: an existing backup is never replaced. Two backups in the same second get
// distinct names, and the first is untouched.
func TestBackupNeverReplacesAnExistingFile(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	dir := backupDir(t)
	first, err := s.Backup(ctx, bopts(dir))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(first.Path)
	seedReports(t, s, 5)
	second, err := s.Backup(ctx, bopts(dir))
	if err != nil {
		t.Fatal(err)
	}
	if second.Path == first.Path {
		t.Fatal("the second backup took the first one's name")
	}
	if !strings.Contains(second.Path, "20261112T100001Z") {
		t.Fatalf("second name %s: want the next second", second.Path)
	}
	after, _ := os.ReadFile(first.Path)
	if string(before) != string(after) {
		t.Fatal("the existing backup changed")
	}
}

// A backup while a goroutine writes 1000 reports through the writer: the copy is
// consistent, its report count is a prefix of the writes, and no write fails.
func TestBackupWhileIngesting(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	var wg sync.WaitGroup
	var werr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if _, err := s.RecordReport(ctx, recordOf(h.ID, i)); err != nil {
				werr = err
				return
			}
		}
	}()
	time.Sleep(20 * time.Millisecond)
	res, err := s.Backup(ctx, bopts(backupDir(t)))
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if werr != nil {
		t.Fatalf("a write failed during the backup: %v", werr)
	}
	db, err := sql.Open("sqlite", "file:"+res.Path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n, maxTS int
	if err := db.QueryRow(`SELECT count(*), coalesce(max(ts),-1) FROM reports`).Scan(&n, &maxTS); err != nil {
		t.Fatal(err)
	}
	if n > 1000 {
		t.Fatalf("%d reports in the copy", n)
	}
	// The writes are ts 0..999 in order: a consistent copy holds exactly 0..n-1.
	if n > 0 && maxTS != int(t0.Unix())+n-1 {
		t.Fatalf("copy holds %d reports with newest ts offset %d: not a prefix of the writes", n, maxTS-int(t0.Unix()))
	}
}

// --keep keeps the newest N backups and touches nothing else, including names
// that merely look similar.
func TestBackupKeepOnlyMatchesTheExactPattern(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	dir := backupDir(t)
	for _, n := range []string{"notes.txt", "clamfleet-x.db", "clamfleet-20200101T000000Z-v1.db.bak", "pre-migrate-v1-to-v2-20200101T000000Z.db"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		o := bopts(dir)
		o.Now = func() time.Time { return t0.Add(time.Duration(i) * time.Minute) }
		if _, err := s.Backup(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	o := bopts(dir)
	o.Now = func() time.Time { return t0.Add(10 * time.Minute) }
	o.Keep = 2
	if _, err := s.Backup(ctx, o); err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^clamfleet-\d{8}T\d{6}Z-v\d+\.db$`)
	var kept []string
	for _, n := range names(t, dir) {
		if re.MatchString(n) {
			kept = append(kept, n)
		}
	}
	if len(kept) != 2 || !strings.Contains(kept[1], "20261112T101000Z") || !strings.Contains(kept[0], "20261112T100300Z") {
		t.Fatalf("kept %v: want the two newest", kept)
	}
	for _, n := range []string{"notes.txt", "clamfleet-x.db", "clamfleet-20200101T000000Z-v1.db.bak", "pre-migrate-v1-to-v2-20200101T000000Z.db"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Fatalf("--keep deleted %s", n)
		}
	}
}

// The pre-migrate family keeps the newest 3 and never deletes regular backups.
func TestPreMigrateBackupsKeepThree(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	dir := backupDir(t)
	if _, err := s.Backup(ctx, bopts(dir)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		o := bopts(dir)
		o.Kind = BackupPreMigrate
		o.Now = func() time.Time { return t0.Add(time.Duration(i) * time.Minute) }
		if _, err := s.Backup(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	var pre, reg int
	for _, n := range names(t, dir) {
		switch {
		case strings.HasPrefix(n, "pre-migrate-"):
			pre++
		case strings.HasPrefix(n, "clamfleet-"):
			reg++
		}
	}
	if pre != 3 || reg != 1 {
		t.Fatalf("pre-migrate %d (want 3), regular %d (want 1): %v", pre, reg, names(t, dir))
	}
	v, _ := s.SchemaVersion(ctx)
	if !regexp.MustCompile(fmt.Sprintf(`pre-migrate-v%d-to-v%d-\d{8}T\d{6}Z\.db`, v, v)).MatchString(strings.Join(names(t, dir), " ")) {
		t.Fatalf("names %v", names(t, dir))
	}
}

// Rule: a backup directory holds personal data. A symlink, a directory open to
// group or others, and one owned by another user are each refused, and nothing is written.
func TestBackupRefusesUnsafeDirectories(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")

	real := backupDir(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	other := backupDir(t)

	for name, c := range map[string]struct {
		dir  string
		want string
		euid func() int
	}{
		"symlink":     {link, "not a real directory", nil},
		"mode 0755":   {open, "chmod 0700", nil},
		"other owner": {other, "owned by uid", func() int { return os.Geteuid() + 1 }},
	} {
		s.backupEUID = c.euid
		_, err := s.Backup(ctx, bopts(c.dir))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, c.want)
		}
		ents, _ := os.ReadDir(c.dir)
		for _, e := range ents {
			if e.Name() != ".lock" {
				t.Errorf("%s: wrote %s", name, e.Name())
			}
		}
	}
	// A missing directory is created 0700.
	s.backupEUID = nil
	d := filepath.Join(t.TempDir(), "new")
	if _, err := s.Backup(ctx, bopts(d)); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("created directory mode %v %v", fi.Mode(), err)
	}
}

// Two backups start together: one succeeds, the other fails at once with
// ErrBackupBusy. A --keep 1 run cannot delete the file of a backup that holds the
// lock (paused after it published).
func TestConcurrentBackupsAreSerialised(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	dir := backupDir(t)
	paused, release := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	s.backupHook = func(stage int) error {
		if stage == 6 && first.CompareAndSwap(false, true) { // published, still holding the lock
			close(paused)
			<-release
		}
		return nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.Backup(ctx, bopts(dir))
		done <- err
	}()
	<-paused
	o := bopts(dir)
	o.Keep = 1
	o.Now = func() time.Time { return t0.Add(time.Hour) }
	if _, err := s.Backup(ctx, o); !errors.Is(err, ErrBackupBusy) {
		t.Fatalf("second backup: %v, want ErrBackupBusy", err)
	}
	var published int
	for _, n := range names(t, dir) {
		if strings.HasPrefix(n, "clamfleet-") {
			published++
		}
	}
	if published != 1 {
		t.Fatalf("the running backup's file is gone or doubled: %v", names(t, dir))
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// With the lock free, a waiter gets it.
	o.LockWait = time.Second
	if _, err := s.Backup(ctx, o); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

func TestBackupFailsBeforeWritingWhenTheDiskIsTooFull(t *testing.T) {
	s := openTemp(t)
	addHost(t, s, "a")
	dir := backupDir(t)
	s.backupFree = func() uint64 { return 10 }
	_, err := s.Backup(context.Background(), bopts(dir))
	if err == nil || !strings.Contains(err.Error(), "free space") {
		t.Fatalf("err = %v", err)
	}
	if got := names(t, dir); len(got) != 0 {
		t.Fatalf("wrote %v", got)
	}
}

// Verification rejects a damaged copy and one at the wrong schema version.
func TestVerifyCopyRejectsDamageAndVersionMismatch(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	seedReports(t, s, 200)
	res, err := s.Backup(ctx, bopts(backupDir(t)))
	if err != nil {
		t.Fatal(err)
	}
	v, _ := s.SchemaVersion(ctx)
	if err := verifyCopy(ctx, res.Path, v); err != nil {
		t.Fatal(err)
	}
	if err := verifyCopy(ctx, res.Path, v+1); err == nil || !strings.Contains(err.Error(), "schema version") {
		t.Fatalf("version mismatch accepted: %v", err)
	}
	// Overwrite a data page in the middle of the file.
	b, _ := os.ReadFile(res.Path)
	bad := filepath.Join(t.TempDir(), "bad.db")
	for i := len(b) / 2; i < len(b)/2+4096 && i < len(b); i++ {
		b[i] = 0xAB
	}
	if err := os.WriteFile(bad, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyCopy(ctx, bad, v); err == nil {
		t.Fatal("a damaged copy passed verification")
	}
}

func recordOf(hostID int64, i int) store.ReportRecord {
	return store.ReportRecord{HostID: hostID, Report: rep("a", t0.Add(time.Duration(i)*time.Second), "1"), ReceivedAt: t0}
}

// Rule: a missing backup directory is created only by the user who owns its parent. A root-run
// backup (here: any other effective uid, through the seam) would create a directory the server user
// cannot use, so it is refused and nothing is created. Mutation: drop the parent-owner check.
func TestBackupDoesNotCreateADirectoryUnderAnotherUsersParent(t *testing.T) {
	s := openTemp(t)
	addHost(t, s, "a")
	parent := t.TempDir()
	dir := filepath.Join(parent, "backups")
	s.backupEUID = func() int { return os.Geteuid() + 1 }
	_, err := s.Backup(context.Background(), bopts(dir))
	if err == nil || !strings.Contains(err.Error(), "refusing to create the backup directory") {
		t.Fatalf("err = %v, want a refusal to create the directory", err)
	}
	if _, serr := os.Lstat(dir); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("the directory was created anyway (%v)", serr)
	}
}

// Rule: the verify connection's DSN is built with url.URL like dsn(), so a backup directory whose name
// holds ? # or % still verifies. With string concatenation the copy is looked up under a truncated name.
func TestBackupVerifyHandlesSpecialCharactersInTheDirectory(t *testing.T) {
	s := openTemp(t)
	addHost(t, s, "a")
	dir := filepath.Join(t.TempDir(), "bk?x#y%20z")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Backup(context.Background(), bopts(dir)); err != nil {
		t.Fatalf("backup --verify in a directory with special characters: %v", err)
	}
}
