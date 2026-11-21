// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// backup.go: the `backup` command. The protocol (temp
// file, fsync, no-replace link, lock, --keep) lives in the sqlite store; this file
// is flags, the umask and the output contract: the path of the new backup on
// stdout and nothing else, so BACKUP=$(clamfleet-server backup) works.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"syscall"
	"time"

	"github.com/clamfleet/clamfleet/internal/server"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
)

// restrictiveUmask makes every file this process creates private (0600/0700 at
// most) from its first byte. The database holds password hashes, sealed secrets
// and detection paths; SQLite creates -wal, -shm and journal files itself, and a
// `sudo -u clamfleet-server` run does not pass through the unit's UMask=.
func restrictiveUmask() { syscall.Umask(0o077) }

func (a *app) backup(ctx context.Context, args []string) int {
	restrictiveUmask()
	fs, cfgFlag := newFlags("backup", a.stderr)
	dir := fs.String("dir", "", "backup directory (default: backup.dir)")
	keep := fs.Int("keep", -1, "keep this many newest backups, 0 = all (default: backup.keep)")
	verify := fs.Bool("verify", false, "open the copy afterwards: integrity_check and schema version")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(a.stderr, "backup: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	log := a.logger(slog.LevelInfo)
	cfg, err := a.loadConfig(log, *cfgFlag)
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return exitError
	}
	o := sqlite.BackupOptions{Dir: cfg.Backup.Dir, Keep: cfg.Backup.Keep, Verify: *verify, Now: a.now}
	if *dir != "" {
		o.Dir = *dir
	}
	if *keep >= 0 {
		o.Keep = *keep
	}
	if *keep < -1 || o.Keep > 365 {
		fmt.Fprintln(a.stderr, "backup: --keep must be between 0 and 365")
		return exitUsage
	}
	st, err := a.openExisting(ctx, log, cfg)
	if err != nil {
		log.Error("database", "error", err.Error())
		return exitError
	}
	defer st.Close()

	start := time.Now() // a duration for the log, never stored
	res, err := st.Backup(ctx, o)
	for _, w := range res.Warnings {
		log.Warn(w)
	}
	switch {
	case errors.Is(err, sqlite.ErrBackupBusy):
		log.Error("backup", "error", err.Error())
		return exitError
	case err != nil:
		// A backup can be published and still report a later failure (directory
		// sync, --keep): the error text names the file, and the exit status is 1.
		log.Error("backup", "error", err.Error())
		return exitError
	}
	log.Info("backup written", "size_bytes", res.Size, "duration_ms", time.Since(start).Milliseconds(), "verified", *verify)
	fmt.Fprintln(a.stdout, res.Path)
	return exitOK
}

// migrateBackupWait is how long the backup before a migration waits for another
// backup that holds the lock: the migration must not run without one.
const migrateBackupWait = 5 * time.Minute

// migrateWithBackup applies pending migrations. Rule: on a database that already
// has a schema, it first writes a verified pre-migrate backup, and when that
// fails the migration does not run (a failed migration on the only copy of the
// data is the worst outcome this project can have). A fresh database has nothing
// to lose and needs no backup. noBackup is migrate's explicit way past a backup
// that cannot be made.
func (a *app) migrateWithBackup(ctx context.Context, log *slog.Logger, cfg server.Config, st *sqlite.Store, noBackup bool) error {
	from, to, err := st.PendingMigrations(ctx)
	if err != nil {
		return err
	}
	if from >= 1 && from < to {
		if noBackup {
			log.Warn("migrating without a backup (--no-backup)", "from", from, "to", to)
		} else {
			res, err := st.Backup(ctx, sqlite.BackupOptions{
				Dir: cfg.Backup.Dir, Kind: sqlite.BackupPreMigrate, Verify: true, LockWait: migrateBackupWait, Now: a.now,
			})
			for _, w := range res.Warnings {
				log.Warn(w)
			}
			if err != nil {
				return fmt.Errorf("the backup before migrating from schema %d to %d failed, so the migration was not run: %w (fix the cause, or run `clamfleet-server migrate --no-backup` once)", from, to, err)
			}
			log.Info("backup before migrating written", "size_bytes", res.Size, "from", from, "to", to)
		}
	}
	return st.Migrate(ctx)
}
