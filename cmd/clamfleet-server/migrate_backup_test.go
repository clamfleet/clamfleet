// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/store/sqlite"
	"github.com/clamfleet/clamfleet/internal/testtls"
)

// m5Database builds a database as the M5 release left it (schema 00005) holding
// rows older than every retention cutoff, so a prune that ran would be visible.
func m5Database(t *testing.T) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), "cf.db")
	ctx := context.Background()
	st, err := sqlite.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MigrateUpTo(ctx, 5); err != nil {
		t.Fatal(err)
	}
	st.Close()
	raw, err := sql.Open("sqlite", "file:"+db)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, q := range []string{
		`INSERT INTO hosts (id, name, token_hash, created_at) VALUES (1, 'a', x'01', 1)`,
		`INSERT INTO reports (host_id, ts, received_at, payload) VALUES (1, 1, 1, '{}')`,
		`INSERT INTO state_changes (host_id, ts, from_state, to_state, reason) VALUES (1, 1, NULL, 'OK', '[]')`,
		`INSERT INTO audit_log (ts, actor_kind, actor, action, target_kind, target) VALUES (1, 'cli', 'x', 'a', 'host', 'a')`,
		`INSERT INTO events (host_id, ts, received_at, path, signature, source) VALUES (1, 1, 1, '/p', 'S', 'clamd')`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return db
}

// runServerWithin is runServer with a deadline: a serve that wrongly starts
// (instead of refusing) is killed and fails the test, never hangs it.
func runServerWithin(t *testing.T, d time.Duration, env []string, args ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	cmd := exec.CommandContext(ctx, serverBin, args...)
	cmd.Env = env
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("%v did not exit within %s (it started instead of refusing?):\n%s", args, d, se.String())
	}
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{so.String(), se.String(), code}
}

func schemaAndRows(t *testing.T, db string) (version int64, rows int) {
	t.Helper()
	raw, err := sql.Open("sqlite", "file:"+db+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.QueryRow(`SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := raw.QueryRow(`SELECT (SELECT count(*) FROM reports) + (SELECT count(*) FROM state_changes) + (SELECT count(*) FROM audit_log) + (SELECT count(*) FROM events)`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	return
}

func preMigrateFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "pre-migrate-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// Rule: a failed backup stops the migration. With an unwritable backup.dir, both
// serve and migrate exit 1, the schema is unchanged and every old row is still
// there (so no retention prune ran either); migrate --no-backup is the way past.
// Mutation: migrating after a failed backup.
func TestMigrationStopsWhenTheBackupFails(t *testing.T) {
	db := m5Database(t)
	dir := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { // owned and private, but not writable
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	env := cliEnv(db, "CLAMFLEET_SERVER_BACKUP_DIR="+dir)

	for _, args := range [][]string{{"serve"}, {"migrate"}} {
		r := runServerWithin(t, 20*time.Second, env, args...)
		if r.code != 1 || !strings.Contains(r.stderr, "migration was not run") {
			t.Fatalf("%v: %+v", args, r)
		}
		if v, rows := schemaAndRows(t, db); v != 5 || rows != 4 {
			t.Fatalf("%v: schema %d, %d old rows: the migration or a prune ran after a failed backup", args, v, rows)
		}
	}
	if r := runServer(t, env, "migrate", "--no-backup"); r.code != 0 || !strings.Contains(r.stderr, "without a backup") {
		t.Fatalf("--no-backup: %+v", r)
	}
	if v, _ := schemaAndRows(t, db); v < 6 {
		t.Fatalf("schema %d after --no-backup", v)
	}
}

// A pending migration on an existing database writes pre-migrate-v5-to-vN-*.db
// first, and the copy is at the OLD schema. A fresh database makes no backup.
func TestMigrateBacksUpBeforeChangingTheSchema(t *testing.T) {
	db := m5Database(t)
	dir := privateDir(t)
	env := cliEnv(db, "CLAMFLEET_SERVER_BACKUP_DIR="+dir)
	if r := runServer(t, env, "migrate"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	files := preMigrateFiles(t, dir)
	if len(files) != 1 || !strings.HasPrefix(files[0], "pre-migrate-v5-to-v") {
		t.Fatalf("backups %v", files)
	}
	if v, rows := schemaAndRows(t, filepath.Join(dir, files[0])); v != 5 || rows != 4 {
		t.Fatalf("the backup is at schema %d with %d rows, want the pre-migration state (5, 4)", v, rows)
	}
	// Up to date: nothing more to back up.
	if r := runServer(t, env, "migrate"); r.code != 0 || len(preMigrateFiles(t, dir)) != 1 {
		t.Fatalf("a no-op migrate wrote a backup: %+v", r)
	}

	fresh := filepath.Join(t.TempDir(), "fresh.db")
	dir2 := privateDir(t)
	if r := runServer(t, cliEnv(fresh, "CLAMFLEET_SERVER_BACKUP_DIR="+dir2), "migrate"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if f := preMigrateFiles(t, dir2); len(f) != 0 {
		t.Fatalf("a fresh database was backed up: %v", f)
	}
}

// serve does the same as migrate: the pre-migrate backup exists once it is listening.
func TestServeBacksUpBeforeMigrating(t *testing.T) {
	tlsb, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db := m5Database(t)
	dir := privateDir(t)
	startServe(t, tlsb, db, "CLAMFLEET_SERVER_BACKUP_DIR="+dir)
	if f := preMigrateFiles(t, dir); len(f) != 1 {
		t.Fatalf("serve did not back up before migrating: %v", f)
	}
}
