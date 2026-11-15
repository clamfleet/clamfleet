// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// openTemp opens a real SQLite database in a temp dir and migrates it.
func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func tableCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN
		('hosts','host_tags','reports','events','audit_log')`).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMigrateEmptyThenNoop(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "t.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckMigrated(ctx); !errors.Is(err, ErrPendingMigrations) {
		t.Fatalf("fresh database: CheckMigrated = %v, want ErrPendingMigrations", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s.w) != 5 {
		t.Fatal("expected the five M2 tables")
	}
	s.Close()

	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate must be a no-op: %v", err)
	}
	if err := s.CheckMigrated(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateUpDownUp(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	// MigrateDown reverts one migration at a time: 00005, 00004 and 00003 first, then 00002, then 00001.
	for range 4 {
		if err := s.MigrateDown(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := tableCount(t, s.w); n != 5 {
		t.Fatalf("after reverting 00002 only, %d of the M2 tables remain, want all 5", n)
	}
	if err := s.MigrateDown(ctx); err != nil {
		t.Fatal(err)
	}
	if n := tableCount(t, s.w); n != 0 {
		t.Fatalf("after down %d tables remain", n)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if n := tableCount(t, s.w); n != 5 {
		t.Fatalf("after up again %d tables", n)
	}
}

func TestOpenRefusesNewerSchema(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	path := s.path
	if _, err := s.w.Exec(`INSERT INTO goose_db_version (version_id, is_applied) VALUES (99, 1)`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, err := Open(ctx, path)
	if err == nil || !strings.Contains(err.Error(), "99") {
		t.Fatalf("want an error naming version 99, got %v", err)
	}
}

// Pragmas live in the DSN so every pooled connection has them. Checking both
// pools catches a pragma dropped from either DSN.
func TestPragmasOnBothPools(t *testing.T) {
	s := openTemp(t)
	for name, db := range map[string]*sql.DB{"writer": s.w, "reader": s.r} {
		want := map[string]string{
			"journal_mode": "wal", "foreign_keys": "1", "busy_timeout": "5000", "synchronous": "1",
		}
		if name == "reader" {
			want["query_only"] = "1"
		} else {
			want["query_only"] = "0"
		}
		for pragma, w := range want {
			var got string
			if err := db.QueryRow("PRAGMA " + pragma).Scan(&got); err != nil {
				t.Fatalf("%s %s: %v", name, pragma, err)
			}
			if got != w {
				t.Errorf("%s: PRAGMA %s = %q, want %q", name, pragma, got, w)
			}
		}
	}
}

func TestWriteThroughReadPoolFails(t *testing.T) {
	s := openTemp(t)
	_, err := s.r.Exec(`INSERT INTO audit_log (ts, actor_kind, actor, action, target_kind, target) VALUES (1,'cli','x','a','host','h')`)
	if err == nil {
		t.Fatal("a write through the read pool must fail (query_only)")
	}
}

// BEGIN IMMEDIATE is what makes concurrent writers wait instead of failing on
// a lock upgrade.
func TestWriterTransactionsAreImmediate(t *testing.T) {
	s := openTemp(t)
	other, err := Open(context.Background(), s.path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	tx, err := s.w.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// With a deferred BEGIN the lock would not be held yet and a second
	// writer's immediate transaction would succeed at once; with IMMEDIATE it
	// waits for busy_timeout, so shorten it for the probe.
	if _, err := other.w.Exec(`PRAGMA busy_timeout=50`); err != nil {
		t.Fatal(err)
	}
	if tx2, err := other.w.Begin(); err == nil {
		tx2.Rollback()
		t.Fatal("second immediate transaction succeeded while the first holds the write lock")
	}
}

func TestFilesAre0600(t *testing.T) {
	s := openTemp(t)
	// Make sure the -wal and -shm files exist.
	if _, err := s.w.Exec(`INSERT INTO audit_log (ts, actor_kind, actor, action, target_kind, target) VALUES (1,'cli','x','a','host','h')`); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := s.r.QueryRow(`SELECT count(*) FROM audit_log`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		fi, err := os.Stat(s.path + suffix)
		if err != nil {
			t.Fatalf("%s%s: %v", filepath.Base(s.path), suffix, err)
		}
		if m := fi.Mode().Perm(); m != 0o600 {
			t.Errorf("%s%s mode %o, want 600", filepath.Base(s.path), suffix, m)
		}
	}
}

// An existing file keeps its mode: the operator may have a reason.
func TestOpenKeepsExistingFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode changed to %o", fi.Mode().Perm())
	}
}
