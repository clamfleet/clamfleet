// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
)

func privateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// Output contract: the path of the backup on stdout and nothing else. The file is
// 0600, opens, and is at the database's schema version.
func TestBackupCommand(t *testing.T) {
	db, env := newDB(t)
	dir := privateDir(t)
	if r := runServer(t, env, "host", "add", "web01"); r.code != 0 {
		t.Fatal(r)
	}
	r := runServer(t, env, "backup", "--dir", dir, "--verify")
	if r.code != 0 {
		t.Fatalf("%+v", r)
	}
	path := strings.TrimSuffix(r.stdout, "\n")
	if strings.Contains(path, "\n") || filepath.Dir(path) != dir || !strings.HasPrefix(filepath.Base(path), "clamfleet-") {
		t.Fatalf("stdout must be exactly one path inside the directory: %q", r.stdout)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi, err)
	}
	cp, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	var hosts int
	var ver int64
	if err := cp.QueryRow(`SELECT count(*) FROM hosts`).Scan(&hosts); err != nil || hosts != 1 {
		t.Fatalf("hosts in the copy: %d %v", hosts, err)
	}
	if err := cp.QueryRow(`SELECT max(version_id) FROM goose_db_version`).Scan(&ver); err != nil || ver < 6 {
		t.Fatalf("schema version %d %v", ver, err)
	}
	_ = db
}

// backup.dir from the config and --keep: after four backups, --keep 2 leaves two.
func TestBackupKeepFromTheCommandLine(t *testing.T) {
	_, env := newDB(t)
	dir := privateDir(t)
	env = append(env, "CLAMFLEET_SERVER_BACKUP_DIR="+dir)
	for i := 0; i < 4; i++ {
		if r := runServer(t, env, "backup", "--keep", "0"); r.code != 0 {
			t.Fatalf("%+v", r)
		}
	}
	if r := runServer(t, env, "backup", "--keep", "2"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	ents, _ := os.ReadDir(dir)
	var n int
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "clamfleet-") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d backups left, want 2", n)
	}
}

func TestBackupRefusesBadInput(t *testing.T) {
	_, env := newDB(t)
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if r := runServer(t, env, "backup", "--dir", open); r.code != 1 || !strings.Contains(r.stderr, "chmod 0700") || r.stdout != "" {
		t.Fatalf("a directory open to others: %+v", r)
	}
	if r := runServer(t, env, "backup", "--keep", "9999"); r.code != 2 {
		t.Fatalf("--keep out of range: %+v", r)
	}
	if r := runServer(t, env, "backup", "extra"); r.code != 2 {
		t.Fatalf("stray argument: %+v", r)
	}
	// A database that does not exist is not created by a backup.
	env2 := cliEnv(filepath.Join(t.TempDir(), "none.db"))
	if r := runServer(t, env2, "backup", "--dir", privateDir(t)); r.code != 1 || r.stdout != "" {
		t.Fatalf("missing database: %+v", r)
	}
}

// --verify on a damaged database exits 1 and publishes nothing: a backup that
// cannot be trusted must not look like one.
func TestBackupOfADamagedDatabaseFails(t *testing.T) {
	db, env := newDB(t)
	ctx := context.Background()
	st, err := sqlite.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	h, err := st.CreateHost(ctx, "a", []byte("0123456789abcdef0123456789abcdef"), time.Now(), testAudit)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 400; i++ {
		if _, err := st.RecordReport(ctx, store.ReportRecord{HostID: h.ID, ReceivedAt: time.Now(),
			Report: proto.Report{Schema: 1, Host: "a", Tags: []string{}, TS: time.Unix(int64(1000+i), 0)}}); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	b, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	// The middle half of the file, not one page range: how the pages are laid out depends on the schema
	// (migration 00007 shifted them, and 8 KiB in the middle then fell on pages integrity_check does not
	// read), while what this test needs is only that some page in use is damaged.
	for i := len(b) / 4; i < 3*len(b)/4; i++ {
		b[i] = 0xAB
	}
	if err := os.WriteFile(db, b, 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(db + "-wal")
	os.Remove(db + "-shm")
	dir := privateDir(t)
	r := runServer(t, env, "backup", "--dir", dir, "--verify")
	if r.code != 1 || r.stdout != "" {
		t.Fatalf("%+v", r)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.Name() != ".lock" {
			t.Fatalf("a file was left behind: %s", e.Name())
		}
	}
}

// The warning reaches the log of the real binary (stderr), and the command still works.
func TestBackupDirOutsideTheStateDirectoryIsLogged(t *testing.T) {
	_, env := newDB(t)
	dir := privateDir(t)
	r := runServer(t, append(env, "CLAMFLEET_SERVER_BACKUP_DIR="+dir), "backup")
	if r.code != 0 || !strings.Contains(r.stderr, "ReadWritePaths="+dir) {
		t.Fatalf("%+v", r)
	}
}
