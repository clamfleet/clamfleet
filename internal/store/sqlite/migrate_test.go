// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/clamfleet/clamfleet/migrations"
	"github.com/pressly/goose/v3"
)

// columns lists the column names of a table.
func columns(t *testing.T, db *sql.DB, table string) map[string]bool {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM pragma_table_info('` + table + `')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[n] = true
	}
	return out
}

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// 00002 runs on a database that already holds Milestone 2 rows (the operator's
// real situation): the fleet columns are backfilled from last_report, the new
// state is NULL ("pending"), nothing existing is lost, and down/up round-trips.
func TestMigration00002OnExistingData(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.prov.UpTo(ctx, 1); err != nil {
		t.Fatal(err)
	}
	const withReport = `{"clamd":{"up":true,"version":"1.4.3"},"sigs":{"daily":{"version":28181,"built":"2026-11-12T06:27:14Z","sigs":1}}}`
	const noDaily = `{"clamd":{"up":false,"version":null},"sigs":{"daily":null}}`
	for _, q := range []string{
		`INSERT INTO hosts (name, token_hash, created_at, last_seen, last_report) VALUES ('a', x'01', 100, 200, '` + withReport + `')`,
		`INSERT INTO hosts (name, token_hash, created_at, last_report) VALUES ('b', x'02', 100, '` + noDaily + `')`,
		`INSERT INTO hosts (name, token_hash, created_at) VALUES ('c', x'03', 100)`,
	} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CheckMigrated(ctx); err == nil {
		t.Fatal("a database at version 1 must report pending migrations")
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	type row struct {
		ver, built sql.NullInt64
		clamd      sql.NullString
		state      sql.NullString
	}
	get := func(name string) row {
		var r row
		if err := s.r.QueryRow(`SELECT daily_version, daily_built, clamd_version, state FROM hosts WHERE name=?`, name).
			Scan(&r.ver, &r.built, &r.clamd, &r.state); err != nil {
			t.Fatal(err)
		}
		return r
	}
	a := get("a")
	// 2026-11-12T06:27:14Z in unix seconds.
	if a.ver.Int64 != 28181 || a.built.Int64 != 1794464834 || a.clamd.String != "1.4.3" || a.state.Valid {
		t.Fatalf("host a: %+v", a)
	}
	if b := get("b"); b.ver.Valid || b.built.Valid || b.clamd.Valid || b.state.Valid {
		t.Fatalf("host b (no daily, clamd version null) must stay NULL: %+v", b)
	}
	if c := get("c"); c.ver.Valid || c.state.Valid {
		t.Fatalf("host c (no report): %+v", c)
	}
	if n := count(t, s, `SELECT count(*) FROM hosts`); n != 3 {
		t.Fatalf("%d hosts after migration", n)
	}

	// Down removes exactly what 00002 added and keeps the hosts; up restores it.
	// 00003 sits on top of it now, so it is reverted first.
	for range 2 {
		if err := s.MigrateDown(ctx); err != nil {
			t.Fatal(err)
		}
	}
	cols := columns(t, s.w, "hosts")
	for _, c := range []string{"state", "state_reason", "state_since", "daily_version", "daily_built", "clamd_version"} {
		if cols[c] {
			t.Errorf("column hosts.%s survived the down migration", c)
		}
	}
	for _, tb := range []string{"state_changes", "users", "user_sessions"} {
		if tableExists(t, s.w, tb) {
			t.Errorf("table %s survived the down migration", tb)
		}
	}
	if n := count(t, s, `SELECT count(*) FROM hosts`); n != 3 {
		t.Fatalf("%d hosts after down", n)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if a := get("a"); a.ver.Int64 != 28181 {
		t.Fatalf("backfill after down/up: %+v", a)
	}
	for _, tb := range []string{"state_changes", "users", "user_sessions"} {
		if !tableExists(t, s.w, tb) {
			t.Errorf("table %s missing after up", tb)
		}
	}
}

// The state_changes cascade (M2 decision 2) and the users table shape that
// decision 11 fixes: email may be NULL for several rows, but not duplicated.
func TestMigration00002ConstraintsAndCascade(t *testing.T) {
	s := openTemp(t)
	h := addHost(t, s, "web01")
	if _, err := s.w.Exec(`INSERT INTO state_changes (host_id, ts, from_state, to_state, reason) VALUES (?, 1, NULL, 'OK', '[]')`, h.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.w.Exec(`DELETE FROM hosts WHERE id=?`, h.ID); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM state_changes`); n != 0 {
		t.Fatalf("state_changes did not cascade: %d rows", n)
	}
	ins := `INSERT INTO users (email, role, auth_source, external_id, created_at, updated_at) VALUES (?, 'viewer', ?, ?, 1, 1)`
	if _, err := s.w.Exec(ins, nil, "ldap", "dn1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.w.Exec(ins, nil, "ldap", "dn2"); err != nil {
		t.Fatalf("two users without an email must be allowed: %v", err)
	}
	if _, err := s.w.Exec(ins, "a@example.org", "local", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.w.Exec(ins, "a@example.org", "local", nil); err == nil {
		t.Fatal("a duplicate email must be refused")
	}
	if _, err := s.w.Exec(ins, nil, "ldap", "dn1"); err == nil {
		t.Fatal("a duplicate (auth_source, external_id) must be refused")
	}
}

// 00003 on a database that holds M3 users and sessions: nothing is lost, every
// existing user starts with auth_version 0 and no TOTP, and down/up round-trips.
func TestMigration00003OnExistingData(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.prov.UpTo(ctx, 2); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users (id, email, role, auth_source, password_hash, created_at, updated_at) VALUES (1, 'a@example.org', 'admin', 'local', 'phc', 1, 1)`,
		`INSERT INTO user_sessions (token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at) VALUES (x'01', 1, x'02', 1, 1, 9)`,
	} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var av, failures int
	var secret, enabled, last sql.NullString
	if err := s.r.QueryRow(`SELECT auth_version, totp_failures, totp_secret, totp_enabled_at, totp_last_step FROM users WHERE id=1`).
		Scan(&av, &failures, &secret, &enabled, &last); err != nil {
		t.Fatal(err)
	}
	if av != 0 || failures != 0 || secret.Valid || enabled.Valid || last.Valid {
		t.Fatalf("an existing user must start with auth_version 0 and no TOTP: %d %d %v %v %v", av, failures, secret, enabled, last)
	}
	if n := count(t, s, `SELECT count(*) FROM user_sessions WHERE totp_pending IS NULL AND totp_pending_at IS NULL`); n != 1 {
		t.Fatalf("the existing session was lost or got a pending secret: %d", n)
	}
	for _, tb := range []string{"user_recovery_codes", "user_login_challenges"} {
		if !tableExists(t, s.w, tb) {
			t.Errorf("table %s missing", tb)
		}
	}

	if err := s.MigrateDown(ctx); err != nil {
		t.Fatal(err)
	}
	for table, cols := range map[string][]string{
		"users":         {"auth_version", "totp_secret", "totp_enabled_at", "totp_last_step", "totp_failures"},
		"user_sessions": {"totp_pending", "totp_pending_at"},
	} {
		have := columns(t, s.w, table)
		for _, c := range cols {
			if have[c] {
				t.Errorf("column %s.%s survived the down migration", table, c)
			}
		}
	}
	for _, tb := range []string{"user_recovery_codes", "user_login_challenges"} {
		if tableExists(t, s.w, tb) {
			t.Errorf("table %s survived the down migration", tb)
		}
	}
	if n := count(t, s, `SELECT count(*) FROM users`); n != 1 {
		t.Fatalf("%d users after down", n)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM users WHERE auth_version = 0`); n != 1 {
		t.Fatalf("%d users after down/up", n)
	}
}

// Rule: an M3 binary must refuse a 00003 database, because it would ignore TOTP
// and let a password alone in. The M3 binary is simulated by a provider that
// knows only migrations 1 and 2, which is what its embedded set was.
func TestM3BinaryRefusesAMigration00003Database(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t) // migrated to the newest version
	if v, err := s.SchemaVersion(ctx); err != nil || v < 3 {
		t.Fatalf("schema version %d, %v: the test needs 00003 applied", v, err)
	}
	old := fstest.MapFS{}
	for _, n := range []string{"00001_init.sql", "00002_health_users.sql"} {
		b, err := migrations.SQLite.ReadFile("sqlite/" + n)
		if err != nil {
			t.Fatal(err)
		}
		old[n] = &fstest.MapFile{Data: b}
	}
	prov, err := goose.NewProvider(goose.DialectSQLite3, s.w, old, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	m3 := &Store{path: s.path, w: s.w, r: s.r, prov: prov}
	err = m3.checkNotNewer(ctx)
	if err == nil || !strings.Contains(err.Error(), "newer than this binary supports") {
		t.Fatalf("an M3 binary must refuse the database: %v", err)
	}
}
