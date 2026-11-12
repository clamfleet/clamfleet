// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
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
	if err := s.MigrateDown(ctx); err != nil {
		t.Fatal(err)
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
