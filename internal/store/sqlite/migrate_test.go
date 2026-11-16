// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"strconv"
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
	// 00003 and 00004 sit on top of it, so they are reverted first.
	if _, err := s.prov.DownTo(ctx, 1); err != nil {
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
// M3 decision 11 fixes: email may be NULL for several rows, but not duplicated.
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

	if _, err := s.prov.DownTo(ctx, 2); err != nil { // 00004 sits on top of 00003
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

// 00004 on a database that holds M3b state changes and events: the old rows
// get alert_pending 0 (upgrading must not alert on history), a planning pass
// right after the upgrade has nothing to do, and down/up round-trips.
func TestMigration00004OnExistingData(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.prov.UpTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO hosts (id, name, token_hash, created_at) VALUES (1, 'a', x'01', 100)`,
		`INSERT INTO state_changes (host_id, ts, from_state, to_state, reason) VALUES (1, 5, NULL, 'CRIT', '[]')`,
		`INSERT INTO events (host_id, ts, received_at, path, signature, source) VALUES (1, 5, 6, '/x', 'Eicar', 'clamonacc')`,
	} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tb := range []string{"state_changes", "events"} {
		if n := count(t, s, `SELECT count(*) FROM `+tb+` WHERE alert_pending = 0`); n != 1 {
			t.Fatalf("%s: the old row must have alert_pending 0 (no alert for history), got %d such rows", tb, n)
		}
		if n := count(t, s, `SELECT count(*) FROM `+tb+` WHERE alert_pending = 1`); n != 0 {
			t.Fatalf("%s: %d old rows flagged for alerting", tb, n)
		}
	}
	for _, tb := range []string{"alert_targets", "alert_notify_state", "alert_deliveries", "alert_log"} {
		if !tableExists(t, s.w, tb) {
			t.Errorf("table %s missing", tb)
		}
	}

	if _, err := s.prov.DownTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
	for _, tb := range []string{"alert_targets", "alert_notify_state", "alert_deliveries", "alert_log"} {
		if tableExists(t, s.w, tb) {
			t.Errorf("table %s survived the down migration", tb)
		}
	}
	for _, tb := range []string{"state_changes", "events"} {
		if columns(t, s.w, tb)["alert_pending"] {
			t.Errorf("%s.alert_pending survived the down migration", tb)
		}
	}
	if n := count(t, s, `SELECT count(*) FROM state_changes`) + count(t, s, `SELECT count(*) FROM events`); n != 2 {
		t.Fatalf("history lost by down: %d rows", n)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM state_changes WHERE alert_pending = 0`); n != 1 {
		t.Fatalf("state change after down/up: %d", n)
	}
}

// The cascades of 4.1: a host delete removes its deliveries, notify state and
// the log rows tied to its history; a target delete keeps its log rows with a
// NULL target id and the name snapshot.
func TestMigration00004Cascades(t *testing.T) {
	s := openTemp(t)
	h := addHost(t, s, "web01")
	for _, q := range []string{
		`INSERT INTO state_changes (id, host_id, ts, from_state, to_state, reason, alert_pending) VALUES (1, ` + itoa(h.ID) + `, 1, NULL, 'CRIT', '[]', 1)`,
		`INSERT INTO alert_targets (id, name, type, config, created_at, updated_at) VALUES (1, 't', 'webhook', '{}', 1, 1)`,
		`INSERT INTO alert_notify_state (target_id, host_id, last_state, last_at) VALUES (1, ` + itoa(h.ID) + `, 'CRIT', 1)`,
		`INSERT INTO alert_deliveries (id, alert_id, target_id, host_id, state_change_id, kind, payload, status, created_at) VALUES (1, 'a', 1, ` + itoa(h.ID) + `, 1, 'state_change', '{}', 'pending', 1)`,
		`INSERT INTO alert_log (ts, target_id, target_name, delivery_id, host_name, state_change_id, status) VALUES (1, 1, 't', 1, 'web01', 1, 'attempting')`,
		`INSERT INTO alert_log (ts, target_id, target_name, host_name, status) VALUES (1, 1, 't', NULL, 'test_sent')`,
	} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.w.Exec(`DELETE FROM alert_targets WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM alert_deliveries`) + count(t, s, `SELECT count(*) FROM alert_notify_state`); n != 0 {
		t.Fatalf("target delete left %d deliveries/notify rows", n)
	}
	if n := count(t, s, `SELECT count(*) FROM alert_log WHERE target_id IS NULL AND target_name = 't' AND delivery_id IS NULL`); n != 2 {
		t.Fatalf("target delete must keep log rows with the name snapshot: %d", n)
	}
	if _, err := s.w.Exec(`DELETE FROM hosts WHERE id = ?`, h.ID); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM alert_log`); n != 1 { // the test-send row has no host
		t.Fatalf("host delete must remove the log rows of its history: %d left", n)
	}
}

// Rule: an M3b binary must refuse a 00004 database, because it would never
// plan or send the queued alerts. The M3b binary is simulated by a provider
// that knows migrations 1 to 3 only.
func TestM3bBinaryRefusesAMigration00004Database(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	if v, err := s.SchemaVersion(ctx); err != nil || v < 4 {
		t.Fatalf("schema version %d, %v: the test needs 00004 applied", v, err)
	}
	old := fstest.MapFS{}
	for _, n := range []string{"00001_init.sql", "00002_health_users.sql", "00003_totp.sql"} {
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
	m3b := &Store{path: s.path, w: s.w, r: s.r, prov: prov}
	err = m3b.checkNotNewer(ctx)
	if err == nil || !strings.Contains(err.Error(), "newer than this binary supports") {
		t.Fatalf("an M3b binary must refuse the database: %v", err)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// 00005 on a database that holds M4 data: existing targets get burst 10,
// existing events occurrences 1, nothing is lost, and down/up round-trips.
func TestMigration00005OnExistingData(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.prov.UpTo(ctx, 4); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO hosts (id, name, token_hash, created_at) VALUES (1, 'a', x'01', 100)`,
		`INSERT INTO events (id, host_id, ts, received_at, path, signature, source, alert_pending) VALUES (1, 1, 10, 11, '/p', 'S', 'clamd', 0)`,
		`INSERT INTO alert_targets (id, name, type, config, created_at, updated_at) VALUES (1, 't', 'webhook', '{}', 1, 1)`,
		`INSERT INTO alert_deliveries (id, alert_id, target_id, host_id, event_id, kind, payload, status, created_at) VALUES (1, 'a', 1, 1, 1, 'detection', '{}', 'sent', 1)`,
	} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT detection_burst FROM alert_targets WHERE id = 1`); n != 10 {
		t.Fatalf("an existing target must get burst 10, got %d", n)
	}
	if n := count(t, s, `SELECT occurrences FROM events WHERE id = 1`); n != 1 {
		t.Fatalf("an existing event must have occurrences 1, got %d", n)
	}
	if n := count(t, s, `SELECT count(*) FROM alert_deliveries WHERE id = 1 AND window_id IS NULL`); n != 1 {
		t.Fatal("an existing delivery lost or got a window")
	}
	for _, tb := range []string{"event_receipts", "alert_detection_windows", "alert_window_events"} {
		if !tableExists(t, s.w, tb) {
			t.Errorf("table %s missing", tb)
		}
	}
	// Down removes everything it added, and up again works on the same data.
	if _, err := s.prov.DownTo(ctx, 4); err != nil {
		t.Fatal(err)
	}
	for _, tb := range []string{"event_receipts", "alert_detection_windows", "alert_window_events"} {
		if tableExists(t, s.w, tb) {
			t.Errorf("table %s survived the down migration", tb)
		}
	}
	if columns(t, s.w, "events")["occurrences"] || columns(t, s.w, "alert_targets")["detection_burst"] || columns(t, s.w, "alert_deliveries")["window_id"] {
		t.Fatal("a column survived the down migration")
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if n := count(t, s, `SELECT count(*) FROM events`); n != 1 {
		t.Fatalf("the event was lost: %d", n)
	}
}

// The constraints the planner relies on: one open window per (target, host),
// and one receipt per (host, agent id). Cascades follow the event and the target.
func TestMigration00005ConstraintsAndCascades(t *testing.T) {
	s := openTemp(t)
	h := addHost(t, s, "web01")
	hid := itoa(h.ID)
	for _, q := range []string{
		`INSERT INTO events (id, host_id, ts, received_at, path, signature, source) VALUES (1, ` + hid + `, 1, 1, '/p', 'S', 'clamd')`,
		`INSERT INTO alert_targets (id, name, type, config, created_at, updated_at) VALUES (1, 't', 'webhook', '{}', 1, 1)`,
		`INSERT INTO event_receipts (host_id, agent_event_id, event_id, received_at) VALUES (` + hid + `, 'a', 1, 1)`,
		`INSERT INTO alert_detection_windows (id, target_id, host_id, window_start) VALUES (1, 1, ` + hid + `, 1)`,
		`INSERT INTO alert_window_events (window_id, event_id) VALUES (1, 1)`,
	} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.w.Exec(`INSERT INTO event_receipts (host_id, agent_event_id, event_id, received_at) VALUES (` + hid + `, 'a', 1, 2)`); err == nil {
		t.Fatal("a second receipt for the same host and agent id was accepted")
	}
	if _, err := s.w.Exec(`INSERT INTO alert_detection_windows (target_id, host_id, window_start) VALUES (1, ` + hid + `, 5)`); err == nil {
		t.Fatal("a second open window for the same target and host was accepted")
	}
	if _, err := s.w.Exec(`UPDATE alert_detection_windows SET closed_at = 9, outcome = 'summarised' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.w.Exec(`INSERT INTO alert_detection_windows (target_id, host_id, window_start) VALUES (1, ` + hid + `, 5)`); err != nil {
		t.Fatalf("a new window after the old one closed: %v", err)
	}
	if _, err := s.w.Exec(`DELETE FROM events WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM event_receipts`) + count(t, s, `SELECT count(*) FROM alert_window_events`); n != 0 {
		t.Fatalf("an event delete left %d receipts/memberships", n)
	}
	if _, err := s.w.Exec(`DELETE FROM alert_targets WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM alert_detection_windows`); n != 0 {
		t.Fatalf("a target delete left %d windows", n)
	}
}

// Rule: an M4 binary must refuse a 00005 database: it would treat replayed
// reports as live and never summarise held detections.
func TestM4BinaryRefusesAMigration00005Database(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	if v, err := s.SchemaVersion(ctx); err != nil || v < 5 {
		t.Fatalf("schema version %d, %v: the test needs 00005 applied", v, err)
	}
	old := fstest.MapFS{}
	for _, n := range []string{"00001_init.sql", "00002_health_users.sql", "00003_totp.sql", "00004_alerting.sql"} {
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
	m4 := &Store{path: s.path, w: s.w, r: s.r, prov: prov}
	err = m4.checkNotNewer(ctx)
	if err == nil || !strings.Contains(err.Error(), "newer than this binary supports") {
		t.Fatalf("an M4 binary must refuse the database: %v", err)
	}
}

// 00006 only adds indexes: it must keep every existing row, round-trip down and up,
// and SQLite must actually use the new indexes for the cascade lookups (plan 4.1, [A19]).
// Without them a pruned event or state change scans the alert tables in full.
func TestMigration00006IndexesServeTheCascades(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.prov.UpTo(ctx, 5); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO hosts (id, name, token_hash, created_at) VALUES (1, 'a', x'01', 100)`,
		`INSERT INTO events (id, host_id, ts, received_at, path, signature, source) VALUES (1, 1, 10, 11, '/p', 'S', 'clamd')`,
		`INSERT INTO alert_targets (id, name, type, config, created_at, updated_at) VALUES (1, 't', 'webhook', '{}', 1, 1)`,
		`INSERT INTO alert_log (ts, target_id, target_name, event_id, status) VALUES (1, 1, 't', 1, 'sent')`,
	} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM alert_log`); n != 1 {
		t.Fatalf("a row was lost by 00006: %d", n)
	}
	// The lookups a cascaded delete performs, one per child column.
	for _, c := range []struct{ query, index string }{
		{`SELECT 1 FROM alert_deliveries WHERE state_change_id = 1`, "alert_deliveries_state_change"},
		{`SELECT 1 FROM alert_log WHERE state_change_id = 1`, "alert_log_state_change"},
		{`SELECT 1 FROM alert_log WHERE event_id = 1`, "alert_log_event"},
	} {
		rows, err := s.w.Query(`EXPLAIN QUERY PLAN ` + c.query)
		if err != nil {
			t.Fatal(err)
		}
		var plan strings.Builder
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan.WriteString(detail + "\n")
		}
		rows.Close()
		if !strings.Contains(plan.String(), c.index) {
			t.Errorf("%s does not use %s:\n%s", c.query, c.index, plan.String())
		}
	}
	if _, err := s.prov.DownTo(ctx, 5); err != nil {
		t.Fatal(err)
	}
	for _, ix := range []string{"alert_deliveries_state_change", "alert_log_state_change", "alert_log_event"} {
		var n int
		if err := s.w.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name=?`, ix).Scan(&n); err != nil || n != 0 {
			t.Errorf("index %s survived the down migration (%d, %v)", ix, n, err)
		}
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
}

// Rule: an M5 binary must refuse a 00006 database, like every earlier migration.
func TestM5BinaryRefusesAMigration00006Database(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	if v, err := s.SchemaVersion(ctx); err != nil || v < 6 {
		t.Fatalf("schema version %d, %v: the test needs 00006 applied", v, err)
	}
	old := fstest.MapFS{}
	for _, n := range []string{"00001_init.sql", "00002_health_users.sql", "00003_totp.sql", "00004_alerting.sql", "00005_events.sql"} {
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
	m5 := &Store{path: s.path, w: s.w, r: s.r, prov: prov}
	err = m5.checkNotNewer(ctx)
	if err == nil || !strings.Contains(err.Error(), "newer than this binary supports") {
		t.Fatalf("an M5 binary must refuse the database: %v", err)
	}
}

// Plan 4.14: 00007 adds users.external_name and the one-time OIDC state table, goes down and up
// again, and keeps the rows of existing users.
func TestMigration00007ExternalAuth(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	if v, err := s.SchemaVersion(ctx); err != nil || v < 7 {
		t.Fatalf("schema version %d, %v: the test needs 00007 applied", v, err)
	}
	for _, c := range []string{`SELECT external_name FROM users LIMIT 1`, `SELECT token_hash, state, nonce, code_verifier, next_path, created_at, expires_at FROM oidc_login_states LIMIT 1`} {
		rows, err := s.w.Query(c)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		rows.Close()
	}
	if _, err := s.prov.DownTo(ctx, 6); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.w.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='oidc_login_states'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("oidc_login_states survived the down migration (%d, %v)", n, err)
	}
	if _, err := s.w.Exec(`SELECT external_name FROM users`); err == nil {
		t.Fatal("users.external_name survived the down migration")
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
}

// Rule: an M6a binary (migrations up to 00006) must refuse a 00007 database, like every earlier migration.
func TestM6aBinaryRefusesAMigration00007Database(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	old := fstest.MapFS{}
	for _, n := range []string{"00001_init.sql", "00002_health_users.sql", "00003_totp.sql", "00004_alerting.sql", "00005_events.sql", "00006_retention.sql"} {
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
	m6a := &Store{path: s.path, w: s.w, r: s.r, prov: prov}
	if err := m6a.checkNotNewer(ctx); err == nil || !strings.Contains(err.Error(), "newer than this binary supports") {
		t.Fatalf("an M6a binary must refuse the database: %v", err)
	}
}
