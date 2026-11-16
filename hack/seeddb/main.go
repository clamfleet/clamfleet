// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Command seeddb writes a ClamFleet database whose rows have KNOWN AGES, so the
// retention acceptance ("old rows are removed per config") can be tested through the
// real server binary and, in the container, through the packaged one.
//
// TEST TOOL. It creates the database (refusing an existing one), migrates it with the
// real store, and seeds rows on both sides of every default retention cutoff. The
// clock is the --now flag: there is no wall-clock default, so a test is reproducible and
// a caller that wants "now" says so (`--now "$(date -u +%FT%TZ)"`).
//
//	seeddb --db /tmp/seed.db --now 2031-03-04T12:00:00Z
//
// It prints one JSON object on stdout: what each table must hold after a retention pass
// with the default keys, and after one with retention.reports_days: 14. The ages
// (days before --now) are in the table below; "kept" rows are those the plan's guards
// keep (an unfinished alert, an open detection window).
//
//	reports        45 d, 20 d, 5 d, and one that ARRIVED 2 d ago with an agent time 100 d old
//	events         400 d, 300 d, 450 d with a retrying delivery
//	state changes  400 d, 100 d, 400 d with a retrying delivery
//	audit          400 d, 100 d (and the host's creation row, now)
//	alert log      100 d, 30 d
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	_ "modernc.org/sqlite"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
)

// Expected is what a table holds after a retention pass.
type Expected struct {
	Reports      int `json:"reports"`
	Events       int `json:"events"`
	StateChanges int `json:"state_changes"`
	Audit        int `json:"audit"`
	AlertLog     int `json:"alert_log"`
}

// Manifest is the tool's output.
type Manifest struct {
	Seeded         Expected `json:"seeded"`
	AfterDefaults  Expected `json:"after_defaults"`
	AfterReports14 Expected `json:"after_reports_days_14"`
	Host           string   `json:"host"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "seeddb:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("seeddb", flag.ContinueOnError)
	dbPath := fs.String("db", "", "database file to create (must not exist)")
	nowFlag := fs.String("now", "", "the clock, RFC 3339 (required: there is no wall-clock default)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dbPath == "" || *nowFlag == "" {
		return fmt.Errorf("--db and --now are required")
	}
	now, err := time.Parse(time.RFC3339, *nowFlag)
	if err != nil {
		return fmt.Errorf("--now: %w", err)
	}
	if _, err := os.Stat(*dbPath); err == nil {
		return fmt.Errorf("%s exists: seeddb never overwrites a database", *dbPath)
	}
	m, err := seed(context.Background(), *dbPath, now.UTC())
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

func ago(now time.Time, days int) time.Time { return now.Add(-time.Duration(days) * 24 * time.Hour) }

func seed(ctx context.Context, path string, now time.Time) (Manifest, error) {
	st, err := sqlite.Open(ctx, path)
	if err != nil {
		return Manifest{}, err
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		return Manifest{}, err
	}
	const host = "seed01"
	h, err := st.CreateHost(ctx, host, []byte("seed-token-hash-0123456789abcdef"), now, store.Audit{Kind: store.ActorCLI, Actor: "seeddb"})
	if err != nil {
		st.Close()
		return Manifest{}, err
	}
	for i, c := range []struct{ ts, recv int }{{45, 45}, {20, 20}, {5, 5}, {100, 2}} {
		if _, err := st.RecordReport(ctx, store.ReportRecord{HostID: h.ID, ReceivedAt: ago(now, c.recv),
			Report: proto.Report{Schema: 1, Host: host, Tags: []string{}, TS: ago(now, c.ts).Add(time.Duration(i) * time.Second)}}); err != nil {
			st.Close()
			return Manifest{}, err
		}
	}
	for i, age := range []int{400, 300, 450} {
		if _, err := st.RecordEvent(ctx, store.EventRecord{HostID: h.ID, ReceivedAt: ago(now, age),
			Event: proto.Event{Schema: 1, Host: host, TS: ago(now, age), Path: fmt.Sprintf("/srv/seed/%d", i), Signature: "Seed-Signature", Source: "clamd"}}); err != nil {
			st.Close()
			return Manifest{}, err
		}
	}
	if err := st.Close(); err != nil {
		return Manifest{}, err
	}

	// The rest has no store API at the ages needed (state changes come from the evaluator, audit rows
	// from commands), so it is written with SQL after the store has created the schema.
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return Manifest{}, err
	}
	defer db.Close()
	u := func(t time.Time) int64 { return t.Unix() }
	stmts := []struct {
		q    string
		args []any
	}{
		// events: all arrived with alert_pending 1; all are marked planned, because a running server
		// would plan an unplanned row within milliseconds and the test could not know whether the
		// retention pass or the dispatcher got there first (an unplanned row is kept by the guard,
		// which the store tests cover). The 450 d one has a retrying delivery that is NOT due
		// (next attempt in 30 days), so the dispatcher leaves it alone and the guard keeps its event.
		{`UPDATE events SET alert_pending = 0`, nil},
		{`INSERT INTO alert_targets (id, name, type, config, created_at, updated_at) VALUES (1, 'seed-target', 'webhook', '{}', 1, 1)`, nil},
		{`INSERT INTO alert_deliveries (alert_id, target_id, host_id, event_id, kind, payload, status, attempts, created_at)
			VALUES ('seed-ev', 1, ?, (SELECT id FROM events WHERE path = '/srv/seed/2'), 'detection', '{}', 'pending', 2, ?)`, []any{h.ID, u(ago(now, 450))}},
		{`UPDATE alert_deliveries SET next_attempt_at = ? WHERE alert_id = 'seed-ev'`, []any{u(now.Add(30 * 24 * time.Hour))}},
		// state changes.
		{`INSERT INTO state_changes (id, host_id, ts, from_state, to_state, reason, alert_pending) VALUES (101, ?, ?, NULL, 'OK', '[]', 0)`, []any{h.ID, u(ago(now, 400))}},
		{`INSERT INTO state_changes (id, host_id, ts, from_state, to_state, reason, alert_pending) VALUES (102, ?, ?, 'OK', 'WARN', '[]', 0)`, []any{h.ID, u(ago(now, 100))}},
		{`INSERT INTO state_changes (id, host_id, ts, from_state, to_state, reason, alert_pending) VALUES (104, ?, ?, 'CRIT', 'OK', '[]', 0)`, []any{h.ID, u(ago(now, 400))}},
		{`INSERT INTO alert_deliveries (alert_id, target_id, host_id, state_change_id, kind, payload, status, attempts, created_at)
			VALUES ('seed-sc', 1, ?, 104, 'state_change', '{}', 'pending', 1, ?)`, []any{h.ID, u(ago(now, 400))}},
		{`UPDATE alert_deliveries SET next_attempt_at = ? WHERE alert_id = 'seed-sc'`, []any{u(now.Add(30 * 24 * time.Hour))}},
		// audit and alert log.
		{`INSERT INTO audit_log (ts, actor_kind, actor, action, target_kind, target) VALUES (?, 'cli', 'seeddb', 'seed.old', 'host', 'seed01')`, []any{u(ago(now, 400))}},
		{`INSERT INTO audit_log (ts, actor_kind, actor, action, target_kind, target) VALUES (?, 'cli', 'seeddb', 'seed.recent', 'host', 'seed01')`, []any{u(ago(now, 100))}},
		{`INSERT INTO alert_log (ts, target_id, target_name, host_name, status) VALUES (?, 1, 'seed-target', 'seed01', 'sent')`, []any{u(ago(now, 100))}},
		{`INSERT INTO alert_log (ts, target_id, target_name, host_name, status) VALUES (?, 1, 'seed-target', 'seed01', 'sent')`, []any{u(ago(now, 30))}},
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s.q, s.args...); err != nil {
			return Manifest{}, fmt.Errorf("%s: %w", s.q, err)
		}
	}
	// What stays. Reports: 5 d, the spooled one (arrived 2 d ago), and 20 d until reports_days drops to 14.
	// Events: 300 d and the 450 d one with the retrying delivery (the pruned one is 400 d).
	// State changes: 100 d and the 400 d one with the retrying delivery.
	// Audit: the 100 d row and the host's creation row (now). Alert log: 30 d.
	return Manifest{
		Host:           host,
		Seeded:         Expected{Reports: 4, Events: 3, StateChanges: 3, Audit: 3, AlertLog: 2},
		AfterDefaults:  Expected{Reports: 3, Events: 2, StateChanges: 2, Audit: 2, AlertLog: 1},
		AfterReports14: Expected{Reports: 2, Events: 2, StateChanges: 2, Audit: 2, AlertLog: 1},
	}, nil
}
