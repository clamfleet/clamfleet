// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func exec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if _, err := s.w.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// Rule: reports are pruned by received_at (server clock), strictly before the
// cutoff. A report with an old agent ts that ARRIVED after the cutoff stays: a
// spooled report must not be pruned the moment it lands.
func TestPruneReportsByArrivalAndBoundary(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	cut := t0.Add(24 * time.Hour)
	record(t, s, h.ID, rep("a", t0.Add(1*time.Second), "1"), cut.Add(-time.Second))    // pruned
	record(t, s, h.ID, rep("a", t0.Add(2*time.Second), "1"), cut)                      // boundary: stays
	record(t, s, h.ID, rep("a", t0.Add(-400*24*time.Hour), "1"), cut.Add(time.Second)) // old ts, fresh arrival: stays
	n, err := s.PruneReports(ctx, cut, 10)
	if err != nil || n != 1 {
		t.Fatalf("pruned %d err %v, want 1", n, err)
	}
	if left := count(t, s, `SELECT count(*) FROM reports`); left != 2 {
		t.Fatalf("%d reports left, want 2", left)
	}
	// The host row is untouched: the fleet page does not depend on history.
	if c := count(t, s, `SELECT count(*) FROM hosts WHERE last_report IS NOT NULL`); c != 1 {
		t.Fatalf("hosts.last_report was lost: %d", c)
	}
}

// Rule: one batch is one transaction, so ingest interleaves with a large prune.
func TestPruneBatchesAreSeparateTransactions(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	tx, err := s.w.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12001; i++ {
		if _, err := tx.Exec(`INSERT INTO reports (host_id, ts, received_at, payload) VALUES (?, ?, 1, '{}')`, h.ID, i); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	txs := 0
	s.onPruneTx = func() { txs++ }
	n, err := s.PruneReports(ctx, time.Unix(1000, 0), 5000)
	if err != nil || n != 12001 {
		t.Fatalf("pruned %d err %v", n, err)
	}
	if txs != 3 {
		t.Fatalf("%d transactions, want 3 (5000, 5000, 2001)", txs)
	}
}

func TestPruneAuditBoundary(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	for _, ts := range []int64{199, 200, 201} {
		exec(t, s, `INSERT INTO audit_log (ts, actor_kind, actor, action, target_kind, target) VALUES (?, 'cli', 'x', 'a', 'host', 'h')`, ts)
	}
	n, err := s.PruneAudit(ctx, time.Unix(200, 0), 10)
	if err != nil || n != 1 {
		t.Fatalf("pruned %d err %v, want 1 (ts < before)", n, err)
	}
	if left := count(t, s, `SELECT count(*) FROM audit_log WHERE ts = 200`); left != 1 {
		t.Fatal("the row at the cutoff was pruned")
	}
}

// seedStateChange adds an old state change with its target and, optionally, a delivery.
func seedStateChange(t *testing.T, s *Store, hostID int64, id int64, pending int, deliveryStatus string, finished *int64) {
	t.Helper()
	exec(t, s, `INSERT OR IGNORE INTO alert_targets (id, name, type, config, created_at, updated_at) VALUES (1, 't', 'webhook', '{}', 1, 1)`)
	exec(t, s, `INSERT INTO state_changes (id, host_id, ts, from_state, to_state, reason, alert_pending) VALUES (?, ?, 5, NULL, 'CRIT', '[]', ?)`, id, hostID, pending)
	if deliveryStatus != "" {
		exec(t, s, `INSERT INTO alert_deliveries (id, alert_id, target_id, host_id, state_change_id, kind, payload, status, created_at, finished_at)
			VALUES (?, ?, 1, ?, ?, 'state_change', '{}', ?, 1, ?)`, id, fmt.Sprintf("a%d", id), hostID, id, deliveryStatus, finished)
		exec(t, s, `INSERT INTO alert_log (ts, target_id, target_name, delivery_id, state_change_id, status) VALUES (5, 1, 't', ?, ?, 'retrying')`, id, id)
	}
}

// Rule: a state change whose alert is not finished is never pruned, or the
// cascade would delete the pending delivery and the alert would be lost. Once the
// delivery finishes, the next prune removes the state change and its alert rows.
func TestPruneStateChangesKeepsUnfinishedAlerts(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	done := int64(9)
	seedStateChange(t, s, h.ID, 1, 1, "", nil)        // not yet planned
	seedStateChange(t, s, h.ID, 2, 0, "pending", nil) // a retrying delivery
	seedStateChange(t, s, h.ID, 3, 0, "sent", &done)  // finished: goes
	seedStateChange(t, s, h.ID, 4, 0, "", nil)        // no alert at all: goes
	n, err := s.PruneStateChanges(ctx, time.Unix(100, 0), 10)
	if err != nil || n != 2 {
		t.Fatalf("pruned %d err %v, want 2", n, err)
	}
	if left := count(t, s, `SELECT count(*) FROM state_changes WHERE id IN (1,2)`); left != 2 {
		t.Fatal("a state change with an unfinished alert was pruned")
	}
	if c := count(t, s, `SELECT count(*) FROM alert_deliveries WHERE id = 2 AND status = 'pending'`); c != 1 {
		t.Fatal("the pending delivery was deleted")
	}
	if c := count(t, s, `SELECT count(*) FROM alert_deliveries WHERE id = 3`); c != 0 {
		t.Fatal("the finished delivery did not cascade")
	}
	// The delivery is sent, the alert planned: the next prune takes both.
	exec(t, s, `UPDATE alert_deliveries SET status = 'sent', finished_at = 10 WHERE id = 2`)
	exec(t, s, `UPDATE state_changes SET alert_pending = 0 WHERE id = 1`)
	n, err = s.PruneStateChanges(ctx, time.Unix(100, 0), 10)
	if err != nil || n != 2 {
		t.Fatalf("second prune: %d err %v, want 2", n, err)
	}
	if c := count(t, s, `SELECT count(*) FROM alert_log`); c != 0 {
		t.Fatalf("%d alert_log rows left after the cascade", c)
	}
	if c := count(t, s, `SELECT count(*) FROM hosts`); c != 1 {
		t.Fatal("the host went with its state change")
	}
}

func TestPruneStateChangesBoundary(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	for i, ts := range []int64{99, 100, 101} {
		exec(t, s, `INSERT INTO state_changes (id, host_id, ts, from_state, to_state, reason) VALUES (?, ?, ?, NULL, 'OK', '[]')`, i+1, h.ID, ts)
	}
	n, err := s.PruneStateChanges(ctx, time.Unix(100, 0), 10)
	if err != nil || n != 1 {
		t.Fatalf("pruned %d err %v, want 1", n, err)
	}
}

func TestOptimizeRuns(t *testing.T) {
	s := openTemp(t)
	if err := s.Optimize(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := s.Optimize(context.Background()); err == nil {
		t.Fatal("Optimize on a closed store must report the error")
	}
}
