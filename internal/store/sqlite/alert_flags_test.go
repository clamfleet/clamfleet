// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
)

// A transition is flagged for the alert planner in the same transaction that
// writes it; a reason-only change is not a transition and is not flagged.
func TestEvaluateHostsFlagsTransitionsForAlerting(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "web01")

	if _, err := s.EvaluateHosts(ctx, t0, nil, fixed("OK")); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM state_changes WHERE alert_pending = 1`); n != 1 {
		t.Fatalf("the first evaluation must be flagged (the planner decides it sends nothing): %d", n)
	}
	if _, err := s.w.Exec(`UPDATE state_changes SET alert_pending = 0`); err != nil { // as the planner would
		t.Fatal(err)
	}
	if _, err := s.EvaluateHosts(ctx, t0.Add(time.Minute), nil, fixed("OK", "reason-only")); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM state_changes WHERE alert_pending = 1`); n != 0 {
		t.Fatalf("a reason-only change was flagged: %d", n)
	}
	if _, err := s.EvaluateHosts(ctx, t0.Add(2*time.Minute), nil, fixed("CRIT", "clamd_down")); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM state_changes WHERE alert_pending = 1 AND to_state = 'CRIT'`); n != 1 {
		t.Fatalf("OK->CRIT must be flagged: %d", n)
	}
}

// A new event is flagged; a duplicate retry from the agent leaves the existing
// row, flag included, alone (so a retried POST never alerts twice).
func TestRecordEventFlagsOnlyNewRows(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	e := store.EventRecord{HostID: h.ID, ReceivedAt: t0, Event: proto.Event{
		Schema: 1, Host: "a", TS: t0, Path: "/tmp/eicar", Signature: "Eicar", Source: "scan"}}
	if _, err := s.RecordEvent(ctx, e); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM events WHERE alert_pending = 1`); n != 1 {
		t.Fatalf("a new event must be flagged: %d", n)
	}
	if _, err := s.w.Exec(`UPDATE events SET alert_pending = 0`); err != nil { // planned meanwhile
		t.Fatal(err)
	}
	if stored, err := s.RecordEvent(ctx, e); err != nil || stored {
		t.Fatalf("duplicate: stored=%v err=%v", stored, err)
	}
	if n := count(t, s, `SELECT count(*) FROM events WHERE alert_pending = 1`); n != 0 {
		t.Fatalf("a duplicate retry re-flagged the event: %d", n)
	}
}
