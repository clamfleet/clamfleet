// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

// burstSetup has host "a" and a webhook target with burst 2, then records n
// detections received at t0 and plans them.
func burstSetup(t *testing.T, n int) *Store {
	t.Helper()
	s := openTemp(t)
	addHost(t, s, "a")
	newTarget(t, s, "ops", "webhook", func(nt *store.NewAlertTarget) { nt.DetectionBurst = 2 })
	for i := 0; i < n; i++ {
		rec(t, s, 1, event("a", aid(i+1), t0, "/p/"+itoa(int64(i)), "Win.Test.EICAR"), t0)
	}
	plan(t, s, t0.Add(time.Second))
	return s
}

func TestWindowIsHeldThenSummarisedInOneTransaction(t *testing.T) {
	ctx := context.Background()
	s := burstSetup(t, 5)
	if n := count(t, s, `SELECT count(*) FROM alert_deliveries WHERE kind = 'detection'`); n != 2 {
		t.Fatalf("%d individual deliveries, want 2", n)
	}
	if n := count(t, s, `SELECT count(*) FROM alert_window_events`); n != 3 {
		t.Fatalf("%d held members, want 3", n)
	}
	if count(t, s, `SELECT count(*) FROM alert_detection_windows WHERE closed_at IS NULL AND sent = 2`) != 1 {
		t.Fatal("one open window with sent = 2")
	}
	if n := count(t, s, `SELECT count(*) FROM alert_log WHERE status = 'held' AND error LIKE 'holding detections beyond 2 until %'`); n != 1 {
		t.Fatalf("%d held rows", n)
	}
	// Members are not "unrouted": they are accounted for.
	if n, _ := s.UnroutedDetections(ctx, t0.Add(-time.Hour)); n != 0 {
		t.Fatalf("held detections counted as unrouted: %d", n)
	}
	work := func(now time.Time) bool {
		ok, err := s.HasAlertWork(ctx, now, testCooldown)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	// The two individual deliveries are due work; drain them to isolate the window.
	// (detections of one host are sent in order, one at a time: claim until none is left)
	for done := 0; done < 2; {
		c, _ := s.ClaimDeliveries(ctx, t0.Add(2*time.Second), time.Minute, store.Claim(10))
		if len(c) == 0 {
			t.Fatalf("only %d of 2 individual deliveries claimable", done)
		}
		for _, d := range c {
			s.FinishAttempt(ctx, d, store.AttemptResult{Status: store.AlertLogSent, Code: "HTTP 204"}, t0.Add(2*time.Second))
			done++
		}
	}
	if work(t0.Add(9*time.Minute + 59*time.Second)) {
		t.Fatal("an open window that is not due is not work")
	}
	if !work(t0.Add(10 * time.Minute)) {
		t.Fatal("a due window is work")
	}
	plan(t, s, t0.Add(10*time.Minute))
	if n := count(t, s, `SELECT count(*) FROM alert_deliveries WHERE kind = 'detection_summary' AND event_id IS NULL AND window_id IS NOT NULL`); n != 1 {
		t.Fatalf("%d summary deliveries", n)
	}
	if n := count(t, s, `SELECT count(*) FROM alert_detection_windows WHERE closed_at IS NOT NULL AND outcome = 'summarised'`); n != 1 {
		t.Fatal("the window must be closed 'summarised'")
	}
	var payload string
	if err := s.r.QueryRow(`SELECT payload FROM alert_deliveries WHERE kind = 'detection_summary'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, `"count":3`) || strings.Contains(payload, "/p/") {
		t.Fatalf("summary payload (3 held, and no path): %s", payload)
	}
	if work(t0.Add(11*time.Minute)) && count(t, s, `SELECT count(*) FROM alert_deliveries WHERE status = 'pending' AND claim_token IS NULL AND next_attempt_at <= `+itoa(t0.Add(11*time.Minute).Unix())) == 0 {
		t.Fatal("a closed window must not be work again")
	}
}

// A failure after the summary delivery was inserted rolls the whole pass back:
// the window stays open with its members, and the next pass makes exactly one summary.
func TestWindowCrashBeforeSummaryCommit(t *testing.T) {
	ctx := context.Background()
	s := burstSetup(t, 4)
	at := t0.Add(10 * time.Minute)
	s.afterAlertPlanDeliveries = func() error { return errors.New("crash") }
	if _, err := s.PlanAlerts(ctx, at, testCooldown, planner()); err == nil {
		t.Fatal("want the injected error")
	}
	s.afterAlertPlanDeliveries = nil
	if n := count(t, s, `SELECT count(*) FROM alert_deliveries WHERE kind = 'detection_summary'`); n != 0 {
		t.Fatalf("%d summaries survived the rollback", n)
	}
	if count(t, s, `SELECT count(*) FROM alert_detection_windows WHERE closed_at IS NULL`) != 1 || count(t, s, `SELECT count(*) FROM alert_window_events`) != 2 {
		t.Fatal("the window must still be open with its members")
	}
	plan(t, s, at)
	if n := count(t, s, `SELECT count(*) FROM alert_deliveries WHERE kind = 'detection_summary'`); n != 1 {
		t.Fatalf("%d summaries after the retry, want exactly 1", n)
	}
}

// After a successful pass the window is closed for good: a new store on the same
// file (a restart) and more passes make no second summary.
func TestWindowCrashAfterCommit(t *testing.T) {
	ctx := context.Background()
	s := burstSetup(t, 4)
	at := t0.Add(10 * time.Minute)
	plan(t, s, at)
	path := s.path
	s.Close()
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	for i := 1; i <= 3; i++ {
		plan(t, s2, at.Add(time.Duration(i)*time.Minute))
	}
	if n := count(t, s2, `SELECT count(*) FROM alert_deliveries WHERE kind = 'detection_summary'`); n != 1 {
		t.Fatalf("%d summaries, want 1", n)
	}
}

// Decision 15: detections switched off while a window holds events: the window
// is discarded with one cancelled log row, no summary follows even when the
// switch is turned back on, and the events stay stored.
func TestWindowDiscardedWhenDetectionsSwitchedOff(t *testing.T) {
	ctx := context.Background()
	s := burstSetup(t, 5)
	upd := func(edit func(*store.AlertTargetUpdate)) store.Cancelled {
		u := store.AlertTargetUpdate{Config: []byte(`{}`), MinSeverity: "WARN", SendStateChanges: true, SendDetections: true, Enabled: true}
		edit(&u)
		c, err := s.UpdateAlertTarget(ctx, "ops", u, nil, t0.Add(time.Minute), cli)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := upd(func(u *store.AlertTargetUpdate) { u.SendDetections = false })
	if c.HeldDetections != 3 {
		t.Fatalf("%+v", c)
	}
	if n := count(t, s, `SELECT count(*) FROM alert_detection_windows WHERE outcome = 'discarded' AND closed_at IS NOT NULL`); n != 1 {
		t.Fatal("the window must be closed 'discarded'")
	}
	if n := count(t, s, `SELECT count(*) FROM alert_log WHERE status = 'cancelled' AND error = '3 held detections were not summarised: detections switched off for this target'`); n != 1 {
		t.Fatal("one cancelled row naming the count")
	}
	upd(func(u *store.AlertTargetUpdate) {})
	plan(t, s, t0.Add(time.Hour))
	if n := count(t, s, `SELECT count(*) FROM alert_deliveries WHERE kind = 'detection_summary'`); n != 0 {
		t.Fatalf("%d summaries after a discard", n)
	}
	if n := count(t, s, `SELECT count(*) FROM events`); n != 5 {
		t.Fatalf("the events must stay: %d", n)
	}
	entries, err := s.AlertLog(ctx, store.AlertLogFilter{TargetName: "ops", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Status == store.AlertLogCancelled && strings.Contains(e.Error, "held detections") {
			found = true
			if e.Kind != "detection" {
				t.Fatalf("a discard row is about detections, kind %q", e.Kind)
			}
		}
	}
	if !found {
		t.Fatal("the discard row is not in the log")
	}
}

func TestWindowDiscardedWhenTargetDisabled(t *testing.T) {
	ctx := context.Background()
	s := burstSetup(t, 4)
	u := store.AlertTargetUpdate{Config: []byte(`{}`), MinSeverity: "WARN", SendStateChanges: true, SendDetections: true, Enabled: false}
	c, err := s.UpdateAlertTarget(ctx, "ops", u, nil, t0.Add(time.Minute), cli)
	if err != nil || c.HeldDetections != 2 {
		t.Fatalf("%+v %v", c, err)
	}
	if count(t, s, `SELECT count(*) FROM alert_detection_windows WHERE outcome = 'discarded'`) != 1 {
		t.Fatal("not discarded")
	}
}

// A window with nothing held that is switched off is closed quietly: no log row.
func TestEmptyWindowDiscardWritesNoLogRow(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	newTarget(t, s, "ops", "webhook", func(nt *store.NewAlertTarget) { nt.DetectionBurst = 5 })
	rec(t, s, 1, event("a", aid(1), t0, "/p", "S"), t0)
	plan(t, s, t0)
	before := count(t, s, `SELECT count(*) FROM alert_log WHERE status = 'cancelled'`)
	u := store.AlertTargetUpdate{Config: []byte(`{}`), MinSeverity: "WARN", SendStateChanges: true, SendDetections: false, Enabled: true}
	if _, err := s.UpdateAlertTarget(ctx, "ops", u, nil, t0.Add(time.Minute), cli); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT count(*) FROM alert_detection_windows WHERE outcome = 'discarded'`) != 1 {
		t.Fatal("the window is not closed")
	}
	if after := count(t, s, `SELECT count(*) FROM alert_log WHERE status = 'cancelled'`); after-before != 1 {
		// one row for the cancelled pending delivery of the first detection, none for the window
		t.Fatalf("%d new cancelled rows, want 1", after-before)
	}
}

// The log names the kind from the delivery: a summary is "detection summary",
// never "test".
func TestAlertLogKindOfASummary(t *testing.T) {
	ctx := context.Background()
	s := burstSetup(t, 4)
	plan(t, s, t0.Add(10*time.Minute))
	c, _ := s.ClaimDeliveries(ctx, t0.Add(10*time.Minute), time.Minute, store.Claim(10))
	for _, d := range c {
		if d.Kind == store.DeliveryDetectionSummary {
			if err := s.FinishAttempt(ctx, d, store.AttemptResult{Status: store.AlertLogSent, Code: "HTTP 204"}, t0.Add(10*time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
	}
	entries, err := s.AlertLog(ctx, store.AlertLogFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Kind+"/"+e.Status] = true
	}
	if !got["detection summary/sent"] || got["test/sent"] {
		t.Fatalf("log kinds: %v", got)
	}
	// And a real test send is still "test".
	if err := s.RecordTestSend(ctx, "ops", []store.TestSendRecord{{Result: store.AttemptResult{Status: store.AlertLogSent, Code: "HTTP 204"}}}, t0.Add(time.Hour), cli); err != nil {
		t.Fatal(err)
	}
	entries, _ = s.AlertLog(ctx, store.AlertLogFilter{Limit: 50})
	if entries[0].Kind != "test" {
		t.Fatalf("test send kind %q", entries[0].Kind)
	}
}

// The burst is a per-target setting, stored and changed through the target.
func TestDetectionBurstIsStoredAndUpdated(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	tg := newTarget(t, s, "ops", "webhook", func(n *store.NewAlertTarget) { n.DetectionBurst = 7 })
	if tg.DetectionBurst != 7 {
		t.Fatal(tg.DetectionBurst)
	}
	got, err := s.AlertTarget(ctx, "ops")
	if err != nil || got.DetectionBurst != 7 {
		t.Fatalf("%+v %v", got, err)
	}
	u := store.AlertTargetUpdate{Config: []byte(`{}`), MinSeverity: "WARN", SendStateChanges: true, SendDetections: true, Enabled: true}
	if _, err := s.UpdateAlertTarget(ctx, "ops", u, nil, t0, cli); err != nil { // nil burst = unchanged
		t.Fatal(err)
	}
	if got, _ := s.AlertTarget(ctx, "ops"); got.DetectionBurst != 7 {
		t.Fatalf("an update without a burst changed it to %d", got.DetectionBurst)
	}
	zero := 0
	u.DetectionBurst = &zero
	if _, err := s.UpdateAlertTarget(ctx, "ops", u, nil, t0, cli); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.AlertTarget(ctx, "ops"); got.DetectionBurst != 0 {
		t.Fatalf("burst %d", got.DetectionBurst)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action = 'alert_target.update' AND detail LIKE '%detection_burst%'`); n != 1 {
		t.Fatal("the audit row must name the changed field")
	}
	neg := -1
	u.DetectionBurst = &neg
	if _, err := s.UpdateAlertTarget(ctx, "ops", u, nil, t0, cli); err == nil {
		t.Fatal("a negative burst was accepted")
	}
}
