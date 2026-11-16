// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package server

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
)

type retClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *retClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *retClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// The runner prunes at start and then once per 24 h of the injected clock, by
// ARRIVAL: an event with an old agent ts that arrived recently stays. Closed
// windows go at 90 days. No path reaches the log.
func TestRetentionRunner(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	clk := &retClock{t: fixedNow}
	h, err := st.CreateHost(ctx, "a", []byte("0123456789abcdef0123456789abcdef"), clk.Now(), store.Audit{Kind: store.ActorCLI, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	old := clk.Now().Add(-400 * 24 * time.Hour)
	for i, c := range []struct {
		path string
		ts   time.Time
		recv time.Time
	}{
		{"/srv/MARKER-OLD", old, old},                                  // arrived 400 days ago: pruned
		{"/srv/MARKER-SPOOLED", old, clk.Now().Add(-24 * time.Hour)},   // old ts, arrived yesterday: kept
		{"/srv/MARKER-RECENT", clk.Now(), clk.Now().Add(-time.Minute)}, // kept
	} {
		if _, err := st.RecordEvent(ctx, store.EventRecord{HostID: h.ID, ReceivedAt: c.recv,
			Event: proto.Event{TS: c.ts, Path: c.path, Signature: fmt.Sprintf("s%d", i), Source: "clamd"}}); err != nil {
			t.Fatal(err)
		}
	}
	// With no alert targets the planner has nothing to do but clear the flags: the
	// events are "planned", so the prune guard (an unfinished alert keeps its event)
	// does not apply to them.
	if _, err := st.PlanAlerts(ctx, clk.Now(), 0, func(store.AlertPlanInput) store.AlertPlanOutput { return store.AlertPlanOutput{} }); err != nil {
		t.Fatal(err)
	}
	logs := &strings.Builder{}
	var lmu sync.Mutex
	log := slog.New(slog.NewJSONHandler(writerFunc(func(p []byte) (int, error) { lmu.Lock(); defer lmu.Unlock(); return logs.Write(p) }), nil))
	tick := make(chan time.Time)
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { RunRetention(rctx, st, clk.Now, DefaultRetention(), log, tick); close(done) }()
	defer func() { cancel(); <-done }()

	count := func() int {
		rows, err := st.ListEvents(ctx, store.EventFilter{Ack: store.AckAll})
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	waitFor := func(want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for count() != want {
			if time.Now().After(deadline) {
				t.Fatalf("%d events, want %d", count(), want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor(2) // the first prune ran at start
	// A tick inside 24 h does nothing, even though an event is now past the limit... ...
	clk.Add(time.Hour)
	tick <- clk.Now()
	time.Sleep(50 * time.Millisecond)
	if count() != 2 {
		t.Fatal("pruned again inside 24 h")
	}
	// 366 days after the spooled event arrived: it goes too, at the next daily run.
	clk.Add(366 * 24 * time.Hour)
	tick <- clk.Now()
	waitFor(0)
	lmu.Lock()
	defer lmu.Unlock()
	if strings.Contains(logs.String(), "MARKER") || !strings.Contains(logs.String(), "old events pruned") {
		t.Fatalf("log: %s", logs.String())
	}
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// Retention bounds and defaults of every key (plan 4.3). A bound that is dropped
// lets a typo delete history at once or keep personal data for centuries.
func TestRetentionConfig(t *testing.T) {
	d := DefaultRetention()
	if d != (Retention{ReportsDays: 30, EventsDays: 365, StateChangesDays: 365, AlertLogDays: 90, AuditDays: 365}) {
		t.Fatalf("defaults %+v", d)
	}
	if c := DefaultConfig(); c.Retention != d {
		t.Fatalf("DefaultConfig retention %+v", c.Retention)
	}
	for _, k := range []struct {
		key      string
		set      func(*Retention, int)
		min, max int
	}{
		{"reports_days", func(r *Retention, v int) { r.ReportsDays = v }, 14, 90},
		{"events_days", func(r *Retention, v int) { r.EventsDays = v }, 7, 3650},
		{"state_changes_days", func(r *Retention, v int) { r.StateChangesDays = v }, 30, 3650},
		{"alert_log_days", func(r *Retention, v int) { r.AlertLogDays = v }, 30, 3650},
		{"audit_days", func(r *Retention, v int) { r.AuditDays = v }, 90, 3650},
	} {
		for _, v := range []int{k.min, k.max} {
			r := DefaultRetention()
			k.set(&r, v)
			if err := r.Validate(); err != nil {
				t.Errorf("%s=%d: %v", k.key, v, err)
			}
		}
		for _, v := range []int{k.min - 1, k.max + 1, 0, -1} {
			r := DefaultRetention()
			k.set(&r, v)
			if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "retention."+k.key) {
				t.Errorf("%s=%d accepted or unnamed: %v", k.key, v, err)
			}
		}
	}
}

// recordingStore records what a pass does. Only the methods the runner calls are
// implemented; the embedded nil interface panics on anything else.
type recordingStore struct {
	store.EventStore
	mu      sync.Mutex
	calls   []string
	cutoffs map[string]time.Time
	passes  int
	block   chan struct{} // when set, PruneEvents waits for it
	entered chan struct{}
}

func (r *recordingStore) rec(name string, before time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, name)
	if r.cutoffs == nil {
		r.cutoffs = map[string]time.Time{}
	}
	r.cutoffs[name] = before
}
func (r *recordingStore) PruneEvents(_ context.Context, b time.Time, _ int) (int64, error) {
	r.mu.Lock()
	r.passes++
	r.mu.Unlock()
	if r.entered != nil {
		r.entered <- struct{}{}
	}
	if r.block != nil {
		<-r.block
	}
	r.rec("events", b)
	return 0, nil
}
func (r *recordingStore) PruneAlertWindows(_ context.Context, b time.Time, _ int) (int64, error) {
	r.rec("windows", b)
	return 0, nil
}
func (r *recordingStore) PruneReports(_ context.Context, b time.Time, _ int) (int64, error) {
	r.rec("reports", b)
	return 0, nil
}
func (r *recordingStore) PruneStateChanges(_ context.Context, b time.Time, _ int) (int64, error) {
	r.rec("state_changes", b)
	return 0, nil
}
func (r *recordingStore) PruneAudit(_ context.Context, b time.Time, _ int) (int64, error) {
	r.rec("audit", b)
	return 0, nil
}
func (r *recordingStore) Optimize(context.Context) error { r.rec("optimize", time.Time{}); return nil }

func (r *recordingStore) snapshot() ([]string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...), r.passes
}

// Every table is pruned with its own key, and PRAGMA optimize runs once per pass,
// after all the prunes. Mutation: unwire one table, or drop Optimize.
func TestRetentionPassPrunesEveryTableThenOptimizes(t *testing.T) {
	rs := &recordingStore{}
	r := Retention{ReportsDays: 20, EventsDays: 100, StateChangesDays: 200, AlertLogDays: 90, AuditDays: 300}
	log := slog.New(slog.NewJSONHandler(&strings.Builder{}, nil))
	if !pruneOnce(context.Background(), rs, fixedNow, r, log) {
		t.Fatal("pass failed")
	}
	calls, _ := rs.snapshot()
	if strings.Join(calls, ",") != "events,state_changes,reports,windows,audit,optimize" {
		t.Fatalf("calls %v", calls)
	}
	for k, d := range map[string]int{"events": 100, "state_changes": 200, "reports": 20, "audit": 300} {
		if want := fixedNow.Add(-days(d)); !rs.cutoffs[k].Equal(want) {
			t.Errorf("%s cutoff %v, want %v", k, rs.cutoffs[k], want)
		}
	}
}

// Rule: passes never overlap. The first pass is blocked inside a prune while five
// ticks arrive (the caller's ticker holds one and drops the rest); once it
// finishes, the next pass starts only after 24 h on the injected clock.
func TestRetentionRunnerNeverOverlaps(t *testing.T) {
	rs := &recordingStore{block: make(chan struct{}), entered: make(chan struct{}, 4)}
	clk := &retClock{t: fixedNow}
	tick := make(chan time.Time, 1) // like time.Ticker's channel: one buffered tick
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	log := slog.New(slog.NewJSONHandler(&strings.Builder{}, nil))
	go func() { RunRetention(ctx, rs, clk.Now, DefaultRetention(), log, tick); close(done) }()
	defer func() { cancel(); <-done }()

	<-rs.entered // the first pass is inside PruneEvents
	for i := 0; i < 5; i++ {
		select {
		case tick <- clk.Now():
		default: // dropped, as time.Ticker does
		}
	}
	if _, passes := rs.snapshot(); passes != 1 {
		t.Fatalf("%d passes started while the first was blocked", passes)
	}
	close(rs.block)
	// The buffered tick is consumed right after the first pass; no 24 h passed on the clock.
	time.Sleep(100 * time.Millisecond)
	if _, passes := rs.snapshot(); passes != 1 {
		t.Fatalf("a second pass ran %d without 24 h on the injected clock", passes)
	}
	clk.Add(24 * time.Hour)
	tick <- clk.Now()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, passes := rs.snapshot(); passes == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no second pass after 24 h")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
