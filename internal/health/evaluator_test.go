// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package health

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
)

var cli = store.Audit{Kind: store.ActorCLI, Actor: "tester"}

// clock is a settable injected clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

type env struct {
	path string
	t    *testing.T
	st   *sqlite.Store
	clk  *clock
	log  *bytes.Buffer
	ev   *Evaluator
}

func newEnv(t *testing.T) *env {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t.db")
	st, err := sqlite.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := &env{path: path, t: t, st: st, clk: &clock{t: now}, log: &bytes.Buffer{}}
	e.ev = New(st, e.clk.Now, DefaultThresholds(), slog.New(slog.NewTextHandler(e.log, nil)))
	e.ev.StartedAt = now.Add(-100 * 24 * time.Hour) // a long-running server unless a test says otherwise
	return e
}

func (e *env) addHost(name string) int64 {
	e.t.Helper()
	h, err := e.st.CreateHost(context.Background(), name, sha256Of(name), e.clk.Now(), cli)
	if err != nil {
		e.t.Fatal(err)
	}
	return h.ID
}

func sha256Of(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

// report stores a healthy report (or a mutated one) received at the clock's now.
func (e *env) report(id int64, mutate func(*proto.Report)) {
	e.t.Helper()
	r := healthy()
	r.Schema, r.Host, r.Tags, r.TS = 1, "h", []string{}, e.clk.Now()
	r.Sigs.Daily.Built = e.clk.Now().Add(-2 * time.Hour)
	if mutate != nil {
		mutate(r)
	}
	if _, err := e.st.RecordReport(context.Background(), store.ReportRecord{HostID: id, Report: *r, ReceivedAt: e.clk.Now()}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) show(name string) store.HostDetail {
	e.t.Helper()
	d, err := e.st.HostByName(context.Background(), name)
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

func (e *env) history(name string) []string {
	var out []string
	d := e.show(name)
	for i := len(d.StateChanges) - 1; i >= 0; i-- {
		c := d.StateChanges[i]
		from := "NULL"
		if c.From != nil {
			from = *c.From
		}
		out = append(out, from+">"+c.To)
	}
	return out
}

func eq(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

func TestEvaluatorOKThenCritWritesOneRowWithInjectedTime(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("web01")
	e.report(id, nil)
	if err := e.ev.Host(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if h := e.history("web01"); !eq(h, []string{"NULL>OK"}) {
		t.Fatalf("first evaluation: %v", h)
	}

	later := now.Add(7 * time.Minute)
	e.clk.Set(later)
	e.report(id, func(r *proto.Report) { r.Clamd.Up = false; r.Clamd.Error = ptr("ping: timeout") })
	if err := e.ev.Host(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	d := e.show("web01")
	if *d.State != StateCrit || !d.StateSince.Equal(later) || !eq(e.history("web01"), []string{"NULL>OK", "OK>CRIT"}) {
		t.Fatalf("state %v since %v history %v", *d.State, d.StateSince, e.history("web01"))
	}
	if ch := d.StateChanges[0]; !ch.TS.Equal(later) || !strings.Contains(string(ch.Reason), `"clamd_down"`) {
		t.Fatalf("transition row: %+v %s", ch, ch.Reason)
	}
	if !strings.Contains(e.log.String(), "host state changed") {
		t.Fatalf("transition not logged: %s", e.log)
	}

	// Re-evaluating unchanged input writes nothing, and the reasons stay a JSON array.
	e.clk.Set(later.Add(time.Minute))
	e.report(id, func(r *proto.Report) { r.Clamd.Up = false; r.Clamd.Error = ptr("ping: timeout") })
	if err := e.ev.All(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h := e.history("web01"); len(h) != 2 {
		t.Fatalf("unchanged evaluation wrote a row: %v", h)
	}
}

// A reason that comes or goes without a state change refreshes state_reason
// but is not a transition.
func TestEvaluatorReasonOnlyChangeWritesNoRow(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("web01")
	e.report(id, func(r *proto.Report) { r.Services.Freshclam = "inactive" }) // WARN: freshclam_inactive
	if err := e.ev.Host(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	e.clk.Set(now.Add(time.Minute))
	e.report(id, func(r *proto.Report) { r.Services.Freshclam = "inactive"; r.LastScan.Exit = 2 }) // still WARN, one more reason
	if err := e.ev.Host(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	d := e.show("web01")
	if *d.State != StateWarn || !strings.Contains(string(d.StateReason), RuleScanFailed) {
		t.Fatalf("reasons not refreshed: %s", d.StateReason)
	}
	if !eq(e.history("web01"), []string{"NULL>WARN"}) || !d.StateSince.Equal(now) {
		t.Fatalf("a reason-only change was recorded as a transition: %v since %v", e.history("web01"), d.StateSince)
	}
}

func TestEvaluatorNewHostIsPendingThenStaleNeverReported(t *testing.T) {
	e := newEnv(t)
	e.addHost("new01")
	if err := e.ev.All(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := e.show("new01"); d.State != nil || len(d.StateChanges) != 0 {
		t.Fatalf("a new host must be pending: %+v", d)
	}
	e.clk.Set(now.Add(15*time.Minute + time.Second))
	if err := e.ev.All(context.Background()); err != nil {
		t.Fatal(err)
	}
	d := e.show("new01")
	if d.State == nil || *d.State != StateStale || !strings.Contains(string(d.StateReason), RuleNeverReported) {
		t.Fatalf("%+v", d)
	}
}

func TestEvaluatorAgentStopsThenRecovers(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("web01")
	e.report(id, func(r *proto.Report) { r.IntervalSeconds = ptr(60) })
	e.ev.All(context.Background())
	e.clk.Set(now.Add(3 * time.Minute))
	e.ev.All(context.Background())
	if h := e.history("web01"); !eq(h, []string{"NULL>OK"}) {
		t.Fatalf("exactly 3 intervals: %v", h)
	}
	e.clk.Set(now.Add(3*time.Minute + time.Second))
	e.ev.All(context.Background())
	e.report(id, func(r *proto.Report) { r.IntervalSeconds = ptr(60) })
	e.ev.Host(context.Background(), id)
	if h := e.history("web01"); !eq(h, []string{"NULL>OK", "OK>STALE", "STALE>OK"}) {
		t.Fatalf("%v", h)
	}
}

func TestEvaluatorSkipsRevokedHosts(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("gone")
	e.report(id, func(r *proto.Report) { r.Clamd.Up = false })
	if err := e.st.SetToken(context.Background(), "gone", nil, now, cli); err != nil {
		t.Fatal(err)
	}
	if err := e.ev.All(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.ev.Host(context.Background(), id); err != nil {
		t.Fatalf("a revoked host is skipped, not an error: %v", err)
	}
	if d := e.show("gone"); d.State != nil {
		t.Fatalf("revoked host evaluated: %v", *d.State)
	}
}

// A revoked host with the newest daily must not make the rest of the fleet "behind".
func TestEvaluatorRevokedHostDoesNotSetFleetNewest(t *testing.T) {
	e := newEnv(t)
	a, b := e.addHost("a"), e.addHost("revoked")
	e.report(a, nil)                                                  // daily version 100
	e.report(b, func(r *proto.Report) { r.Sigs.Daily.Version = 900 }) // far ahead
	if err := e.st.SetToken(context.Background(), "revoked", nil, now, cli); err != nil {
		t.Fatal(err)
	}
	e.ev.All(context.Background())
	if d := e.show("a"); *d.State != StateOK {
		t.Fatalf("host a: %s %s", *d.State, d.StateReason)
	}
	// ...and a live host that is ahead does count.
	c := e.addHost("c")
	e.report(c, func(r *proto.Report) { r.Sigs.Daily.Version = 200 })
	e.ev.All(context.Background())
	if d := e.show("a"); *d.State != StateWarn || !strings.Contains(string(d.StateReason), RuleDailyBehind) {
		t.Fatalf("host a: %s %s", *d.State, d.StateReason)
	}
}

// A server that was down for hours must not mark every host STALE when it starts.
func TestRestartDoesNotMarkFleetStale(t *testing.T) {
	e := newEnv(t)
	ids := []int64{e.addHost("a"), e.addHost("b")}
	for _, id := range ids {
		e.report(id, nil)
	}
	e.ev.All(context.Background())

	// The server is down for 6 hours, then a new process (new evaluator) starts.
	e.clk.Set(now.Add(6 * time.Hour))
	restarted := New(e.st, e.clk.Now, DefaultThresholds(), slog.New(slog.NewTextHandler(e.log, nil)))
	if err := restarted.All(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a", "b"} {
		if d := e.show(n); *d.State == StateStale || len(d.StateChanges) != 1 {
			t.Fatalf("%s: %s, history %v", n, *d.State, e.history(n))
		}
	}
	// If nobody reports, they do go STALE once the window after the start has passed.
	e.clk.Set(now.Add(6*time.Hour + 15*time.Minute + time.Second))
	restarted.All(context.Background())
	if d := e.show("a"); *d.State != StateStale {
		t.Fatalf("a: %s", *d.State)
	}
}

// Host and All racing: each real change is recorded exactly once.
func TestEvaluatorConcurrentCallsRecordEachChangeOnce(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("web01")
	e.report(id, nil)
	hammer := func() {
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var err error
				if i%2 == 0 {
					err = e.ev.Host(context.Background(), id)
				} else {
					err = e.ev.All(context.Background())
				}
				if err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
	}
	hammer()
	if h := e.history("web01"); !eq(h, []string{"NULL>OK"}) {
		t.Fatalf("%v", h)
	}
	e.clk.Set(now.Add(time.Minute))
	e.report(id, func(r *proto.Report) { r.Clamd.Up = false })
	hammer()
	if h := e.history("web01"); !eq(h, []string{"NULL>OK", "OK>CRIT"}) {
		t.Fatalf("%v", h)
	}
}

type countingStore struct {
	store.HealthStore
	calls atomic.Int32
	fail  atomic.Bool
	mu    sync.Mutex
	asked [][]int64
}

func (c *countingStore) EvaluateHosts(ctx context.Context, now time.Time, ids []int64, eval func(store.HealthInput) store.HealthOutcome) ([]store.Transition, error) {
	c.calls.Add(1)
	c.mu.Lock()
	c.asked = append(c.asked, ids)
	c.mu.Unlock()
	if c.fail.Load() {
		return nil, errors.New("boom")
	}
	return nil, nil
}

func TestRunEvaluatesAtStartAndOnEveryTickAndStopsOnCancel(t *testing.T) {
	cs := &countingStore{}
	logBuf := &bytes.Buffer{}
	ev := New(cs, (&clock{t: now}).Now, DefaultThresholds(), slog.New(slog.NewTextHandler(logBuf, nil)))
	tick := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { ev.Run(ctx, tick); close(done) }()

	waitCalls := func(n int32) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for cs.calls.Load() < n {
			select {
			case <-deadline:
				t.Fatalf("only %d evaluations, want %d", cs.calls.Load(), n)
			case <-time.After(time.Millisecond):
			}
		}
	}
	waitCalls(1) // at start, before any tick
	cs.fail.Store(true)
	tick <- now
	waitCalls(2)
	tick <- now // a failing pass does not end the loop
	waitCalls(3)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
	if n := cs.calls.Load(); n != 3 {
		t.Fatalf("%d evaluations, want 3", n)
	}
	if !strings.Contains(logBuf.String(), "health evaluation failed") {
		t.Fatalf("failure not logged: %s", logBuf)
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for _, ids := range cs.asked {
		if ids != nil {
			t.Fatalf("the loop must evaluate all hosts, got %v", ids)
		}
	}
}

// A corrupt last_report must not make a reporting host look "never reported"
// (measured from registration) nor fail the pass for the other hosts.
func TestEvaluatorCorruptReportIsJudgedFromLastSeen(t *testing.T) {
	e := newEnv(t)
	bad, good := e.addHost("bad01"), e.addHost("good01")
	e.report(bad, nil)
	e.report(good, nil)
	raw, err := sql.Open("sqlite", e.path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE hosts SET last_report='{not json' WHERE name='bad01'`); err != nil {
		t.Fatal(err)
	}
	if err := e.ev.All(context.Background()); err != nil {
		t.Fatalf("one corrupt row must not fail the pass: %v", err)
	}
	d := e.show("bad01")
	if *d.State != StateWarn || !strings.Contains(string(d.StateReason), RuleReportUnreadable) {
		t.Fatalf("%s %s", *d.State, d.StateReason)
	}
	if g := e.show("good01"); *g.State != StateOK {
		t.Fatalf("the healthy host was not evaluated: %s", *g.State)
	}
	if !strings.Contains(e.log.String(), "bad01") || !strings.Contains(e.log.String(), "cannot be decoded") {
		t.Fatalf("no warning naming the host:\n%s", e.log)
	}
	// Long after registration but 1 minute after its last report: still not STALE.
	e.clk.Set(now.Add(time.Minute))
	e.ev.All(context.Background())
	if d := e.show("bad01"); strings.Contains(string(d.StateReason), RuleNeverReported) || *d.State == StateStale {
		t.Fatalf("a reporting host was judged never_reported/STALE: %s", d.StateReason)
	}
	// Silent past the window: STALE with the stale reason.
	e.clk.Set(now.Add(15*time.Minute + time.Second))
	e.ev.All(context.Background())
	if d := e.show("bad01"); *d.State != StateStale || !strings.Contains(string(d.StateReason), `"stale"`) {
		t.Fatalf("%s %s", *d.State, d.StateReason)
	}
}
