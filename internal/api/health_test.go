// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package api_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/health"
	"github.com/clamfleet/clamfleet/internal/server"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
)

// goldenNow is one hour after the golden report's ts, so its signatures are
// fresh and its scan is recent: the only thing wrong with the golden host is
// that freshclam is "inactive" (WARN), as on a real Debian box with the
// updater stopped.
var goldenNow = time.Date(2026, 11, 12, 11, 30, 45, 0, time.UTC)

// newHealthEnv is newEnv with the health evaluator wired the way the binary
// wires it: the evaluator's Host is the AfterReport hook.
func newHealthEnv(t *testing.T, after func(ev *health.Evaluator) func(context.Context, int64) error) *env {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "api.db")
	st, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	clock := func() time.Time { return goldenNow }
	ev := health.New(st, clock, health.DefaultThresholds(), log)
	h := server.NewHandler(server.Deps{Store: st, Now: clock, Log: log, AfterReport: after(ev)})
	e := &env{t: t, srv: httptest.NewServer(h), st: st, dbPath: path, logs: logs}
	t.Cleanup(func() { e.srv.Close(); st.Close() })
	return e
}

func hostHost(ev *health.Evaluator) func(context.Context, int64) error { return ev.Host }

// The "404 on a button" class: nothing but the real router decides whether an
// accepted report reaches the evaluator.
func TestReportTriggersEvaluation(t *testing.T) {
	e := newHealthEnv(t, hostHost)
	tok := e.host("app01")
	if d := e.detail("app01"); d.State != nil {
		t.Fatalf("before any report the host is pending, got %v", *d.State)
	}
	if r := e.do("POST", "/v1/report", tok, golden(t)); r.status != 202 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	d := e.detail("app01")
	if d.State == nil || *d.State != "WARN" || !strings.Contains(string(d.StateReason), "freshclam_inactive") {
		t.Fatalf("golden report: state %v reasons %s", d.State, d.StateReason)
	}

	// clamd stops: CRIT at once, not one loop later.
	down := report(t, func(m map[string]any) {
		m["ts"] = "2026-11-12T11:30:00Z"
		m["clamd"] = map[string]any{"up": false, "version": nil, "queue": nil, "error": "ping: timeout"}
	})
	if r := e.do("POST", "/v1/report", tok, down); r.status != 202 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	d = e.detail("app01")
	if *d.State != "CRIT" || !strings.Contains(string(d.StateReason), "clamd_down") || !strings.Contains(string(d.StateReason), "ping: timeout") {
		t.Fatalf("after clamd down: %v %s", *d.State, d.StateReason)
	}
	if len(d.StateChanges) != 2 || d.StateChanges[0].To != "CRIT" || *d.StateChanges[0].From != "WARN" {
		t.Fatalf("history: %+v", d.StateChanges)
	}
}

// Nothing reaches the evaluator for a request that stored nothing, and a
// duplicate (a retry) does: last_seen moved.
func TestAfterReportOnlyForAcceptedReports(t *testing.T) {
	var calls atomic.Int32
	e := newHealthEnv(t, func(*health.Evaluator) func(context.Context, int64) error {
		return func(context.Context, int64) error { calls.Add(1); return nil }
	})
	tok := e.host("app01")
	if r := e.do("POST", "/v1/report", "", golden(t)); r.status != 401 {
		t.Fatalf("%d", r.status)
	}
	if r := e.do("POST", "/v1/report", tok, []byte(`{"schema":2}`)); r.status != 400 {
		t.Fatalf("%d", r.status)
	}
	if calls.Load() != 0 {
		t.Fatalf("evaluator called %d times for rejected requests", calls.Load())
	}
	for i := 0; i < 2; i++ { // the second is a duplicate of the first
		if r := e.do("POST", "/v1/report", tok, golden(t)); r.status != 202 {
			t.Fatalf("%d", r.status)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("evaluator called %d times for two accepted reports, want 2", calls.Load())
	}
}

// The report is already stored when the evaluation runs: its failure is logged
// and the agent still gets its 202 (a 5xx would make it retry a stored report).
func TestAfterReportFailureDoesNotChangeTheResponse(t *testing.T) {
	e := newHealthEnv(t, func(*health.Evaluator) func(context.Context, int64) error {
		return func(context.Context, int64) error { return errors.New("evaluation exploded") }
	})
	tok := e.host("app01")
	if r := e.do("POST", "/v1/report", tok, golden(t)); r.status != 202 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	if d := e.detail("app01"); d.ReportCount != 1 {
		t.Fatal("the report must be stored")
	}
	if countMsg(e, "health evaluation after a report failed") != 1 {
		t.Fatalf("failure not logged once:\n%s", e.logs.String())
	}
	if strings.Contains(e.logs.String(), tok) {
		t.Fatal("token in log")
	}
}
