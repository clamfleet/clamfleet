// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package server

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
)

func ptr[T any](v T) *T { return &v }

// The encoder's golden output for a fixed snapshot: the format, the sort order, a
// host that was never seen (no last-seen series) and a host without a database
// (no age series for it).
func TestEncodeMetricsGolden(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	got := string(EncodeMetrics(store.MetricsSnapshot{
		Hosts: []store.MetricsHost{
			{Name: "web02", State: ptr("CRIT"), LastSeen: ptr(time.Unix(1_999_999_000, 0)), SigBuilt: map[string]time.Time{"daily": time.Unix(1_999_996_400, 0), "main": time.Unix(1_999_000_000, 0)}},
			{Name: "app01", State: ptr("OK"), LastSeen: ptr(time.Unix(1_999_999_900, 0))},
			{Name: "new01"},
		},
		OpenEvents: 3, DeliveriesPending: 1, DeliveriesRetrying: 2, DeliveriesFailed: 4,
	}, now, "0.6.0"))
	want := `# HELP clamfleet_hosts Registered hosts by health state ("pending": never evaluated; revoked hosts excluded).
# TYPE clamfleet_hosts gauge
clamfleet_hosts{state="OK"} 1
clamfleet_hosts{state="WARN"} 0
clamfleet_hosts{state="CRIT"} 1
clamfleet_hosts{state="STALE"} 0
clamfleet_hosts{state="pending"} 1
# HELP clamfleet_host_state One series per host, 1 for the host's current health state.
# TYPE clamfleet_host_state gauge
clamfleet_host_state{host="app01",state="OK"} 1
clamfleet_host_state{host="new01",state="pending"} 1
clamfleet_host_state{host="web02",state="CRIT"} 1
# HELP clamfleet_host_last_seen_timestamp_seconds Unix time of the host's last accepted report (absent when never seen).
# TYPE clamfleet_host_last_seen_timestamp_seconds gauge
clamfleet_host_last_seen_timestamp_seconds{host="app01"} 1999999900
clamfleet_host_last_seen_timestamp_seconds{host="web02"} 1999999000
# HELP clamfleet_host_signature_age_seconds Server clock minus the build time of the host's signature database (daily, main, bytecode).
# TYPE clamfleet_host_signature_age_seconds gauge
clamfleet_host_signature_age_seconds{host="web02",db="daily"} 3600
clamfleet_host_signature_age_seconds{host="web02",db="main"} 1000000
# HELP clamfleet_events_open Detections not yet acknowledged.
# TYPE clamfleet_events_open gauge
clamfleet_events_open 3
# HELP clamfleet_alert_deliveries Alert deliveries: pending and retrying now, failed within retention.alert_log_days.
# TYPE clamfleet_alert_deliveries gauge
clamfleet_alert_deliveries{status="failed"} 4
clamfleet_alert_deliveries{status="pending"} 1
clamfleet_alert_deliveries{status="retrying"} 2
# HELP clamfleet_build_info The server version, always 1.
# TYPE clamfleet_build_info gauge
clamfleet_build_info{version="0.6.0"} 1
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

// A label value is escaped (\, " and newline), or one odd host name would break
// the whole scrape: Prometheus rejects a malformed exposition.
func TestEncodeMetricsEscapesLabelValues(t *testing.T) {
	got := string(EncodeMetrics(store.MetricsSnapshot{Hosts: []store.MetricsHost{{Name: "a\"b\\c\nd", State: ptr("OK")}}}, time.Unix(1, 0), "v"))
	if !strings.Contains(got, `clamfleet_host_state{host="a\"b\\c\nd",state="OK"} 1`) {
		t.Fatalf("not escaped:\n%s", got)
	}
	for _, l := range strings.Split(strings.TrimSpace(got), "\n") {
		if !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "clamfleet_") {
			t.Fatalf("a line that is neither a comment nor a series: %q", l)
		}
	}
}

const metricsToken = "0123456789abcdef0123456789abcdef0123456789ab"

type metricsEnv struct {
	h     http.Handler
	st    *sqlite.Store
	db    *sql.DB
	logs  *strings.Builder
	clock time.Time
}

func newMetricsEnv(t *testing.T, token []byte) *metricsEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "m.db")
	st, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	logs := &strings.Builder{}
	var mu sync.Mutex
	log := slog.New(slog.NewJSONHandler(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return logs.Write(p) }), nil))
	e := &metricsEnv{st: st, db: db, logs: logs, clock: fixedNow}
	e.h = NewHandler(Deps{Store: st, Now: func() time.Time { return e.clock }, Log: log, MetricsToken: token, Version: "9.9.9"})
	return e
}

func (e *metricsEnv) get(t *testing.T, hdr map[string]string) (int, string, http.Header) {
	t.Helper()
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.RemoteAddr = "192.0.2.7:4000"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	b, _ := io.ReadAll(w.Result().Body)
	return w.Code, string(b), w.Result().Header
}

func (e *metricsEnv) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := e.db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// Disabled: 404, whatever is sent. Enabled: 401 for no header, a wrong token,
// another scheme and a token with a trailing space, each with a warn line that
// carries the client address and never the header; the right token gets 200.
// Mutations: no token check, or answering while disabled.
func TestMetricsThroughRouter(t *testing.T) {
	off := newMetricsEnv(t, nil)
	if code, _, _ := off.get(t, map[string]string{"Authorization": "Bearer " + metricsToken}); code != 404 {
		t.Fatalf("disabled: %d, want 404", code)
	}

	e := newMetricsEnv(t, []byte(metricsToken))
	for name, hdr := range map[string]map[string]string{
		"no header":      nil,
		"wrong token":    {"Authorization": "Bearer wrong-token-wrong-token-wrong-token-1"},
		"basic":          {"Authorization": "Basic " + metricsToken},
		"trailing space": {"Authorization": "Bearer " + metricsToken + " "},
		"prefix":         {"Authorization": "Bearer " + metricsToken[:20]},
		"lowercase":      {"Authorization": "bearer " + metricsToken},
	} {
		code, body, _ := e.get(t, hdr)
		if code != 401 || strings.Contains(body, "clamfleet_") {
			t.Errorf("%s: %d", name, code)
		}
	}
	if !strings.Contains(e.logs.String(), `"client":"192.0.2.7"`) {
		t.Fatalf("no warn line with the client address:\n%s", e.logs.String())
	}
	if strings.Contains(e.logs.String(), "wrong-token") || strings.Contains(e.logs.String(), metricsToken[:20]) {
		t.Fatal("a presented token reached the log")
	}
	// A console session cookie alone is not a credential here.
	if code, _, _ := e.get(t, map[string]string{"Cookie": "__Host-clamfleet_session=abc"}); code != 401 {
		t.Fatalf("a session cookie alone: %d", code)
	}

	code, body, h := e.get(t, map[string]string{"Authorization": "Bearer " + metricsToken})
	if code != 200 || h.Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", code, h)
	}
	if !strings.Contains(body, `clamfleet_build_info{version="9.9.9"} 1`) {
		t.Fatalf("body:\n%s", body)
	}
}

// The seeded fleet (OK, WARN, CRIT, STALE, pending, one revoked; one open event; one
// retrying delivery) gives the expected numbers.
func TestMetricsCountsTheSeededFleet(t *testing.T) {
	ctx := context.Background()
	e := newMetricsEnv(t, []byte(metricsToken))
	mk := func(name string) int64 {
		h, err := e.st.CreateHost(ctx, name, []byte("0123456789abcdef0123456789abcdef"+name), e.clock, store.Audit{Kind: store.ActorCLI, Actor: "t"})
		if err != nil {
			t.Fatal(err)
		}
		return h.ID
	}
	for name, state := range map[string]string{"ok1": "OK", "ok2": "OK", "warn1": "WARN", "crit1": "CRIT", "stale1": "STALE"} {
		mk(name)
		e.exec(t, `UPDATE hosts SET state = ? WHERE name = ?`, state, name)
	}
	mk("fresh1") // never evaluated: pending
	rv := mk("gone1")
	e.exec(t, `UPDATE hosts SET token_hash = NULL, state = 'CRIT' WHERE id = ?`, rv) // revoked: excluded
	built := e.clock.Add(-2 * time.Hour)
	id := mk("sig1")
	if _, err := e.st.RecordReport(ctx, store.ReportRecord{HostID: id, ReceivedAt: e.clock, Report: proto.Report{
		Schema: 1, Host: "sig1", Tags: []string{}, TS: e.clock,
		Sigs: proto.Sigs{Daily: &proto.SigDB{Version: 1, Built: built, Sigs: 1}},
	}}); err != nil {
		t.Fatal(err)
	}
	e.exec(t, `INSERT INTO events (host_id, ts, received_at, path, signature, source) VALUES (?, 1, 1, '/p', 'S', 'clamd')`, id)
	e.exec(t, `INSERT INTO alert_targets (id, name, type, config, created_at, updated_at) VALUES (1, 't', 'webhook', '{}', 1, 1)`)
	for i, c := range []struct {
		status             string
		attempts, finished int64
	}{{"pending", 0, 0}, {"pending", 2, 0}, {"pending", 1, 0}, {"failed", 5, e.clock.Unix() - 3600}, {"failed", 5, 5}, {"sent", 1, 5}} {
		var fin any
		if c.finished != 0 {
			fin = c.finished
		}
		e.exec(t, `INSERT INTO alert_deliveries (alert_id, target_id, host_id, kind, payload, status, attempts, created_at, finished_at) VALUES (?, 1, ?, 'state_change', '{}', ?, ?, 1, ?)`,
			string(rune('a'+i)), id, c.status, c.attempts, fin)
	}
	_, body, _ := e.get(t, map[string]string{"Authorization": "Bearer " + metricsToken})
	for _, want := range []string{
		`clamfleet_hosts{state="OK"} 2`, `clamfleet_hosts{state="WARN"} 1`, `clamfleet_hosts{state="CRIT"} 1`,
		`clamfleet_hosts{state="STALE"} 1`, `clamfleet_hosts{state="pending"} 2`, // fresh1 and sig1
		`clamfleet_events_open 1`,
		`clamfleet_alert_deliveries{status="pending"} 1`, `clamfleet_alert_deliveries{status="retrying"} 2`,
		`clamfleet_alert_deliveries{status="failed"} 1`, // only the one within the window
		`clamfleet_host_signature_age_seconds{host="sig1",db="daily"} 7200`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "gone1") {
		t.Error("a revoked host is exported")
	}
}

// Rule: personal data and free text never reach /metrics: an event's path and
// signature, a host's tags.
func TestMetricsNoPersonalData(t *testing.T) {
	ctx := context.Background()
	e := newMetricsEnv(t, []byte(metricsToken))
	h, err := e.st.CreateHost(ctx, "web01", []byte("0123456789abcdef0123456789abcdef"), e.clock, store.Audit{Kind: store.ActorCLI, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.RecordReport(ctx, store.ReportRecord{HostID: h.ID, ReceivedAt: e.clock, Report: proto.Report{
		Schema: 1, Host: "web01", Tags: []string{"TAG-MARKER-alice"}, TS: e.clock}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.RecordEvent(ctx, store.EventRecord{HostID: h.ID, ReceivedAt: e.clock,
		Event: proto.Event{TS: e.clock, Path: "/home/alice/PATH-MARKER", Signature: "SIG-MARKER", Source: "clamd"}}); err != nil {
		t.Fatal(err)
	}
	_, body, _ := e.get(t, map[string]string{"Authorization": "Bearer " + metricsToken})
	for _, m := range []string{"MARKER", "alice"} {
		if strings.Contains(body, m) {
			t.Fatalf("%q reached /metrics:\n%s", m, body)
		}
	}
	if !strings.Contains(body, "clamfleet_events_open 1") {
		t.Fatalf("the event is not counted:\n%s", body)
	}
}

func TestMetricsConfig(t *testing.T) {
	c := DefaultConfig()
	if c.Metrics.Enabled || c.Metrics.TokenFile != "" {
		t.Fatalf("metrics must be off by default: %+v", c.Metrics)
	}
	c.Metrics.Enabled = true
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "metrics.token_file") {
		t.Fatalf("enabled without a token file: %v", err)
	}
	c.Metrics.TokenFile = "token"
	if err := c.Validate(); err == nil {
		t.Fatal("a relative token_file was accepted")
	}
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	c.Metrics.TokenFile = write("short", "too-short\n", 0o600)
	if _, err := loadMetricsToken(c.Metrics); err == nil || !strings.Contains(err.Error(), "at least 32") {
		t.Fatalf("a short token: %v", err)
	}
	c.Metrics.TokenFile = write("open", metricsToken+"\n", 0o644)
	if _, err := loadMetricsToken(c.Metrics); err == nil {
		t.Fatal("a world-readable token file was accepted")
	}
	c.Metrics.TokenFile = write("good", metricsToken+"\n", 0o600)
	tok, err := loadMetricsToken(c.Metrics)
	if err != nil || string(tok) != metricsToken {
		t.Fatalf("%q %v", tok, err)
	}
	if tok, err := loadMetricsToken(Metrics{}); tok != nil || err != nil {
		t.Fatal("disabled metrics must load nothing")
	}
}
