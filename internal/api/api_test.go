// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// These tests go through the real router: an httptest.NewServer around
// server.NewHandler, a real http.Client, a real SQLite store, an injected
// clock and a log buffer. A test that called a handler function directly could
// not notice an unmounted route or a missing middleware (a release once
// shipped with a 404 on a button that way).
package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/agentauth"
	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/server"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
)

// now is the injected server clock. It is far from the real date on purpose:
// anything stamped from the wall clock instead of this would be visibly wrong.
var now = time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type env struct {
	t      *testing.T
	srv    *httptest.Server
	st     *sqlite.Store
	dbPath string
	logs   *syncBuf
}

func newEnv(t *testing.T) *env { return newEnvLevel(t, slog.LevelDebug) }

// newEnvLevel is newEnv with the log handler at a given level (the server default is info).
func newEnvLevel(t *testing.T, level slog.Level) *env { return newEnvOpts(t, level, nil) }

// newEnvOpts also sets the trusted proxies.
func newEnvOpts(t *testing.T, level slog.Level, trusted []netip.Prefix) *env {
	t.Helper()
	return newEnvDeps(t, level, trusted, nil)
}

// newEnvDeps also lets a test set hooks on server.Deps (AfterReport, AfterEvent).
func newEnvDeps(t *testing.T, level slog.Level, trusted []netip.Prefix, mut func(*server.Deps)) *env {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api.db")
	ctx := context.Background()
	st, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: level}))
	deps := server.Deps{Store: st, Now: func() time.Time { return now }, Log: log, TrustedProxies: trusted}
	if mut != nil {
		mut(&deps)
	}
	h := server.NewHandler(deps)
	e := &env{t: t, srv: httptest.NewServer(h), st: st, dbPath: path, logs: logs}
	t.Cleanup(func() { e.srv.Close(); st.Close() })
	return e
}

// host registers a host and returns its token.
func (e *env) host(name string) string {
	e.t.Helper()
	tok, hash, err := agentauth.Generate()
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.st.CreateHost(context.Background(), name, hash, now, store.Audit{Kind: store.ActorCLI, Actor: "test"}); err != nil {
		e.t.Fatal(err)
	}
	return tok
}

type resp struct {
	status int
	body   string
	header http.Header
}

func (e *env) do(method, path, token string, body []byte) resp {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	// Redirects are not followed: the route-table test must see the 303 itself.
	c := &http.Client{Transport: e.srv.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return resp{r.StatusCode, string(b), r.Header}
}

func (e *env) detail(name string) store.HostDetail {
	e.t.Helper()
	d, err := e.st.HostByName(context.Background(), name)
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

func golden(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "agent", "testdata", "report.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// report returns the golden report (real agent output) after mutating its
// generic JSON form.
func report(t *testing.T, mut func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(golden(t), &m); err != nil {
		t.Fatal(err)
	}
	if mut != nil {
		mut(m)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func event(t *testing.T, mut func(m map[string]any)) []byte {
	t.Helper()
	m := map[string]any{"schema": 1, "host": "app01", "ts": "2026-11-12T10:30:45Z",
		"path": "/home/u/eicar.txt", "signature": "Win.Test.EICAR_HDB-1", "source": "clamonacc"}
	if mut != nil {
		mut(m)
	}
	b, _ := json.Marshal(m)
	return b
}

func logLines(e *env) []map[string]any {
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(e.logs.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			e.t.Fatalf("log line is not JSON: %q", l)
		}
		out = append(out, m)
	}
	return out
}

func countMsg(e *env, substr string) int {
	n := 0
	for _, m := range logLines(e) {
		if s, _ := m["msg"].(string); strings.Contains(s, substr) {
			n++
		}
	}
	return n
}

func TestReportStoredThroughRouter(t *testing.T) {
	e := newEnv(t)
	tok := e.host("app01")
	r := e.do("POST", "/v1/report", tok, golden(t))
	if r.status != 202 || strings.TrimSpace(r.body) != "{}" {
		t.Fatalf("status %d body %q", r.status, r.body)
	}
	if ct := r.header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}
	d := e.detail("app01")
	var rep proto.Report
	if err := json.Unmarshal(golden(t), &rep); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(rep)
	if string(d.LastReport) != string(want) {
		t.Fatalf("last_report is not the canonical payload\n got %s\nwant %s", d.LastReport, want)
	}
	// Times are the injected clock (2031), not the agent's (2026) or the real one.
	if d.FirstSeen == nil || !d.FirstSeen.Equal(now) || d.LastSeen == nil || !d.LastSeen.Equal(now) {
		t.Fatalf("first_seen %v last_seen %v, want %v", d.FirstSeen, d.LastSeen, now)
	}
	if strings.Join(d.Tags, ",") != "web,prod" && strings.Join(d.Tags, ",") != "prod,web" {
		t.Fatalf("tags %v", d.Tags)
	}
	if d.AgentVersion != "0.1.0" || d.ReportCount != 1 {
		t.Fatalf("%+v", d)
	}
}

func TestBadTokenIs401ThroughRouter(t *testing.T) {
	e := newEnv(t)
	good := e.host("a")
	revoked := e.host("b")
	if err := e.st.SetToken(context.Background(), "b", nil, now, store.Audit{Kind: store.ActorCLI, Actor: "t"}); err != nil {
		t.Fatal(err)
	}
	unknown, _, _ := agentauth.Generate()
	cases := []struct{ name, header string }{
		{"no header", ""},
		{"empty bearer", "Bearer"},
		{"basic", "Basic " + good},
		{"unknown valid-format token", "Bearer " + unknown},
		{"revoked token", "Bearer " + revoked},
		{"malformed", "Bearer cfa_nope"},
		{"user-token prefix", "Bearer cfu_" + good[4:]},
	}
	var first resp
	for i, c := range cases {
		req, _ := http.NewRequest("POST", e.srv.URL+"/v1/report", bytes.NewReader(golden(t)))
		if c.header != "" {
			req.Header.Set("Authorization", c.header)
		}
		hr, err := e.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(hr.Body)
		hr.Body.Close()
		got := resp{hr.StatusCode, string(b), hr.Header}
		if got.status != 401 {
			t.Errorf("%s: status %d", c.name, got.status)
		}
		if got.header.Get("WWW-Authenticate") != `Bearer realm="clamfleet"` {
			t.Errorf("%s: WWW-Authenticate %q", c.name, got.header.Get("WWW-Authenticate"))
		}
		if i == 0 {
			first = got
		} else if got.body != first.body {
			// No oracle: every cause answers byte-for-byte the same.
			t.Errorf("%s: body %q differs from %q", c.name, got.body, first.body)
		}
	}
	for _, name := range []string{"a", "b"} {
		if n := e.detail(name).ReportCount; n != 0 {
			t.Errorf("host %s has %d reports after rejected requests", name, n)
		}
	}
	logs := e.logs.String()
	for _, secret := range []string{good, revoked, unknown, good[4:]} {
		if strings.Contains(logs, secret) {
			t.Fatalf("a token appears in the log:\n%s", logs)
		}
	}
	if strings.Contains(strings.ToLower(logs), "authorization") || strings.Contains(logs, "Bearer") {
		t.Fatalf("the Authorization header appears in the log:\n%s", logs)
	}
}

func TestUnknownFieldsAccepted(t *testing.T) {
	e := newEnv(t)
	tok := e.host("app01")
	b := report(t, func(m map[string]any) {
		m["future_field"] = map[string]any{"x": 1}
		m["os"].(map[string]any)["codename"] = "trixie"
	})
	if r := e.do("POST", "/v1/report", tok, b); r.status != 202 {
		t.Fatalf("status %d body %s", r.status, r.body)
	}
	stored := string(e.detail("app01").LastReport)
	if strings.Contains(stored, "future_field") || strings.Contains(stored, "codename") {
		t.Fatalf("unknown keys were stored: %s", stored)
	}
}

func TestReportBoundToTokenHost(t *testing.T) {
	e := newEnv(t)
	tokA := e.host("a")
	e.host("b")
	post := func(ts string) {
		b := report(t, func(m map[string]any) { m["host"] = "b"; m["ts"] = ts })
		if r := e.do("POST", "/v1/report", tokA, b); r.status != 202 {
			t.Fatalf("status %d", r.status)
		}
	}
	post("2026-11-12T10:00:00Z")
	if e.detail("a").LastReport == nil || e.detail("a").ReportedName != "b" {
		t.Fatal("the report must be stored under the token's host")
	}
	if d := e.detail("b"); d.LastReport != nil || d.ReportCount != 0 || d.LastSeen != nil {
		t.Fatalf("host b was touched: %+v", d)
	}
	post("2026-11-12T10:05:00Z")
	if n := countMsg(e, "differs from the registered host"); n != 1 {
		t.Fatalf("%d mismatch warnings, want exactly 1", n)
	}
	for _, m := range logLines(e) {
		if s, _ := m["msg"].(string); strings.Contains(s, "differs") && (m["registered"] != "a" || m["reported"] != "b") {
			t.Fatalf("warning lacks both names: %v", m)
		}
	}
}

func TestClockSkewWarnedOncePerChangeButAccepted(t *testing.T) {
	e := newEnv(t)
	tok := e.host("app01")
	post := func(ts time.Time) {
		b := report(t, func(m map[string]any) { m["ts"] = ts.Format(time.RFC3339) })
		if r := e.do("POST", "/v1/report", tok, b); r.status != 202 {
			t.Fatalf("status %d", r.status)
		}
	}
	post(now.Add(time.Hour))
	post(now.Add(time.Hour + time.Minute))
	if n := countMsg(e, "clock is ahead"); n != 1 {
		t.Fatalf("%d skew warnings, want 1", n)
	}
	post(now)
	post(now.Add(2 * time.Hour))
	if n := countMsg(e, "clock is ahead"); n != 2 {
		t.Fatalf("%d skew warnings after recovery and a new skew, want 2", n)
	}
	if n := e.detail("app01").ReportCount; n != 4 {
		t.Fatalf("%d reports stored, want all 4 (skew never rejects)", n)
	}
}

func TestInvalidPayload400(t *testing.T) {
	e := newEnv(t)
	tok := e.host("app01")
	manyTags := make([]string, 33)
	for i := range manyTags {
		manyTags[i] = "t" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	cases := map[string][]byte{
		"not json":         []byte("hello"),
		"empty body":       nil,
		"array":            []byte("[]"),
		"trailing garbage": append(golden(t), []byte(" xyz")...),
		"two documents":    append(golden(t), golden(t)...),
		"schema 0":         report(t, func(m map[string]any) { m["schema"] = 0 }),
		"schema 2":         report(t, func(m map[string]any) { m["schema"] = 2 }),
		"missing ts":       report(t, func(m map[string]any) { delete(m, "ts") }),
		"bad ts":           report(t, func(m map[string]any) { m["ts"] = "yesterday" }),
		"33 tags":          report(t, func(m map[string]any) { m["tags"] = manyTags }),
		"empty tag":        report(t, func(m map[string]any) { m["tags"] = []string{""} }),
		"control in tag":   report(t, func(m map[string]any) { m["tags"] = []string{"a\nb"} }),
		"long tag":         report(t, func(m map[string]any) { m["tags"] = []string{strings.Repeat("x", 65)} }),
		"wrong type":       report(t, func(m map[string]any) { m["tags"] = "web" }),
	}
	for name, body := range cases {
		r := e.do("POST", "/v1/report", tok, body)
		var m map[string]string
		if r.status != 400 || json.Unmarshal([]byte(r.body), &m) != nil || m["error"] == "" {
			t.Errorf("%s: status %d body %q, want 400 with an error key", name, r.status, r.body)
		}
		if strings.Contains(r.body, "proto.") {
			t.Errorf("%s: Go type names leak into the response: %s", name, r.body)
		}
	}
	if n := e.detail("app01").ReportCount; n != 0 {
		t.Fatalf("%d reports stored from invalid payloads", n)
	}
	// 32 tags is the limit and must be accepted; duplicates are collapsed.
	ok := report(t, func(m map[string]any) { m["tags"] = manyTags[:32] })
	if r := e.do("POST", "/v1/report", tok, ok); r.status != 202 {
		t.Fatalf("32 tags: %d %s", r.status, r.body)
	}
	dup := report(t, func(m map[string]any) { m["tags"] = []string{"a", "a", "b"}; m["ts"] = "2026-11-12T11:00:00Z" })
	if r := e.do("POST", "/v1/report", tok, dup); r.status != 202 {
		t.Fatalf("duplicate tags: %d %s", r.status, r.body)
	}
	if tags := e.detail("app01").Tags; strings.Join(tags, ",") != "a,b" {
		t.Fatalf("tags %v", tags)
	}
}

func TestBodyLimitAndAuthOrder(t *testing.T) {
	e := newEnv(t)
	tok := e.host("app01")
	pad := func(n int) []byte {
		return []byte(`{"schema":1,"pad":"` + strings.Repeat("x", n))
	}
	// Authenticated and just over 1 MiB: 413.
	if r := e.do("POST", "/v1/report", tok, pad(1<<20)); r.status != 413 {
		t.Fatalf("1 MiB+: status %d", r.status)
	}
	// Unauthenticated 2 MiB: 401, not 413. Auth runs before the body is read,
	// so an unauthenticated client cannot make the server parse a megabyte.
	if r := e.do("POST", "/v1/report", "", pad(2<<20)); r.status != 401 {
		t.Fatalf("unauthenticated 2 MiB: status %d, want 401", r.status)
	}
	if r := e.do("POST", "/v1/event", tok, pad(64<<10)); r.status != 413 {
		t.Fatalf("event 64 KiB+: status %d", r.status)
	}
	// Exactly at the limit is not 413 (it is invalid JSON here: 400).
	if r := e.do("POST", "/v1/report", tok, append(pad(1<<20-30), []byte(`"}`)...)); r.status != 400 {
		t.Fatalf("under the limit: status %d", r.status)
	}
}

func TestWrongMethodAndUnknownPath(t *testing.T) {
	e := newEnv(t)
	tok := e.host("app01")
	if r := e.do("GET", "/v1/report", tok, nil); r.status != 405 {
		t.Fatalf("GET /v1/report: %d", r.status)
	}
	if r := e.do("POST", "/v1/reports", tok, golden(t)); r.status != 404 {
		t.Fatalf("POST /v1/reports: %d", r.status)
	}
}

func TestEventStoredAndIdempotent(t *testing.T) {
	e := newEnv(t)
	tok := e.host("app01")
	for i := 0; i < 2; i++ {
		if r := e.do("POST", "/v1/event", tok, event(t, nil)); r.status != 202 || strings.TrimSpace(r.body) != "{}" {
			t.Fatalf("attempt %d: %d %s", i, r.status, r.body)
		}
	}
	d := e.detail("app01")
	if d.EventCount != 1 {
		t.Fatalf("%d events, want 1 (a retry is stored once)", d.EventCount)
	}
	// An event is not a report: it must not move last_seen (spec 9 STALE is about reports).
	if d.LastSeen != nil {
		t.Fatalf("an event moved last_seen to %v", d.LastSeen)
	}
	if r := e.do("POST", "/v1/event", tok, event(t, func(m map[string]any) { m["path"] = "/other" })); r.status != 202 {
		t.Fatalf("second path: %d", r.status)
	}
	if n := e.detail("app01").EventCount; n != 2 {
		t.Fatalf("%d events, want 2", n)
	}
}

func TestEventValidation(t *testing.T) {
	e := newEnv(t)
	tok := e.host("app01")
	cases := map[string][]byte{
		"empty path":     event(t, func(m map[string]any) { m["path"] = "" }),
		"long path":      event(t, func(m map[string]any) { m["path"] = strings.Repeat("p", 4097) }),
		"NUL in path":    event(t, func(m map[string]any) { m["path"] = "/a\u0000b" }),
		"empty sig":      event(t, func(m map[string]any) { m["signature"] = "" }),
		"long sig":       event(t, func(m map[string]any) { m["signature"] = strings.Repeat("s", 257) }),
		"empty source":   event(t, func(m map[string]any) { m["source"] = "" }),
		"long source":    event(t, func(m map[string]any) { m["source"] = strings.Repeat("s", 33) }),
		"schema 2":       event(t, func(m map[string]any) { m["schema"] = 2 }),
		"missing ts":     event(t, func(m map[string]any) { delete(m, "ts") }),
		"not an object":  []byte(`"x"`),
		"trailing bytes": append(event(t, nil), '}'),
	}
	for name, body := range cases {
		if r := e.do("POST", "/v1/event", tok, body); r.status != 400 {
			t.Errorf("%s: status %d body %s", name, r.status, r.body)
		}
	}
	if n := e.detail("app01").EventCount; n != 0 {
		t.Fatalf("%d events stored from invalid input", n)
	}
	max := event(t, func(m map[string]any) {
		m["path"] = strings.Repeat("p", 4096)
		m["signature"] = strings.Repeat("s", 256)
		m["source"] = strings.Repeat("c", 32)
	})
	if r := e.do("POST", "/v1/event", tok, max); r.status != 202 {
		t.Fatalf("limits are inclusive: %d %s", r.status, r.body)
	}
}

// A database failure is a 503 on both authenticated routes and healthz, never
// a 401: an agent must not read an outage as a revoked token.
func TestStoreDownGives503(t *testing.T) {
	e := newEnv(t)
	tok := e.host("app01")
	if r := e.do("GET", "/healthz", "", nil); r.status != 200 || !strings.Contains(r.body, `"ok"`) {
		t.Fatalf("healthz while up: %d %s", r.status, r.body)
	}
	e.st.Close()
	for _, c := range []struct{ method, path string }{{"POST", "/v1/report"}, {"POST", "/v1/event"}} {
		r := e.do(c.method, c.path, tok, golden(t))
		if r.status != 503 {
			t.Errorf("%s: status %d, want 503", c.path, r.status)
		}
		if r.header.Get("WWW-Authenticate") != "" {
			t.Errorf("%s: a 503 must not look like an auth challenge", c.path)
		}
	}
	if r := e.do("GET", "/healthz", "", nil); r.status != 503 || !strings.Contains(r.body, "unavailable") {
		t.Fatalf("healthz while down: %d %s", r.status, r.body)
	}
	for _, s := range []string{"sql:", "database is closed"} {
		if r := e.do("POST", "/v1/report", tok, golden(t)); strings.Contains(r.body, s) {
			t.Fatalf("internal error text leaks into the response: %s", r.body)
		}
	}
}

// The expected routes are written out by hand, compared with server.Routes()
// exactly and probed against NewHandler: a route registered outside this list, or with the wrong auth
// class, fails here.
func TestRouteTable(t *testing.T) {
	// The console routes (classes public, user, admin) are exercised in depth by
	// internal/web TestUIRouteTable; here they are pinned in the table and probed
	// without any credential, so a route moved to a weaker class fails in two places.
	expected := []server.Route{
		{Method: "POST", Path: "/v1/report", Auth: server.AuthAgent},
		{Method: "POST", Path: "/v1/event", Auth: server.AuthAgent},
		{Method: "GET", Path: "/healthz", Auth: server.AuthNone},
		{Method: "GET", Path: "/metrics", Auth: server.AuthMetrics},
		{Method: "GET", Path: "/static/{file}", Auth: server.AuthPublic},
		{Method: "GET", Path: "/login", Auth: server.AuthPublic},
		{Method: "POST", Path: "/login", Auth: server.AuthPublic},
		{Method: "GET", Path: "/login/totp", Auth: server.AuthPublic},
		{Method: "POST", Path: "/login/totp", Auth: server.AuthPublic},
		{Method: "POST", Path: "/logout", Auth: server.AuthUser},
		{Method: "GET", Path: "/{$}", Auth: server.AuthUser},
		{Method: "GET", Path: "/fleet/rows", Auth: server.AuthUser},
		{Method: "GET", Path: "/hosts/{name}", Auth: server.AuthUser},
		{Method: "GET", Path: "/events", Auth: server.AuthUser},
		{Method: "POST", Path: "/events/{id}/ack", Auth: server.AuthAdmin},
		{Method: "POST", Path: "/events/ack", Auth: server.AuthAdmin},
		{Method: "GET", Path: "/admin/hosts", Auth: server.AuthAdmin},
		{Method: "POST", Path: "/admin/hosts", Auth: server.AuthAdmin},
		{Method: "POST", Path: "/admin/hosts/{name}/rotate-token", Auth: server.AuthAdmin},
		{Method: "POST", Path: "/admin/hosts/{name}/revoke-token", Auth: server.AuthAdmin},
		{Method: "POST", Path: "/admin/hosts/{name}/delete", Auth: server.AuthAdmin},
		{Method: "GET", Path: "/account", Auth: server.AuthUser},
		{Method: "POST", Path: "/account/password", Auth: server.AuthUser},
		{Method: "GET", Path: "/account/totp", Auth: server.AuthUser},
		{Method: "POST", Path: "/account/totp/setup", Auth: server.AuthUser},
		{Method: "POST", Path: "/account/totp/confirm", Auth: server.AuthUser},
		{Method: "POST", Path: "/account/totp/recovery-codes", Auth: server.AuthUser},
		{Method: "POST", Path: "/account/totp/disable", Auth: server.AuthUser},
		{Method: "GET", Path: "/admin/alerts", Auth: server.AuthAdmin},
		{Method: "GET", Path: "/admin/alerts/new", Auth: server.AuthAdmin},
		{Method: "POST", Path: "/admin/alerts", Auth: server.AuthAdmin},
		{Method: "GET", Path: "/admin/alerts/{name}", Auth: server.AuthAdmin},
		{Method: "POST", Path: "/admin/alerts/{name}", Auth: server.AuthAdmin},
		{Method: "POST", Path: "/admin/alerts/{name}/test", Auth: server.AuthAdmin},
		{Method: "POST", Path: "/admin/alerts/{name}/rotate-secret", Auth: server.AuthAdmin},
		{Method: "POST", Path: "/admin/alerts/{name}/delete", Auth: server.AuthAdmin},
	}
	// The declared table must match the hardcoded list exactly, so a route that
	// is added to server.Routes() (even an open one the probe below would not
	// find) fails here.
	got := server.Routes()
	if len(got) != len(expected) {
		t.Fatalf("server.Routes() = %v, want exactly %v", got, expected)
	}
	for i, rt := range expected {
		if got[i] != rt {
			t.Fatalf("server.Routes()[%d] = %v, want %v", i, got[i], rt)
		}
	}
	e := newEnv(t)
	concrete := strings.NewReplacer("{$}", "", "{file}", "app.css", "{name}", "web01", "{id}", "1")
	for _, rt := range expected {
		path := concrete.Replace(rt.Path)
		var r resp
		switch rt.Auth {
		case server.AuthAgent:
			r = e.do(rt.Method, path, "", golden(t))
			if r.status != 401 {
				t.Errorf("%s %s: status %d without a token, want 401", rt.Method, rt.Path, r.status)
			}
			// A valid token must get through the same route.
			tok := e.host("probe" + strings.NewReplacer("/", "-", ".", "-").Replace(rt.Path))
			body := golden(t)
			if strings.HasSuffix(rt.Path, "/event") {
				body = event(t, nil)
			}
			if r := e.do(rt.Method, path, tok, body); r.status != 202 {
				t.Errorf("%s %s: status %d with a valid token, want 202", rt.Method, rt.Path, r.status)
			}
		case server.AuthMetrics:
			// Off by default: the route exists and answers 404 (TestMetricsThroughRouter in
			// internal/server covers the token).
			if r = e.do(rt.Method, path, "", nil); r.status != 404 {
				t.Errorf("%s %s: status %d with metrics off, want 404", rt.Method, rt.Path, r.status)
			}
		case server.AuthNone, server.AuthPublic:
			want := 200
			if rt.Path == "/login/totp" {
				want = 303 // public, but needs a login challenge: without one it redirects to /login
			}
			if r = e.do(rt.Method, path, "", nil); r.status != want {
				t.Errorf("%s %s: status %d, want %d", rt.Method, rt.Path, r.status, want)
			}
		case server.AuthUser, server.AuthAdmin:
			want := 401
			if rt.Method == "GET" {
				want = 303
			}
			if r = e.do(rt.Method, path, "", nil); r.status != want {
				t.Errorf("%s %s: status %d without a session, want %d", rt.Method, rt.Path, r.status, want)
			}
		}
	}
	// Nothing else is mounted: every other method on a listed path, and
	// plausible future paths, must not answer with anything but 404/405 (a
	// 401 would mean an unlisted authenticated route exists, a 2xx an open one).
	listed := map[string]bool{}
	for _, rt := range expected {
		listed[rt.Method+" "+concrete.Replace(rt.Path)] = true
	}
	// "new" is a reserved alert target name because GET /admin/alerts/new is a
	// literal route next to the {name} wildcard; every other method on that path
	// reaches the wildcard routes (and gets the admin class like them, then a 404
	// for the target "new" that cannot exist).
	for _, rt := range expected {
		if strings.HasPrefix(rt.Path, "/admin/alerts/{name}") && !strings.Contains(strings.TrimPrefix(rt.Path, "/admin/alerts/{name}"), "/") {
			listed[rt.Method+" /admin/alerts/new"] = true
		}
	}
	paths := []string{"/", "/metrics", "/v1", "/v1/", "/v1/tasks", "/v1/hosts", "/v1/events", "/v1/reports", "/api/v1/report", "/admin", "/login", "/fleet", "/hosts", "/users", "/static/"}
	for _, rt := range expected {
		if !strings.Contains(rt.Path, "{") || rt.Path == "/{$}" {
			paths = append(paths, concrete.Replace(rt.Path))
		}
	}
	for _, p := range paths {
		for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			if listed[m+" "+p] {
				continue
			}
			if r := e.do(m, p, "", nil); r.status != 404 && r.status != 405 {
				t.Errorf("%s %s: status %d, want 404 or 405 (an unlisted route is mounted)", m, p, r.status)
			}
		}
	}
}

func TestRequestLogFields(t *testing.T) {
	// Info is the default level of `serve`: decision 10 needs the client IP of accepted requests there.
	e := newEnvLevel(t, slog.LevelInfo)
	tok := e.host("app01")
	e.do("POST", "/v1/report", tok, golden(t))
	e.do("POST", "/v1/report", "", golden(t))
	var okLine, badLine map[string]any
	for _, m := range logLines(e) {
		if m["msg"] != "request" {
			continue
		}
		if m["status"] == float64(202) {
			okLine = m
		}
		if m["status"] == float64(401) {
			badLine = m
		}
	}
	if okLine == nil || badLine == nil {
		t.Fatalf("missing request lines:\n%s", e.logs.String())
	}
	if okLine["level"] != "INFO" || badLine["level"] != "WARN" {
		t.Fatalf("levels: %v / %v", okLine["level"], badLine["level"])
	}
	// Decision 10: the client IP is always logged, on success too.
	for _, m := range []map[string]any{okLine, badLine} {
		if m["client_ip"] != "127.0.0.1" || m["method"] != "POST" || m["path"] != "/v1/report" {
			t.Errorf("fields: %v", m)
		}
	}
	if okLine["host"] != "app01" || badLine["host"] != "" {
		t.Errorf("host field: %v / %v", okLine["host"], badLine["host"])
	}
	if strings.Contains(e.logs.String(), tok) {
		t.Fatal("token in log")
	}
}

// The token and its hash must not reach the database in the clear: only the
// SHA-256 is stored (read the file, and the WAL, after a clean close).
func TestTokenNotInDatabaseBytes(t *testing.T) {
	e := newEnv(t)
	tok := e.host("app01")
	e.do("POST", "/v1/report", tok, golden(t))
	e.srv.Close()
	if err := e.st.Close(); err != nil {
		t.Fatal(err)
	}
	var all []byte
	for _, suffix := range []string{"", "-wal"} {
		b, err := os.ReadFile(e.dbPath + suffix)
		if err == nil {
			all = append(all, b...)
		}
	}
	if len(all) == 0 {
		t.Fatal("read no database bytes")
	}
	if bytes.Contains(all, []byte(tok)) || bytes.Contains(all, []byte(tok[4:])) {
		t.Fatal("the plain token is in the database file")
	}
	if !bytes.Contains(all, agentauth.Hash(tok)) {
		t.Fatal("the token hash is not in the database file (the test would be vacuous)")
	}
}

// Client IP for the logs (decision 12): the peer here is always 127.0.0.1
// (httptest on loopback); X-Forwarded-For is believed only when that peer is a
// trusted proxy, and then only its rightmost untrusted entry.
func TestClientIPInRequestLog(t *testing.T) {
	pfx := func(s ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, e := range s {
			out = append(out, netip.MustParsePrefix(e))
		}
		return out
	}
	cases := []struct {
		name    string
		trusted []netip.Prefix
		xff     []string // one header line each
		want    string
	}{
		{"untrusted peer, forged XFF ignored", nil, []string{"6.6.6.6"}, "127.0.0.1"},
		{"peer not in a non-empty list, forged XFF ignored", pfx("10.0.0.0/8"), []string{"6.6.6.6"}, "127.0.0.1"},
		{"trusted peer, real client", pfx("127.0.0.0/8"), []string{"203.0.113.7"}, "203.0.113.7"},
		{"trusted peer, no XFF", pfx("127.0.0.1/32"), nil, "127.0.0.1"},
		{"client-prepended fake entry is not chosen", pfx("127.0.0.0/8"), []string{"6.6.6.6, 203.0.113.7"}, "203.0.113.7"},
		{"trusted proxy chain", pfx("127.0.0.0/8", "10.0.0.0/8"), []string{"203.0.113.7, 10.0.0.9"}, "203.0.113.7"},
		{"fake entry before a proxy chain", pfx("127.0.0.0/8", "10.0.0.0/8"), []string{"6.6.6.6, 203.0.113.7, 10.0.0.9"}, "203.0.113.7"},
		{"multiple XFF header lines are combined", pfx("127.0.0.0/8", "10.0.0.0/8"), []string{"6.6.6.6", "203.0.113.7, 10.0.0.9"}, "203.0.113.7"},
		{"IPv6 client", pfx("127.0.0.0/8"), []string{"2001:db8::1"}, "2001:db8::1"},
		{"IPv6 zone is not logged", pfx("127.0.0.0/8"), []string{"fe80::1%evil-text"}, "127.0.0.1"},
		{"garbage falls back to the peer", pfx("127.0.0.0/8"), []string{"garbage"}, "127.0.0.1"},
		{"garbage at the rightmost untrusted position", pfx("127.0.0.0/8"), []string{"203.0.113.7, garbage"}, "127.0.0.1"},
		{"only trusted entries fall back to the peer", pfx("127.0.0.0/8", "10.0.0.0/8"), []string{"10.0.0.9"}, "127.0.0.1"},
		{"empty header", pfx("127.0.0.0/8"), []string{""}, "127.0.0.1"},
	}
	for _, c := range cases {
		e := newEnvOpts(t, slog.LevelDebug, c.trusted)
		req, _ := http.NewRequest("POST", e.srv.URL+"/v1/report", nil)
		for _, v := range c.xff {
			req.Header.Add("X-Forwarded-For", v)
		}
		resp, err := e.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		var got any
		for _, m := range logLines(e) {
			if m["msg"] == "request" {
				got = m["client_ip"]
			}
		}
		if got != c.want {
			t.Errorf("%s: client_ip = %v, want %s", c.name, got, c.want)
		}
	}
}

func TestEventIDValidation(t *testing.T) {
	e := newEnv(t)
	tok := e.host("app01")
	for name, id := range map[string]any{
		"short": "abc", "uppercase": strings.Repeat("A", 32), "non hex": strings.Repeat("g", 32), "33 chars": strings.Repeat("a", 33), "number": 5,
	} {
		if r := e.do("POST", "/v1/event", tok, event(t, func(m map[string]any) { m["id"] = id })); r.status != 400 {
			t.Errorf("%s: status %d", name, r.status)
		}
	}
	for name, id := range map[string]any{"null": nil, "32 hex": strings.Repeat("a", 32)} {
		if r := e.do("POST", "/v1/event", tok, event(t, func(m map[string]any) { m["id"] = id })); r.status != 202 {
			t.Errorf("%s: status %d %s", name, r.status, r.body)
		}
	}
}

// With ids, two different detections in one second are both counted (x2) and a
// retry of one is not; through the real router.
func TestEventIDsThroughRouter(t *testing.T) {
	e := newEnv(t)
	tok := e.host("app01")
	post := func(id string) {
		t.Helper()
		if r := e.do("POST", "/v1/event", tok, event(t, func(m map[string]any) { m["id"] = id })); r.status != 202 {
			t.Fatalf("%d %s", r.status, r.body)
		}
	}
	post(strings.Repeat("a", 32))
	post(strings.Repeat("b", 32))
	post(strings.Repeat("b", 32)) // retry
	rows, err := e.st.ListEvents(context.Background(), store.EventFilter{Ack: store.AckAll})
	if err != nil || len(rows) != 1 || rows[0].Occurrences != 2 {
		t.Fatalf("%+v %v: want one row with occurrences 2", rows, err)
	}
}

// AfterEvent reports whether the event is new, so the dispatcher is woken for a
// new detection only. Without the wiring a detection would wait for the 5 s tick.
func TestAfterEventIsCalledWithStored(t *testing.T) {
	var mu sync.Mutex
	var calls []bool
	e := newEnvDeps(t, slog.LevelDebug, nil, func(d *server.Deps) {
		d.AfterEvent = func(_ context.Context, stored bool) { mu.Lock(); calls = append(calls, stored); mu.Unlock() }
	})
	tok := e.host("app01")
	id := strings.Repeat("c", 32)
	for i := 0; i < 2; i++ {
		e.do("POST", "/v1/event", tok, event(t, func(m map[string]any) { m["id"] = id }))
	}
	e.do("POST", "/v1/event", tok, event(t, func(m map[string]any) { m["signature"] = "" })) // invalid: no call
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 || !calls[0] || calls[1] {
		t.Fatalf("AfterEvent calls %v, want [true false]", calls)
	}
}

// A replayed report is stored but not evaluated; a live one is.
func TestReplayedReportSkipsEvaluation(t *testing.T) {
	var mu sync.Mutex
	evaluated := 0
	e := newEnvDeps(t, slog.LevelDebug, nil, func(d *server.Deps) {
		d.AfterReport = func(context.Context, int64) error { mu.Lock(); evaluated++; mu.Unlock(); return nil }
	})
	tok := e.host("app01")
	if r := e.do("POST", "/v1/report", tok, report(t, nil)); r.status != 202 {
		t.Fatal(r.status)
	}
	if r := e.do("POST", "/v1/report", tok, report(t, func(m map[string]any) { m["replay"] = true; m["ts"] = "2026-11-12T09:00:00Z" })); r.status != 202 {
		t.Fatal(r.status)
	}
	mu.Lock()
	defer mu.Unlock()
	if evaluated != 1 {
		t.Fatalf("%d evaluations, want 1 (the live report only)", evaluated)
	}
	if d := e.detail("app01"); d.ReportCount != 2 {
		t.Fatalf("%d reports stored, want 2", d.ReportCount)
	}
}

// The path is personal data: no ingest error text, log line or audit row may
// contain it, whatever made the request invalid.
func TestIngestErrorsNeverEchoPath(t *testing.T) {
	e := newEnv(t)
	tok := e.host("app01")
	const marker = "/home/MARKER-PATH"
	bodies := map[string][]byte{
		"path too long":   event(t, func(m map[string]any) { m["path"] = marker + strings.Repeat("p", 4100) }),
		"NUL in path":     event(t, func(m map[string]any) { m["path"] = marker + "\u0000" }),
		"bad schema":      event(t, func(m map[string]any) { m["path"] = marker; m["schema"] = 2 }),
		"bad id":          event(t, func(m map[string]any) { m["path"] = marker; m["id"] = "nope" }),
		"bad signature":   event(t, func(m map[string]any) { m["path"] = marker; m["signature"] = "" }),
		"bad ts":          event(t, func(m map[string]any) { m["path"] = marker; m["ts"] = "yesterday" }),
		"path as number":  event(t, func(m map[string]any) { m["path"] = 5; m["signature"] = marker }),
		"trailing":        append(event(t, func(m map[string]any) { m["path"] = marker }), []byte(" "+marker)...),
		"oversized (413)": event(t, func(m map[string]any) { m["path"] = marker; m["pad"] = strings.Repeat("x", 70000) }),
	}
	for name, body := range bodies {
		r := e.do("POST", "/v1/event", tok, body)
		if r.status != 400 && r.status != 413 {
			t.Errorf("%s: status %d", name, r.status)
		}
		if strings.Contains(r.body, "MARKER") {
			t.Errorf("%s: the response echoes the path: %s", name, r.body)
		}
	}
	if strings.Contains(e.logs.String(), "MARKER") {
		t.Fatalf("a log line contains the path:\n%s", e.logs.String())
	}
	rows, _ := e.st.ListEvents(context.Background(), store.EventFilter{Ack: store.AckAll})
	if len(rows) != 0 {
		t.Fatalf("%d events stored from invalid input", len(rows))
	}
}
