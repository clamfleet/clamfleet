// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Router tests of the alert pages and the alert pipeline behind them: every
// request goes through server.NewHandler (an unmounted route or a missing
// middleware turns these red), with real SQLite, an injected clock, a loopback
// webhook receiver and a loopback SMTP fake. The dispatcher is the real one,
// sharing the store and the clock with the console, driven by RunOnce.
package web_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/alert"
	"github.com/clamfleet/clamfleet/internal/secrets"
	"github.com/clamfleet/clamfleet/internal/server"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/testsmtp"
)

// hookRecv is a webhook receiver on loopback that records what it gets.
type hookRecv struct {
	srv    *httptest.Server
	status atomic.Int64
	mu     sync.Mutex
	reqs   []recvReq
}

type recvReq struct {
	path   string
	header http.Header
	body   string
}

func newHookRecv(t *testing.T) *hookRecv {
	t.Helper()
	h := &hookRecv{}
	h.status.Store(204)
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.reqs = append(h.reqs, recvReq{r.URL.Path, r.Header.Clone(), string(b)})
		h.mu.Unlock()
		w.WriteHeader(int(h.status.Load()))
		io.WriteString(w, "SECRET-BODY-MARKER")
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hookRecv) url(path string) string { return h.srv.URL + path }
func (h *hookRecv) count() int             { h.mu.Lock(); defer h.mu.Unlock(); return len(h.reqs) }
func (h *hookRecv) all() []recvReq {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]recvReq(nil), h.reqs...)
}

// payloads decodes the state-change payloads received.
func (h *hookRecv) states() []alert.StateChangePayload {
	var out []alert.StateChangePayload
	for _, r := range h.all() {
		var p alert.StateChangePayload
		if json.Unmarshal([]byte(r.body), &p) == nil && p.Kind == "state_change" {
			out = append(out, p)
		}
	}
	return out
}

func (r recvReq) verify(signingKey string) bool {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(signingKey, "whsec_"))
	if err != nil {
		return false
	}
	ts, _ := strconv.ParseInt(r.header.Get("webhook-timestamp"), 10, 64)
	return alert.VerifySignature(key, r.header.Get("webhook-id"), ts, []byte(r.body), r.header.Get("webhook-signature"))
}

func testKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	k, err := secrets.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := secrets.Parse(strings.NewReader(secrets.EncodeKeyLine(k)))
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

type alertOpts struct {
	keys     *secrets.Keyring
	loopback bool
	smtp     *testsmtp.Server
	cooldown time.Duration
	public   string
}

// alertEnv builds an env whose handler has the alert pages and a real
// dispatcher (the same store and clock), plus a logged-in admin.
func alertEnv(t *testing.T, o alertOpts) (*env, *server.Alerts, *browser, string) {
	t.Helper()
	var al *server.Alerts
	if o.cooldown == 0 {
		o.cooldown = 15 * time.Minute
	}
	e := newReportEnv(t, func(d *server.Deps) {
		cfg := server.DefaultConfig()
		cfg.Alert.Webhook.AllowLoopback = o.loopback
		cfg.Alert.Cooldown = o.cooldown
		cfg.PublicURL = o.public
		if o.smtp != nil {
			host, port, _ := strings.Cut(o.smtp.Addr, ":")
			p, _ := strconv.Atoi(port)
			cfg.SMTP = server.SMTP{Host: host, Port: p, TLS: "none", From: "clamfleet@test.example", Timeout: 5 * time.Second}
		}
		var err error
		if al, err = server.BuildAlerts(cfg, d.Store, o.keys, d.Now, d.Log); err != nil {
			t.Fatal(err)
		}
		d.Alerts, d.Keys = al, o.keys
	})
	b, tok := adminBrowser(t, e)
	return e, al, b, tok
}

func startFakeSMTP(t *testing.T, o testsmtp.Options) *testsmtp.Server {
	t.Helper()
	s, err := testsmtp.Listen("127.0.0.1:0", o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// whsecRE finds a signing key in a page. html/template escapes '+' as &#43;, so the
// match includes the entity characters and the caller unescapes (see keysIn).
var whsecRE = regexp.MustCompile(`whsec_[A-Za-z0-9+/=&#;]+`)

// keysIn returns every signing key shown in a page body, unescaped.
func keysIn(body string) []string {
	var out []string
	for _, k := range whsecRE.FindAllString(body, -1) {
		out = append(out, html.UnescapeString(k))
	}
	return out
}

func createWebhook(t *testing.T, b *browser, tok, name, hookURL string, extra url.Values) (key string, p page) {
	t.Helper()
	form := url.Values{"csrf_token": {tok}, "type": {"webhook"}, "name": {name}, "url": {hookURL}, "min_severity": {"WARN"},
		"state_changes": {"1"}, "detections": {"1"}, "enabled": {"1"}}
	for k, v := range extra {
		form[k] = v
	}
	p = b.post("/admin/alerts", form)
	if p.status != 200 {
		t.Fatalf("create webhook %s: %d\n%s", name, p.status, p.body)
	}
	keys := keysIn(p.body)
	if len(keys) != 1 {
		t.Fatalf("the key page must show exactly one whsec_ key, got %d:\n%s", len(keys), p.body)
	}
	return keys[0], p
}

func createEmail(t *testing.T, b *browser, tok, name, to string) {
	t.Helper()
	p := b.post("/admin/alerts", url.Values{"csrf_token": {tok}, "type": {"email"}, "name": {name}, "to": {to}, "min_severity": {"WARN"},
		"state_changes": {"1"}, "detections": {"1"}, "enabled": {"1"}})
	if p.status != 303 {
		t.Fatalf("create email %s: %d\n%s", name, p.status, p.body)
	}
}

func (e *env) runAlerts(a *server.Alerts) {
	e.t.Helper()
	if err := a.Dispatcher.RunOnce(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

// postEvent sends a detection through /v1/event with the host's token.
func postEvent(t *testing.T, e *env, token, path string, at time.Time) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"schema": 1, "host": "web01", "ts": at.UTC().Format(time.RFC3339), "path": path, "signature": "Eicar-Test", "source": "scan"})
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/event", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func fileBytes(t *testing.T, e *env) string {
	t.Helper()
	var all strings.Builder
	for _, suffix := range []string{"", "-wal"} {
		if b, err := os.ReadFile(e.dbPath + suffix); err == nil {
			all.Write(b)
		}
	}
	return all.String()
}

func auditDetails(t *testing.T, e *env) string {
	t.Helper()
	raw, err := openRaw(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rows, err := raw.Query(`SELECT action || ' ' || actor_kind || ' ' || actor || ' ' || target || ' ' || COALESCE(detail, '') FROM audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out strings.Builder
	for rows.Next() {
		var s string
		rows.Scan(&s)
		out.WriteString(s + "\n")
	}
	return out.String()
}

// Mutation 33 (webhook URL or key in clear) and the secret-once rules: the key
// and the URL path appear in no DB byte, no log line, no audit detail and no
// later page.
func TestAlertTargetCRUDThroughRouter(t *testing.T) {
	rcv := newHookRecv(t)
	e, _, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t), loopback: true, public: "https://cf.example"})
	const marker = "/hook/TOKEN-MARKER"

	if p := b.get("/admin/alerts"); p.status != 200 || !strings.Contains(p.body, `data-testid="alerts-empty"`) || !strings.Contains(p.body, `data-testid="nav-alerts"`) {
		t.Fatalf("empty list: %d\n%s", p.status, p.body)
	}
	// The literal /admin/alerts/new beats the {name} wildcard (A7).
	if p := b.get("/admin/alerts/new?type=webhook"); p.status != 200 || !strings.Contains(p.body, `data-testid="alert-url"`) {
		t.Fatalf("new page: %d", p.status)
	}
	if p := b.get("/admin/alerts/new?type=bogus"); p.status != 400 {
		t.Fatalf("bad type: %d", p.status)
	}

	key, p := createWebhook(t, b, tok, "ops", rcv.url(marker), nil)
	if p.header.Get("Cache-Control") != "no-store" || p.header.Get("Pragma") != "no-cache" || !strings.Contains(p.body, `data-testid="secret-value"`) {
		t.Fatalf("the key page must not be cached: %v", p.header)
	}
	if strings.Contains(p.body, "TOKEN-MARKER") {
		t.Fatal("the key page shows the URL path")
	}

	// Later pages: no key, no URL path; the list shows scheme and host only.
	for _, path := range []string{"/admin/alerts", "/admin/alerts/ops"} {
		pg := b.get(path)
		if pg.status != 200 || strings.Contains(pg.body, "whsec_") || strings.Contains(pg.body, "TOKEN-MARKER") || strings.Contains(pg.body, key[6:]) {
			t.Fatalf("%s leaks the key or the URL (status %d)", path, pg.status)
		}
	}
	list := b.get("/admin/alerts")
	if !strings.Contains(list.body, `data-testid="alert-row-ops"`) || !strings.Contains(list.body, "http://127.0.0.1:") || !strings.Contains(list.body, `data-testid="alert-unencrypted-ops"`) {
		t.Fatalf("the list must show the destination and the unencrypted badge:\n%s", list.body)
	}

	// Edit (blank URL keeps it), rotate, delete with typed confirmation.
	up := b.post("/admin/alerts/ops", url.Values{"csrf_token": {tok}, "min_severity": {"CRIT"}, "tags": {"prod, web"}, "state_changes": {"1"}, "detections": {"1"}, "enabled": {"1"}})
	if up.status != 303 || !strings.HasPrefix(up.header.Get("Location"), "/admin/alerts/ops?") {
		t.Fatalf("update: %d %q\n%s", up.status, up.header.Get("Location"), up.body)
	}
	edit := b.get(up.header.Get("Location"))
	if !strings.Contains(edit.body, "Alert target ops saved.") || !strings.Contains(edit.body, `value="prod, web"`) || !strings.Contains(edit.body, `<option value="CRIT" selected>`) {
		t.Fatalf("after update:\n%s", edit.body)
	}
	rot := b.post("/admin/alerts/ops/rotate-secret", url.Values{"csrf_token": {tok}})
	newKeys := keysIn(rot.body)
	if rot.status != 200 || len(newKeys) != 1 || newKeys[0] == key || rot.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("rotate: %d %v", rot.status, newKeys)
	}
	if bad := b.post("/admin/alerts/ops/delete", url.Values{"csrf_token": {tok}, "confirm": {"nope"}}); bad.status != 400 || e.count(`SELECT count(*) FROM alert_targets`) != 1 {
		t.Fatalf("delete with a wrong confirmation: %d", bad.status)
	}
	if d := b.post("/admin/alerts/ops/delete", url.Values{"csrf_token": {tok}, "confirm": {"OPS"}}); d.status != 303 || e.count(`SELECT count(*) FROM alert_targets`) != 0 {
		t.Fatalf("delete: %d", d.status)
	}
	if p := b.get("/admin/alerts/ops"); p.status != 404 {
		t.Fatalf("a deleted target: %d", p.status)
	}

	// Audit: every change, by the signed-in user.
	for _, a := range []string{"alert_target.add", "alert_target.update", "alert_target.secret.rotate", "alert_target.delete"} {
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action = ? AND actor_kind = 'user' AND actor = 'adm@example.com' AND target = 'ops' AND target_kind = 'alert_target'`, a); n != 1 {
			t.Errorf("%d audit rows for %s", n, a)
		}
	}
	// Mutation 33: nothing secret anywhere on disk or in the logs.
	disk, logs, audit := fileBytes(t, e), e.logs.String(), auditDetails(t, e)
	for _, secret := range []string{"TOKEN-MARKER", key, key[6:], newKeys[0][6:]} {
		for where, hay := range map[string]string{"database file": disk, "log": logs, "audit log": audit} {
			if strings.Contains(hay, secret) {
				t.Errorf("%q found in the %s", secret, where)
			}
		}
	}
}

func TestAlertTargetValidation(t *testing.T) {
	// Loopback is off here, so the policy refusals are visible.
	e, _, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t)})
	const marker = "TOKEN-MARKER"
	cases := []struct {
		name string
		form url.Values
		want int
	}{
		{"userinfo", url.Values{"type": {"webhook"}, "name": {"a"}, "url": {"https://user:pw@hooks.example/" + marker}}, 400},
		{"ftp", url.Values{"type": {"webhook"}, "name": {"a"}, "url": {"ftp://hooks.example/" + marker}}, 400},
		{"loopback literal", url.Values{"type": {"webhook"}, "name": {"a"}, "url": {"http://127.0.0.1:8080/" + marker}}, 400},
		{"localhost", url.Values{"type": {"webhook"}, "name": {"a"}, "url": {"http://localhost:8080/" + marker}}, 400},
		{"metadata", url.Values{"type": {"webhook"}, "name": {"a"}, "url": {"http://169.254.169.254/latest/" + marker}}, 400},
		{"public plaintext literal", url.Values{"type": {"webhook"}, "name": {"a"}, "url": {"http://203.0.113.5/" + marker}}, 400},
		{"reserved name", url.Values{"type": {"webhook"}, "name": {"new"}, "url": {"https://hooks.example/" + marker}}, 400},
		{"bad name", url.Values{"type": {"webhook"}, "name": {"A B"}, "url": {"https://hooks.example/" + marker}}, 400},
		{"bad severity", url.Values{"type": {"webhook"}, "name": {"a"}, "url": {"https://hooks.example/" + marker}, "min_severity": {"OK"}}, 400},
		{"invalid recipient", url.Values{"type": {"email"}, "name": {"a"}, "to": {"not-an-address"}}, 400},
		{"email with smtp.host empty", url.Values{"type": {"email"}, "name": {"a"}, "to": {"a@x.example"}}, 400},
		{"unknown type", url.Values{"type": {"syslog"}, "name": {"a"}}, 400},
	}
	for _, c := range cases {
		form := url.Values{"csrf_token": {tok}, "min_severity": {"WARN"}, "state_changes": {"1"}, "enabled": {"1"}}
		for k, v := range c.form {
			form[k] = v
		}
		p := b.post("/admin/alerts", form)
		if p.status != c.want {
			t.Errorf("%s: %d, want %d", c.name, p.status, c.want)
		}
		if strings.Contains(p.body, marker) {
			t.Errorf("%s: the error page contains the URL", c.name)
		}
	}
	if n := e.count(`SELECT count(*) FROM alert_targets`); n != 0 {
		t.Fatalf("%d targets stored by refused requests", n)
	}
	// More than 20 recipients.
	var many []string
	for i := 0; i < 21; i++ {
		many = append(many, "u"+strconv.Itoa(i)+"@x.example")
	}
	srv := startFakeSMTP(t, testsmtp.Options{})
	_, _, b2, tok2 := alertEnv(t, alertOpts{keys: testKeyring(t), smtp: srv})
	if p := b2.post("/admin/alerts", url.Values{"csrf_token": {tok2}, "type": {"email"}, "name": {"m"}, "to": {strings.Join(many, ",")}, "min_severity": {"WARN"}}); p.status != 400 {
		t.Fatalf("21 recipients: %d", p.status)
	}
	// A webhook target without a key file: a 503 page that says what to do.
	e3, _, b3, tok3 := alertEnv(t, alertOpts{keys: nil})
	p := b3.post("/admin/alerts", url.Values{"csrf_token": {tok3}, "type": {"webhook"}, "name": {"a"}, "url": {"https://hooks.example/x"}, "min_severity": {"WARN"}})
	if p.status != 503 || !strings.Contains(p.body, "key generate") || e3.count(`SELECT count(*) FROM alert_targets`) != 0 {
		t.Fatalf("no key file: %d", p.status)
	}
	// A duplicate name is a conflict.
	_, _, b4, tok4 := alertEnv(t, alertOpts{keys: testKeyring(t)})
	form := url.Values{"csrf_token": {tok4}, "type": {"webhook"}, "name": {"dup"}, "url": {"https://hooks.example/x"}, "min_severity": {"WARN"}}
	if p := b4.post("/admin/alerts", form); p.status != 200 {
		t.Fatalf("first: %d", p.status)
	}
	if p := b4.post("/admin/alerts", form); p.status != 409 {
		t.Fatalf("duplicate: %d", p.status)
	}
}

// Review finding 12, mutation 34: the update path validates the URL exactly as
// create does, and a refused one leaves the sealed blob byte-identical.
func TestUpdateURLToBlockedAddressRefused(t *testing.T) {
	rcv := newHookRecv(t)
	e, al, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t), loopback: true})
	createWebhook(t, b, tok, "ops", rcv.url("/hook/ok"), nil)
	blob := func() string {
		raw, _ := openRaw(e.dbPath)
		defer raw.Close()
		var s string
		raw.QueryRow(`SELECT hex(secret) FROM alert_targets WHERE name = 'ops'`).Scan(&s)
		return s
	}
	before := blob()
	for _, bad := range []string{"http://169.254.169.254/latest", "http://100.100.100.200/", "ftp://x.example/", "https://u:p@x.example/"} {
		p := b.post("/admin/alerts/ops", url.Values{"csrf_token": {tok}, "url": {bad}, "min_severity": {"WARN"}, "state_changes": {"1"}, "detections": {"1"}, "enabled": {"1"}})
		if p.status != 400 || !strings.Contains(p.body, "The stored URL was not changed") {
			t.Errorf("update to %s: %d", bad, p.status)
		}
		if blob() != before {
			t.Fatalf("the sealed secret changed after a refused update to %s", bad)
		}
	}
	// The next transition still goes to the old receiver.
	postReport(t, e, registerHost(t, e, "web01"), setClamdDown)
	e.runAlerts(al)
	if len(rcv.states()) != 1 || rcv.all()[0].path != "/hook/ok" {
		t.Fatalf("the old receiver did not get the alert: %v", rcv.all())
	}
	// With loopback off (a second env) an update to http://localhost/ is refused too (mutation 26).
	e2, _, b2, tok2 := alertEnv(t, alertOpts{keys: testKeyring(t)})
	createWebhook(t, b2, tok2, "ops", "https://hooks.example/ok", nil)
	blob2 := func() string {
		raw, _ := openRaw(e2.dbPath)
		defer raw.Close()
		var s string
		raw.QueryRow(`SELECT hex(secret) FROM alert_targets WHERE name = 'ops'`).Scan(&s)
		return s
	}
	before2 := blob2()
	p := b2.post("/admin/alerts/ops", url.Values{"csrf_token": {tok2}, "url": {"http://localhost/"}, "min_severity": {"WARN"}})
	if p.status != 400 || blob2() != before2 {
		t.Fatalf("update to http://localhost/: %d", p.status)
	}
	// A good new URL replaces it and keeps the signing key (the receiver keeps verifying).
	rcv2 := newHookRecv(t)
	key, _ := createWebhook(t, b, tok, "ops2", rcv.url("/hook/two"), nil)
	if p := b.post("/admin/alerts/ops2", url.Values{"csrf_token": {tok}, "url": {rcv2.url("/hook/new")}, "min_severity": {"WARN"}, "state_changes": {"1"}, "detections": {"1"}, "enabled": {"1"}}); p.status != 303 {
		t.Fatalf("good update: %d\n%s", p.status, p.body)
	}
	e.advance(20 * time.Minute)
	postReport(t, e, registerHost(t, e, "web02"), setClamdDown)
	e.runAlerts(al)
	got := rcv2.all()
	if len(got) != 1 || got[0].path != "/hook/new" || !got[0].verify(key) {
		t.Fatalf("the new receiver must get a request signed with the unchanged key: %+v", got)
	}
}

// Review finding 5, mutation 20: switching a kind off cancels what is pending.
func TestSwitchOffThroughRouter(t *testing.T) {
	rcv := newHookRecv(t)
	rcv.status.Store(503) // the first delivery stays pending (retrying)
	e, al, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t), loopback: true})
	createWebhook(t, b, tok, "ops", rcv.url("/h"), nil)
	postReport(t, e, registerHost(t, e, "web01"), setClamdDown)
	e.runAlerts(al)
	if rcv.count() != 1 || e.count(`SELECT count(*) FROM alert_deliveries WHERE status = 'pending'`) != 1 {
		t.Fatalf("setup: hits %d", rcv.count())
	}
	p := b.post("/admin/alerts/ops", url.Values{"csrf_token": {tok}, "min_severity": {"WARN"}, "detections": {"1"}, "enabled": {"1"}}) // state_changes unticked
	if p.status != 303 {
		t.Fatalf("%d\n%s", p.status, p.body)
	}
	if pg := b.get(p.header.Get("Location")); !strings.Contains(pg.body, "1 pending alert cancelled") {
		t.Fatalf("the page must say what was cancelled:\n%s", pg.body)
	}
	e.advance(10 * time.Minute)
	e.runAlerts(al)
	if rcv.count() != 1 {
		t.Fatalf("a cancelled alert was sent: %d requests", rcv.count())
	}
	if e.count(`SELECT count(*) FROM alert_deliveries WHERE status = 'cancelled'`) != 1 {
		t.Fatal("not cancelled")
	}
	if e.count(`SELECT count(*) FROM audit_log WHERE action = 'alert_target.update' AND detail LIKE '%"cancelled":"1"%'`) != 1 {
		t.Fatal("the audit row must carry the count")
	}
}

// Mutation 33 (AAD without the target id): target A's secret copied into B's
// row does not open for B, and A's URL is never used for B's alerts.
func TestSwappedTargetSecretDoesNotOpen(t *testing.T) {
	rcvA, rcvB := newHookRecv(t), newHookRecv(t)
	e, al, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t), loopback: true})
	createWebhook(t, b, tok, "a", rcvA.url("/a"), nil)
	createWebhook(t, b, tok, "b", rcvB.url("/b"), nil)
	raw, err := sql.Open("sqlite", "file:"+e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`UPDATE alert_targets SET secret = (SELECT secret FROM alert_targets WHERE name = 'a') WHERE name = 'b'`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	postReport(t, e, registerHost(t, e, "web01"), setClamdDown)
	e.runAlerts(al)
	if rcvA.count() != 1 {
		t.Fatalf("a's own alert: %d", rcvA.count())
	}
	if rcvB.count() != 0 {
		t.Fatal("b's receiver was contacted with a swapped secret")
	}
	if n := e.count(`SELECT count(*) FROM alert_log WHERE target_name = 'b' AND status = 'failed' AND code = 'secret' AND error LIKE '%cannot be opened%'`); n != 1 {
		t.Fatalf("b must fail permanently with a clear text: %d", n)
	}
	// The Alerts page carries a banner for b.
	if p := b.get("/admin/alerts"); !strings.Contains(p.body, `data-testid="alert-banner-unreadable-b"`) || strings.Contains(p.body, `data-testid="alert-banner-unreadable-a"`) {
		t.Fatalf("banner:\n%s", p.body)
	}
}

// Mutations 28 (response body shown or stored), 40 (rate limit or class of the
// route removed) and the signature of the test payload.
func TestTestSendThroughRouter(t *testing.T) {
	rcv := newHookRecv(t)
	e, _, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t), loopback: true, public: "https://cf.example"})
	key, _ := createWebhook(t, b, tok, "ops", rcv.url("/hook/T"), nil)

	hx := map[string]string{"HX-Request": "true", "X-CSRF-Token": tok, "Sec-Fetch-Site": "same-origin"}
	p := b.do("POST", "/admin/alerts/ops/test", hx, url.Values{})
	if p.status != 200 || !strings.Contains(p.body, "Delivered: HTTP 204") || strings.Contains(p.body, "<html") {
		t.Fatalf("fragment: %d\n%s", p.status, p.body)
	}
	if strings.Contains(p.body, "SECRET-BODY-MARKER") || strings.Contains(p.body, "/hook/T") {
		t.Fatal("the fragment shows the response body or the URL")
	}
	reqs := rcv.all()
	if len(reqs) != 1 {
		t.Fatalf("%d requests", len(reqs))
	}
	var tp alert.TestPayload
	if err := json.Unmarshal([]byte(reqs[0].body), &tp); err != nil || tp.Kind != "test" || tp.Target != "ops" || tp.URL == nil || *tp.URL != "https://cf.example" {
		t.Fatalf("%+v %v", tp, err)
	}
	if !reqs[0].verify(key) {
		t.Fatal("the test payload is not signed with the target's key")
	}
	if reqs[0].header.Get("webhook-timestamp") != strconv.FormatInt(e.clock().Unix(), 10) {
		t.Fatal("the timestamp must come from the injected clock")
	}
	if e.count(`SELECT count(*) FROM alert_log WHERE status = 'test_sent' AND target_name = 'ops'`) != 1 || e.count(`SELECT count(*) FROM audit_log WHERE action = 'alert_target.test' AND detail LIKE '%sent%'`) != 1 {
		t.Fatal("log row or audit row missing")
	}
	if bytes := fileBytes(t, e); strings.Contains(bytes, "SECRET-BODY-MARKER") || strings.Contains(e.logs.String(), "SECRET-BODY-MARKER") {
		t.Fatal("the response body was stored or logged")
	}
	// A second test inside 10 s: 429 with a fragment (htmx must swap it).
	p = b.do("POST", "/admin/alerts/ops/test", hx, url.Values{})
	if p.status != 429 || !strings.Contains(p.body, "wait 10 seconds") || rcv.count() != 1 {
		t.Fatalf("rate limit: %d\n%s", p.status, p.body)
	}
	e.advance(11 * time.Second)
	if p := b.do("POST", "/admin/alerts/ops/test", hx, url.Values{}); p.status != 200 {
		t.Fatalf("after the gap: %d", p.status)
	}
	// Without htmx: a redirect with a notice.
	e.advance(11 * time.Second)
	pn := b.post("/admin/alerts/ops/test", url.Values{"csrf_token": {tok}})
	if pn.status != 303 || !strings.Contains(pn.header.Get("Location"), "notice=test-ok") {
		t.Fatalf("plain post: %d %q", pn.status, pn.header.Get("Location"))
	}
	if pg := b.get(pn.header.Get("Location")); !strings.Contains(pg.body, "Test message to ops delivered.") {
		t.Fatalf("notice:\n%s", pg.body)
	}
	if p := b.post("/admin/alerts/ghost/test", url.Values{"csrf_token": {tok}}); p.status != 404 {
		t.Fatalf("unknown target: %d", p.status)
	}
}

// seedWebhook creates a webhook target straight in the store, sealed with keys,
// bypassing the console's URL validation (what a database edit or an older
// policy could leave behind). It returns the signing key.
func seedWebhook(t *testing.T, e *env, keys *secrets.Keyring, name, hookURL string) string {
	t.Helper()
	key, err := alert.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.st.CreateAlertTarget(context.Background(), store.NewAlertTarget{Name: name, Type: store.TargetTypeWebhook, Config: []byte(`{"url_display":"x","plaintext":true}`),
		MinSeverity: "WARN", SendStateChanges: true, SendDetections: true, Enabled: true},
		func(id int64) ([]byte, error) {
			plain, _ := alert.WebhookSecret{URL: hookURL, SigningKey: key}.Marshal()
			return keys.Seal(secrets.PurposeAlertTarget, plain, uint64(id))
		}, e.clock(), cliAudit)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// With loopback off, the fragment says "Blocked" and the receiver is never hit
// (the policy is enforced at send time, whatever was stored).
func TestTestSendIsBlockedByThePolicy(t *testing.T) {
	rcv := newHookRecv(t)
	keys := testKeyring(t)
	e, _, b, tok := alertEnv(t, alertOpts{keys: keys})
	seedWebhook(t, e, keys, "ops", rcv.url("/x"))
	hx := map[string]string{"HX-Request": "true", "X-CSRF-Token": tok, "Sec-Fetch-Site": "same-origin"}
	p := b.do("POST", "/admin/alerts/ops/test", hx, url.Values{})
	if p.status != 200 || !strings.Contains(p.body, "Blocked: address 127.0.0.1 is loopback") || rcv.count() != 0 {
		t.Fatalf("%d hits %d\n%s", p.status, rcv.count(), p.body)
	}
	if e.count(`SELECT count(*) FROM alert_log WHERE status = 'test_failed' AND code = 'blocked'`) != 1 {
		t.Fatal("no test_failed log row")
	}
}

func TestFirstEvaluationOKDoesNotAlert(t *testing.T) {
	rcv := newHookRecv(t)
	e, al, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t), loopback: true})
	createWebhook(t, b, tok, "ops", rcv.url("/h"), nil)
	postReport(t, e, registerHost(t, e, "web01"), nil) // healthy: NULL -> OK
	e.runAlerts(al)
	if rcv.count() != 0 || e.count(`SELECT count(*) FROM alert_deliveries`) != 0 {
		t.Fatalf("a first evaluation of OK alerted: %d requests", rcv.count())
	}
	if e.count(`SELECT count(*) FROM state_changes WHERE alert_pending = 1`) != 0 {
		t.Fatal("the flag must be cleared even when nothing is sent")
	}
}

// The spec 14 acceptance at functional level, mutations
// 1, 4, 5, 6, 17 and 43 (the planner, the flags, the cooldown, the recovery
// summary and the per-attempt log), through the real router with a webhook and
// an email target.
func TestReportTransitionAlertsThroughRouter(t *testing.T) {
	rcv := newHookRecv(t)
	srv := startFakeSMTP(t, testsmtp.Options{})
	e, al, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t), loopback: true, smtp: srv, public: "https://cf.example"})
	createWebhook(t, b, tok, "ops", rcv.url("/h"), nil)
	createEmail(t, b, tok, "mail", "ops@x.example")
	hostTok := registerHost(t, e, "web01")

	// 1. clamd down: exactly one state_change to CRIT with the host link.
	postReport(t, e, hostTok, setClamdDown)
	e.runAlerts(al)
	sts := rcv.states()
	if len(sts) != 1 || sts[0].To != "CRIT" || sts[0].From != nil || sts[0].Host != "web01" || sts[0].URL == nil || *sts[0].URL != "https://cf.example/hosts/web01" || sts[0].Changes != 1 || sts[0].Resolved {
		t.Fatalf("step 1: %+v", sts)
	}
	if len(sts[0].ReasonCodes) == 0 || sts[0].ReasonCodes[0] != "clamd_down" {
		t.Fatalf("reason codes %v", sts[0].ReasonCodes)
	}
	if len(srv.Messages()) != 1 || !strings.Contains(srv.Messages()[0].Data, "Subject: [ClamFleet] web01: none -> CRIT") {
		t.Fatalf("email: %+v", srv.Messages())
	}
	e.runAlerts(al)
	e.runAlerts(al)
	if rcv.count() != 1 || len(srv.Messages()) != 1 {
		t.Fatal("redelivered after success")
	}

	// 2. A healthy report 2 minutes later: held, nothing sent, a 'held' log row.
	e.advance(2 * time.Minute)
	postReport(t, e, hostTok, nil)
	e.runAlerts(al)
	if rcv.count() != 1 || len(srv.Messages()) != 1 {
		t.Fatalf("the recovery inside the cooldown was sent: %d %d", rcv.count(), len(srv.Messages()))
	}
	if e.count(`SELECT count(*) FROM alert_log WHERE status = 'held'`) != 2 {
		t.Fatalf("%d held rows, want 2 (one per target)", e.count(`SELECT count(*) FROM alert_log WHERE status = 'held'`))
	}

	// 3. At the end of the window: exactly one recovery, from CRIT, changes 1.
	e.advance(13 * time.Minute)
	e.runAlerts(al)
	sts = rcv.states()
	if len(sts) != 2 || sts[1].To != "OK" || sts[1].From == nil || *sts[1].From != "CRIT" || sts[1].Changes != 1 || !sts[1].Resolved {
		t.Fatalf("step 3: %+v", sts)
	}
	if len(srv.Messages()) != 2 || !strings.Contains(srv.Messages()[1].Data, "CRIT -> OK resolved for this target") {
		t.Fatalf("email recovery: %d", len(srv.Messages()))
	}

	// 4. The receiver fails the next transition: retrying rows with the code.
	rcv.status.Store(500)
	e.advance(16 * time.Minute)
	postReport(t, e, hostTok, setClamdDown)
	e.runAlerts(al)
	if n := e.count(`SELECT count(*) FROM alert_log WHERE status = 'retrying' AND code = 'HTTP 500' AND target_name = 'ops'`); n != 1 {
		t.Fatalf("%d retrying rows", n)
	}
	if len(srv.Messages()) != 3 {
		t.Fatalf("the email target must get the third alert regardless: %d", len(srv.Messages()))
	}
	// The Alerts page shows the history with codes.
	if p := b.get("/admin/alerts"); !strings.Contains(p.body, "HTTP 500") || !strings.Contains(p.body, "retrying") {
		t.Fatalf("recent deliveries:\n%s", p.body)
	}
}

// Mutation 7: detections are not held and ignore the minimum severity; a
// retried duplicate POST gives no third delivery.
func TestDetectionAlertsAreNotHeld(t *testing.T) {
	rcv := newHookRecv(t)
	e, al, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t), loopback: true})
	createWebhook(t, b, tok, "ops", rcv.url("/h"), url.Values{"min_severity": {"STALE"}})
	hostTok := registerHost(t, e, "web01")
	postReport(t, e, hostTok, nil)
	at := e.clock()
	for i, path := range []string{"/tmp/a", "/tmp/b"} {
		if code := postEvent(t, e, hostTok, path, at.Add(time.Duration(i)*time.Second)); code != 202 {
			t.Fatalf("event: %d", code)
		}
		e.advance(time.Second)
	}
	// Two passes: the second detection waits behind the first one for the same
	// (target, host) until it has finished (per-pair order), not for the cooldown.
	e.runAlerts(al)
	e.runAlerts(al)
	if rcv.count() != 2 {
		t.Fatalf("%d detection requests, want 2 inside the cooldown", rcv.count())
	}
	var p alert.DetectionPayload
	if err := json.Unmarshal([]byte(rcv.all()[0].body), &p); err != nil || p.Kind != "detection" || p.Path != "/tmp/a" || p.Signature != "Eicar-Test" || p.Host != "web01" {
		t.Fatalf("%+v %v", p, err)
	}
	postEvent(t, e, hostTok, "/tmp/b", at.Add(time.Second)) // the agent retries the second event, same timestamp
	e.runAlerts(al)
	if rcv.count() != 2 {
		t.Fatalf("a retried duplicate alerted again: %d", rcv.count())
	}
}

// Review finding 12, mutation 38: a detection no target takes is visible.
func TestUnroutedDetectionIsVisible(t *testing.T) {
	rcv := newHookRecv(t)
	e, al, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t), loopback: true})
	createWebhook(t, b, tok, "ops", rcv.url("/h"), url.Values{"tags": {"prod"}})
	hostTok := registerHost(t, e, "web01")
	postReport(t, e, hostTok, func(m map[string]any) { m["tags"] = []string{"dev"} })
	if code := postEvent(t, e, hostTok, "/tmp/x", e.clock()); code != 202 {
		t.Fatalf("event: %d", code)
	}
	e.runAlerts(al)
	if rcv.count() != 0 || e.count(`SELECT count(*) FROM alert_deliveries`) != 0 {
		t.Fatal("an unmatched detection was delivered")
	}
	if e.count(`SELECT count(*) FROM events WHERE alert_pending = 1`) != 0 || e.count(`SELECT count(*) FROM events`) != 1 {
		t.Fatal("the flag must be cleared and the event kept")
	}
	if l := e.logs.String(); !strings.Contains(l, "detection matched no alert target") || !strings.Contains(l, `"host":"web01"`) || !strings.Contains(l, `"event_id":1`) {
		t.Fatalf("no warning naming the host and the event:\n%s", l)
	}
	if p := b.get("/admin/alerts"); !strings.Contains(p.body, "1 detection in the last 7 days matched no alert target") {
		t.Fatalf("banner:\n%s", p.body)
	}
}

// Banners and the viewer: email off, no public_url, and no menu item or access
// for viewers (M4 decision 18).
func TestAlertsPageBannersAndViewerAccess(t *testing.T) {
	e, _, b, _ := alertEnv(t, alertOpts{keys: testKeyring(t)})
	p := b.get("/admin/alerts")
	for _, want := range []string{"alert-banner-email-off", "alert-banner-no-public-url"} {
		if !strings.Contains(p.body, want) {
			t.Errorf("banner %s missing", want)
		}
	}
	e.addUser("view@example.com", "viewer", goodPW, false)
	v := e.browser()
	v.login("view@example.com", goodPW)
	if home := v.get("/"); strings.Contains(home.body, "/admin/alerts") || strings.Contains(home.body, "nav-alerts") {
		t.Fatal("a viewer sees the Alerts menu item")
	}
	for _, path := range []string{"/admin/alerts", "/admin/alerts/new?type=email", "/admin/alerts/ops"} {
		if p := v.get(path); p.status != 403 {
			t.Errorf("viewer GET %s: %d", path, p.status)
		}
	}
	srv := startFakeSMTP(t, testsmtp.Options{})
	_, _, b2, _ := alertEnv(t, alertOpts{keys: testKeyring(t), smtp: srv, public: "https://cf.example"})
	p = b2.get("/admin/alerts")
	if strings.Contains(p.body, "alert-banner-email-off") || strings.Contains(p.body, "alert-banner-no-public-url") {
		t.Fatal("banners shown although email and public_url are configured")
	}
}

// The email target path: a plaintext relay is marked unencrypted, and the list
// shows the first recipient and a count.
func TestEmailTargetListShowsRecipientsAndPlaintextBadge(t *testing.T) {
	srv := startFakeSMTP(t, testsmtp.Options{})
	_, _, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t), smtp: srv})
	createEmail(t, b, tok, "mail", "a@x.example, b@x.example\nc@x.example")
	p := b.get("/admin/alerts")
	if !strings.Contains(p.body, "a@x.example and 2 more") || !strings.Contains(p.body, `data-testid="alert-unencrypted-mail"`) {
		t.Fatalf("%s", p.body)
	}
	if e := b.get("/admin/alerts/mail"); !strings.Contains(e.body, "c@x.example") || !strings.Contains(e.body, "alert-form-smtp-plain") {
		t.Fatalf("edit page:\n%s", e.body)
	}
}

// Mutation: secrets in logs. After create, test, rotate and delivery, the log
// buffer and the audit details hold no key, URL path or SMTP password.
func TestNoSecretInLogsOrAuditForAlerts(t *testing.T) {
	rcv := newHookRecv(t)
	e, al, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t), loopback: true})
	key, _ := createWebhook(t, b, tok, "ops", rcv.url("/hook/PATH-MARKER"), nil)
	b.do("POST", "/admin/alerts/ops/test", map[string]string{"HX-Request": "true", "X-CSRF-Token": tok, "Sec-Fetch-Site": "same-origin"}, url.Values{})
	rot := b.post("/admin/alerts/ops/rotate-secret", url.Values{"csrf_token": {tok}})
	postReport(t, e, registerHost(t, e, "web01"), setClamdDown)
	e.runAlerts(al)
	if rcv.count() < 2 {
		t.Fatalf("%d requests", rcv.count())
	}
	newKey := keysIn(rot.body)[0]
	logs, audit := e.logs.String(), auditDetails(t, e)
	for _, secret := range []string{"PATH-MARKER", key[6:], newKey[6:], "SECRET-BODY-MARKER"} {
		if strings.Contains(logs, secret) || strings.Contains(audit, secret) {
			t.Errorf("%q reached the logs or the audit log", secret)
		}
	}
	if !strings.Contains(logs, `"msg":"alert delivered"`) || !strings.Contains(logs, `"msg":"alert"`) {
		t.Fatalf("the delivery was not logged:\n%s", logs)
	}
}

// Review finding 1: a test send that stalls must still answer inside the
// console's write timeout. With smtp.timeout 120 s and a stalled relay, the
// dispatcher's cap (TestBudget here, MaxTestSend in production) ends the send
// and the fragment arrives.
func TestTestSendIsCappedBelowTheWriteTimeout(t *testing.T) {
	srv := startFakeSMTP(t, testsmtp.Options{Stall: true})
	e, al, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t), smtp: srv})
	al.Dispatcher.MailTimeout = 120 * time.Second
	al.Dispatcher.Mail.(*alert.SMTPSender).Config.Timeout = 120 * time.Second // the sender's own session deadline, as configured
	al.Dispatcher.TestBudget = 500 * time.Millisecond
	createEmail(t, b, tok, "mail", "a@x.example")
	b.c.Timeout = 4 * time.Second // what a browser behind the 30 s write timeout would never wait for
	start := time.Now()
	p := b.do("POST", "/admin/alerts/mail/test", map[string]string{"HX-Request": "true", "X-CSRF-Token": tok, "Sec-Fetch-Site": "same-origin"}, url.Values{})
	if p.status != 200 || !strings.Contains(p.body, "timed out") || time.Since(start) > 3*time.Second {
		t.Fatalf("%d after %v\n%s", p.status, time.Since(start), p.body)
	}
	if e.count(`SELECT count(*) FROM alert_log WHERE status = 'test_failed' AND code = 'timeout'`) != 1 {
		t.Fatal("the failed test was not logged")
	}
}

// racyStore simulates another admin acting between the console's read of a target
// and its write: after the first AlertTarget read it runs `during` once.
type racyStore struct {
	store.Store
	during func()
	armed  *atomic.Bool
}

func (r racyStore) AlertTarget(ctx context.Context, name string) (store.AlertTarget, error) {
	t, err := r.Store.AlertTarget(ctx, name)
	if err == nil && r.armed.Swap(false) {
		r.during()
	}
	return t, err
}

// Review finding 2 through the router: an update and a rotation interleaved
// answer 409 "changed by someone else", never a silent overwrite.
func TestRotateAndUpdateRaceAnswers409(t *testing.T) {
	rcv := newHookRecv(t)
	var armed atomic.Bool
	var inner store.Store
	var during func()
	keys := testKeyring(t)
	e := newReportEnv(t, func(d *server.Deps) {
		inner = d.Store
		d.Store = racyStore{d.Store, func() { during() }, &armed}
		cfg := server.DefaultConfig()
		cfg.Alert.Webhook.AllowLoopback = true
		al, err := server.BuildAlerts(cfg, d.Store, keys, d.Now, d.Log)
		if err != nil {
			t.Fatal(err)
		}
		d.Alerts, d.Keys = al, keys
	})
	b, tok := adminBrowser(t, e)
	createWebhook(t, b, tok, "ops", rcv.url("/h"), nil)
	secret := func() string {
		raw, _ := openRaw(e.dbPath)
		defer raw.Close()
		var s string
		raw.QueryRow(`SELECT hex(secret) || config FROM alert_targets WHERE name = 'ops'`).Scan(&s)
		return s
	}
	rotateConcurrently := func() {
		tg, _ := inner.AlertTarget(context.Background(), "ops")
		inner.RotateAlertSecret(context.Background(), "ops", store.TargetSnapshot{Config: tg.Config, Sealed: tg.Sealed},
			func(int64) ([]byte, error) { return []byte("other-admin"), nil }, e.clock(), cliAudit)
	}

	// A URL change races a rotation by another admin.
	during = rotateConcurrently
	armed.Store(true)
	p := b.post("/admin/alerts/ops", url.Values{"csrf_token": {tok}, "url": {rcv.url("/new")}, "min_severity": {"WARN"}, "state_changes": {"1"}, "detections": {"1"}, "enabled": {"1"}})
	if p.status != 409 || !strings.Contains(p.body, "changed by someone else") {
		t.Fatalf("update racing a rotation: %d\n%s", p.status, p.body)
	}
	if got := secret(); !strings.HasPrefix(got, hexOf("other-admin")) {
		t.Fatalf("the update overwrote the other admin's rotation: %s", got)
	}
	// A rotation races a URL change by another admin.
	during = func() {
		tg, _ := inner.AlertTarget(context.Background(), "ops")
		inner.UpdateAlertTarget(context.Background(), "ops", store.AlertTargetUpdate{Config: []byte(`{"url_display":"theirs","plaintext":true}`), MinSeverity: "WARN",
			SendStateChanges: true, SendDetections: true, Enabled: true}, func(int64) ([]byte, error) { return []byte("their-url"), nil }, e.clock(), cliAudit)
		_ = tg
	}
	// "other-admin" is not a real sealed blob, so the rotate would answer 409 (cannot open) on its own; give the
	// target a real secret first through the console.
	if p := b.post("/admin/alerts/ops", url.Values{"csrf_token": {tok}, "url": {rcv.url("/real")}, "min_severity": {"WARN"}, "state_changes": {"1"}, "detections": {"1"}, "enabled": {"1"}}); p.status != 200 && p.status != 303 {
		t.Fatalf("re-entering the URL: %d", p.status)
	}
	armed.Store(true)
	before := secret()
	p = b.post("/admin/alerts/ops/rotate-secret", url.Values{"csrf_token": {tok}})
	if p.status != 409 || !strings.Contains(p.body, "changed by someone else") {
		t.Fatalf("rotation racing an update: %d\n%s", p.status, p.body)
	}
	if got := secret(); got == before || !strings.HasPrefix(got, hexOf("their-url")) {
		t.Fatalf("the rotation overwrote the other admin's update: %s", got)
	}
}

func hexOf(s string) string { return strings.ToUpper(hex.EncodeToString([]byte(s))) }
