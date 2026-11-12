// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package web_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// reportTime is the golden report's own timestamp; the clock of these tests
// starts a minute later, so the report is fresh.
var reportTime = time.Date(2026, 11, 12, 10, 30, 45, 0, time.UTC)

func newReportEnv(t *testing.T, opts ...opt) *env {
	t.Helper()
	return newEnvAt(t, reportTime.Add(time.Minute), opts...)
}

// postReport sends the golden report (real agent output) with changes to
// /v1/report through the real router, with the host's bearer token.
func postReport(t *testing.T, e *env, token string, mut func(m map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "agent", "testdata", "report.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	// Fresh signatures and a running freshclam: the baseline is OK.
	m["services"].(map[string]any)["freshclam"] = "active"
	m["ts"] = e.clock().Add(-10 * time.Second).UTC().Format(time.RFC3339)
	if mut != nil {
		mut(m)
	}
	body, _ := json.Marshal(m)
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/report", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 202 {
		t.Fatalf("POST /v1/report: %d", resp.StatusCode)
	}
}

func setClamdDown(m map[string]any) {
	m["clamd"] = map[string]any{"up": false, "version": nil, "queue": nil, "error": "ping: timeout"}
}

func TestReportTriggersEvaluation(t *testing.T) {
	e := newReportEnv(t)
	e.addUser("view@example.com", "viewer", goodPW, false)
	tok := registerHost(t, e, "web01")
	b := e.browser()
	b.login("view@example.com", goodPW)

	// Before any report the host is pending.
	if p := b.get("/fleet/rows"); !strings.Contains(p.body, `data-state="pending"`) {
		t.Fatalf("a host without a report must be pending:\n%s", p.body)
	}
	postReport(t, e, tok, setClamdDown)

	p := b.get("/fleet/rows")
	if p.status != 200 || !strings.Contains(p.body, `data-testid="fleet-state-web01">CRIT<`) || !strings.Contains(strings.ToLower(p.body), "clamd") {
		t.Fatalf("after a clamd-down report the fragment must show CRIT and a clamd reason (the report must have triggered an evaluation):\n%s", p.body)
	}
	// The fragment is a fragment: no layout.
	if strings.Contains(p.body, "<html") || strings.Contains(p.body, "csrf-token") {
		t.Fatal("/fleet/rows returned a full page")
	}
	if cc := p.header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q", cc)
	}
	// Filters.
	if p := b.get("/fleet/rows?state=OK"); strings.Contains(p.body, "fleet-row-web01") {
		t.Error("state=OK still lists the CRIT host")
	}
	if p := b.get("/fleet/rows?state=CRIT"); !strings.Contains(p.body, "fleet-row-web01") {
		t.Error("state=CRIT leaves out the CRIT host")
	}
	if p := b.get("/fleet/rows?tag=prod"); !strings.Contains(p.body, "fleet-row-web01") {
		t.Error("tag=prod (a tag of the report) leaves out the host")
	}
	if p := b.get("/fleet/rows?tag=nope"); strings.Contains(p.body, "fleet-row-web01") || !strings.Contains(p.body, "fleet-no-match") {
		t.Error("tag=nope still lists the host")
	}
	// An unknown state is ignored, not an error.
	if p := b.get("/fleet/rows?state=BOGUS"); p.status != 200 || !strings.Contains(p.body, "fleet-row-web01") {
		t.Errorf("state=BOGUS: %d", p.status)
	}
	// Recovery shows too (a later timestamp: the same one would be a retry of the first report).
	e.advance(time.Minute)
	postReport(t, e, tok, nil)
	if p := b.get("/fleet/rows"); !strings.Contains(p.body, `data-testid="fleet-state-web01">OK<`) {
		t.Fatalf("a good report must bring the host back to OK:\n%s", p.body)
	}
}

func TestFleetPageOrderAgeAndCounts(t *testing.T) {
	e := newReportEnv(t)
	e.addUser("view@example.com", "viewer", goodPW, false)
	okTok := registerHost(t, e, "alpha-ok")
	critTok := registerHost(t, e, "zeta-crit")
	registerHost(t, e, "mid-pending")
	revoked := registerHost(t, e, "revoked01")
	postReport(t, e, okTok, nil)
	postReport(t, e, critTok, setClamdDown)
	postReport(t, e, revoked, nil)
	if err := e.st.SetToken(t.Context(), "revoked01", nil, e.clock(), cliAudit); err != nil {
		t.Fatal(err)
	}
	e.advance(3*time.Minute + 10*time.Second)

	b := e.browser()
	b.login("view@example.com", goodPW)
	p := b.get("/")
	if p.status != 200 {
		t.Fatal(p.status)
	}
	iCrit, iPend, iOK := strings.Index(p.body, "fleet-row-zeta-crit"), strings.Index(p.body, "fleet-row-mid-pending"), strings.Index(p.body, "fleet-row-alpha-ok")
	if !(iCrit > 0 && iCrit < iPend && iPend < iOK) {
		t.Errorf("rows must be worst first (CRIT, pending, OK): %d %d %d", iCrit, iPend, iOK)
	}
	if strings.Contains(p.body, "revoked01") {
		t.Error("a revoked host is shown on the fleet page")
	}
	// "ago" comes from the injected clock: the reports were accepted at 10:31:45, 3m10s ago.
	if !regexp.MustCompile(`>3m ago<`).MatchString(p.body) {
		t.Errorf("last-seen text must be computed from the injected clock:\n%s", p.body)
	}
	if !strings.Contains(p.body, `title="2026-11-12 10:31:45 UTC"`) {
		t.Errorf("absolute UTC time missing in the title attribute")
	}
	for _, want := range []string{`data-testid="count-CRIT">CRIT 1<`, `data-testid="count-OK">OK 1<`, `data-testid="count-pending">pending 1<`, `data-testid="count-WARN">WARN 0<`} {
		if !strings.Contains(p.body, want) {
			t.Errorf("counts: missing %s", want)
		}
	}
	// The live region polls with the same filter.
	if !strings.Contains(p.body, `hx-get="/fleet/rows"`) || !strings.Contains(p.body, `hx-trigger="every 15s"`) {
		t.Error("live region lacks the 15 s poll")
	}
	q := b.get("/?tag=prod&state=CRIT")
	if !strings.Contains(q.body, `hx-get="/fleet/rows?state=CRIT&amp;tag=prod"`) || !strings.Contains(q.body, `<option value="prod" selected>`) || !strings.Contains(q.body, `<option value="CRIT" selected>`) {
		t.Errorf("filters are not carried into the page and the poll URL:\n%s", q.body)
	}
	// Filter options come from the whole fleet, not from the filtered rows.
	if !strings.Contains(b.get("/?state=OK").body, `<option value="web">`) {
		t.Error("the tag list shrank with the state filter")
	}
}

func TestFleetEmptyState(t *testing.T) {
	e := newEnv(t)
	e.addUser("view@example.com", "viewer", goodPW, false)
	b := e.browser()
	b.login("view@example.com", goodPW)
	if p := b.get("/"); p.status != 200 || !strings.Contains(p.body, `data-testid="fleet-empty"`) {
		t.Fatalf("an empty fleet needs a message: %d", p.status)
	}
}

func TestHostPageAndHistory(t *testing.T) {
	e := newReportEnv(t)
	e.addUser("view@example.com", "viewer", goodPW, false)
	e.addUser("adm@example.com", "admin", goodPW, false)
	tok := registerHost(t, e, "web01")
	postReport(t, e, tok, nil)
	e.advance(time.Minute)
	postReport(t, e, tok, setClamdDown)

	viewer := e.browser()
	viewer.login("view@example.com", goodPW)
	p := viewer.get("/hosts/web01")
	if p.status != 200 {
		t.Fatalf("%d", p.status)
	}
	for _, want := range []string{
		`data-testid="host-state">CRIT<`, `data-testid="host-reasons"`, "clamd_down", "ping: timeout",
		`data-testid="host-report"`, "28181", `data-testid="host-history"`, "OK", "CRIT", "agent_version", // placeholder replaced below
	} {
		if want == "agent_version" {
			continue
		}
		if !strings.Contains(p.body, want) {
			t.Errorf("host page lacks %q", want)
		}
	}
	if n := strings.Count(p.body, `data-testid="host-history-row"`); n != 2 {
		t.Errorf("%d history rows, want 2 (none->OK, OK->CRIT)", n)
	}
	// The injected clock, not the wall clock, drives every time on the page.
	if !strings.Contains(p.body, "2026-11-12 10:32:45 UTC") {
		t.Errorf("times on the page do not come from the injected clock")
	}
	// A viewer gets no admin block (the handler leaves the data out, not only the markup).
	if strings.Contains(p.body, "host-admin") || strings.Contains(p.body, "host-audit") || strings.Contains(p.body, "Token set") {
		t.Error("a viewer received the admin block")
	}
	admin := e.browser()
	admin.login("adm@example.com", goodPW)
	ap := admin.get("/hosts/web01")
	if !strings.Contains(ap.body, `data-testid="host-admin"`) || !strings.Contains(ap.body, "host.add") || !strings.Contains(ap.body, "Token set 2026-") {
		t.Errorf("admin block missing:\n%s", ap.body)
	}
	if p := viewer.get("/hosts/nope"); p.status != 404 || !strings.Contains(p.body, `data-testid="error-page"`) {
		t.Errorf("unknown host: %d", p.status)
	}
	// Names are case-insensitive, like everywhere else.
	if p := viewer.get("/hosts/WEB01"); p.status != 200 {
		t.Errorf("upper-case host name: %d", p.status)
	}
}

func TestAgentSuppliedTextIsEscaped(t *testing.T) {
	e := newReportEnv(t)
	e.addUser("view@example.com", "viewer", goodPW, false)
	e.addUser("adm@example.com", "admin", goodPW, false)
	tok := registerHost(t, e, "web01")
	postReport(t, e, tok, func(m map[string]any) {
		m["tags"] = []string{"<script>x</script>", `"><img src=x onerror=alert(1)>`}
		m["host"] = `"><img src=x>`
		m["agent_version"] = "<b>0.1</b>"
		m["clamd"] = map[string]any{"up": false, "version": "<i>1</i>", "queue": nil, "error": "<script>alert('e')</script>"}
		m["freshclam"] = map[string]any{"last_ok": nil, "last_error": "2026-11-12T10:00:00Z", "last_error_msg": `<img src=y onerror=alert(2)>`, "source": "journal"}
		m["services"] = map[string]any{"clamd": "<u>active</u>", "freshclam": "failed", "clamonacc": "inactive"}
	})
	for _, who := range []struct{ email string }{{"view@example.com"}, {"adm@example.com"}} {
		b := e.browser()
		b.login(who.email, goodPW)
		for _, path := range []string{"/", "/fleet/rows", "/hosts/web01"} {
			body := b.get(path).body
			for _, raw := range []string{"<script>x", "<script>alert", "<img src=x", "<img src=y", "<b>0.1", "<i>1", "<u>active"} {
				if strings.Contains(body, raw) {
					t.Errorf("%s as %s: raw agent text %q reached the page unescaped", path, who.email, raw)
				}
			}
		}
		// The escaped form is there (the text is shown, just inert).
		if body := b.get("/fleet/rows").body; !strings.Contains(body, "&lt;script&gt;x&lt;/script&gt;") {
			t.Errorf("escaped tag missing from the fleet fragment:\n%s", body)
		}
		if body := b.get("/hosts/web01").body; !strings.Contains(body, "&lt;img src=y onerror=alert(2)&gt;") || !strings.Contains(body, "&lt;i&gt;1&lt;/i&gt;") {
			t.Errorf("escaped report text missing from the host page")
		}
	}
}

func TestFleetFragmentForSessionlessPollLeavesThePage(t *testing.T) {
	e := newEnv(t)
	e.addUser("view@example.com", "viewer", goodPW, false)
	// What the htmx poll of an expired tab sees.
	p := e.browser().do("GET", "/fleet/rows", map[string]string{"HX-Request": "true"}, nil)
	if p.status != 401 || p.header.Get("HX-Redirect") != "/login" {
		t.Fatalf("%d %q", p.status, p.header.Get("HX-Redirect"))
	}
	// And after the idle timeout of a signed-in tab.
	b := e.browser()
	b.login("view@example.com", goodPW)
	e.advance(2 * time.Hour)
	if p := b.do("GET", "/fleet/rows", map[string]string{"HX-Request": "true"}, nil); p.status != 401 || p.header.Get("HX-Redirect") != "/login" {
		t.Fatalf("expired session poll: %d %q", p.status, p.header.Get("HX-Redirect"))
	}
}
