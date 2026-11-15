// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Router tests of the detections page and acknowledgement: every request goes
// through server.NewHandler, with real SQLite and an injected clock.
package web_test

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/health"
	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/server"
	"github.com/clamfleet/clamfleet/internal/store"
)

func recordEvent(t *testing.T, e *env, hostID int64, path, sig string, ts, recv time.Time, id int) int64 {
	t.Helper()
	aid := fmt.Sprintf("%032x", id)
	if _, err := e.st.RecordEvent(context.Background(), store.EventRecord{HostID: hostID, ReceivedAt: recv,
		Event: proto.Event{Schema: 1, ID: &aid, TS: ts, Path: path, Signature: sig, Source: "clamd"}}); err != nil {
		t.Fatal(err)
	}
	// The id of the row this call stored, found through its receipt: the newest
	// row by any ordering is not necessarily the one just created.
	return int64(e.count(`SELECT event_id FROM event_receipts WHERE host_id = ? AND agent_event_id = ?`, hostID, aid))
}

func hostID(t *testing.T, e *env, name string) int64 {
	t.Helper()
	d, err := e.st.HostByName(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return d.ID
}

func TestEventsPageThroughRouter(t *testing.T) {
	e := newEnv(t)
	e.addUser("view@example.com", "viewer", goodPW, false)
	registerHost(t, e, "web01")
	registerHost(t, e, "db01")
	web, db := hostID(t, e, "web01"), hostID(t, e, "db01")
	now := e.clock()
	for i := 0; i < 120; i++ {
		recordEvent(t, e, web, fmt.Sprintf("/srv/file%03d", i), "Win.Test.EICAR_HDB-1", now.Add(-time.Duration(i)*time.Second), now, i+1)
	}
	// A spooled event: detected 3 hours before it arrived.
	spooled := recordEvent(t, e, db, "/srv/old.bin", "Php.Shell_x", now.Add(-3*time.Hour), now, 500)

	viewer := e.browser()
	viewer.login("view@example.com", goodPW)
	p := viewer.get("/events")
	if p.status != 200 || !strings.Contains(p.body, `data-testid="events-page"`) {
		t.Fatalf("%d", p.status)
	}
	if n := strings.Count(p.body, `data-testid="event-row-`); n != 50 {
		t.Fatalf("%d rows on the first page, want 50", n)
	}
	if !strings.Contains(p.body, `data-testid="events-count">121 matching`) {
		t.Fatalf("count line:\n%s", between(p.body, `data-testid="events-count"`, "</p>"))
	}
	// The newest id first.
	if !strings.Contains(p.body, fmt.Sprintf(`data-testid="event-row-%d"`, spooled)) {
		t.Fatal("the newest event is not on the first page")
	}
	if !strings.Contains(p.body, `received 3h later, spooled`) {
		t.Fatal("the late arrival of a spooled event is not shown")
	}
	// A viewer's page has no acknowledgement markup at all.
	for _, bad := range []string{"event-ack-", "events-bulk-", "/events/ack", "/ack\""} {
		if strings.Contains(p.body, bad) {
			t.Fatalf("a viewer's page contains %q", bad)
		}
	}
	// Pagination by keyset: Older, then Newest.
	older := hrefOf(t, p.body, "events-older")
	p2 := viewer.get(older)
	if n := strings.Count(p2.body, `data-testid="event-row-`); n != 50 || !strings.Contains(p2.body, `data-testid="events-newest"`) {
		t.Fatalf("page 2: %d rows", n)
	}
	p3 := viewer.get(hrefOf(t, p2.body, "events-older"))
	if n := strings.Count(p3.body, `data-testid="event-row-`); n != 21 || strings.Contains(p3.body, `data-testid="events-older"`) {
		t.Fatalf("page 3: %d rows, and no further Older link", n)
	}
	// Filters: host, signature (a substring, case-insensitive), state.
	p = viewer.get("/events?host=db01")
	if n := strings.Count(p.body, `data-testid="event-row-`); n != 1 || !strings.Contains(p.body, `events-count">1 matching`) {
		t.Fatalf("host filter: %d rows", n)
	}
	p = viewer.get("/events?sig=eicar")
	if !strings.Contains(p.body, `121`) && !strings.Contains(p.body, `120 matching`) {
		t.Fatalf("signature filter:\n%s", between(p.body, `data-testid="events-count"`, "</p>"))
	}
	p = viewer.get("/events?sig=zzz")
	if !strings.Contains(p.body, `data-testid="events-no-match"`) {
		t.Fatal("no events-no-match state")
	}
	// A path filter does not exist: a query parameter "path" changes nothing and is never echoed.
	p = viewer.get("/events?path=/srv/file001")
	if strings.Contains(p.body, "/srv/file001\"") && strings.Contains(p.body, `value="/srv/file001"`) {
		t.Fatal("the path parameter was echoed into the page")
	}
	// Empty database: the empty state.
	e2 := newEnv(t)
	e2.addUser("view@example.com", "viewer", goodPW, false)
	b2 := e2.browser()
	b2.login("view@example.com", goodPW)
	if p := b2.get("/events"); !strings.Contains(p.body, `data-testid="events-empty"`) {
		t.Fatal("no empty state")
	}
}

func between(s, from, to string) string {
	i := strings.Index(s, from)
	if i < 0 {
		return ""
	}
	j := strings.Index(s[i:], to)
	if j < 0 {
		return s[i:]
	}
	return s[i : i+j]
}

func hrefOf(t *testing.T, body, testid string) string {
	t.Helper()
	m := regexp.MustCompile(`href="([^"]+)" data-testid="` + testid + `"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no link %s", testid)
	}
	return strings.ReplaceAll(m[1], "&amp;", "&")
}

func TestAckThroughRouter(t *testing.T) {
	e := newEnv(t)
	b, tok := adminBrowser(t, e)
	registerHost(t, e, "web01")
	hid := hostID(t, e, "web01")
	id := recordEvent(t, e, hid, "/srv/a", "Eicar", e.clock(), e.clock(), 1)
	idStr := strconv.FormatInt(id, 10)

	// htmx: a 200 fragment (the row, not a page) naming who acknowledged.
	px := b.do("POST", "/events/"+idStr+"/ack", map[string]string{"HX-Request": "true", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": tok}, url.Values{})
	if px.status != 200 || !strings.Contains(px.body, `data-testid="event-ackby-`+idStr+`">Acknowledged by adm@example.com`) || strings.Contains(px.body, "<html") {
		t.Fatalf("htmx ack: %d\n%s", px.status, px.body)
	}
	if strings.Contains(px.body, "event-ack-"+idStr) {
		t.Fatal("an acknowledged row still offers the button")
	}
	rows := e.count(`SELECT count(*) FROM audit_log WHERE action = 'event.ack' AND actor_kind = 'user' AND actor = 'adm@example.com'`)
	if rows != 1 {
		t.Fatalf("%d audit rows", rows)
	}
	if !strings.Contains(e.logs.String(), `"msg":"event acknowledged"`) || strings.Contains(e.logs.String(), "/srv/a") {
		t.Fatalf("log line missing, or it carries the path:\n%s", e.logs.String())
	}
	// A second acknowledgement is a 200 showing who, and writes no new audit row.
	px = b.do("POST", "/events/"+idStr+"/ack", map[string]string{"HX-Request": "true", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": tok}, url.Values{})
	if px.status != 200 || !strings.Contains(px.body, "Acknowledged by adm@example.com") {
		t.Fatalf("second ack: %d", px.status)
	}
	if rows := e.count(`SELECT count(*) FROM audit_log WHERE action = 'event.ack'`); rows != 1 {
		t.Fatalf("%d audit rows after a second ack", rows)
	}
	// An unknown id is a 404.
	if p := b.post("/events/9999/ack", url.Values{"csrf_token": {tok}}); p.status != 404 {
		t.Fatalf("unknown id: %d", p.status)
	}
	if p := b.post("/events/abc/ack", url.Values{"csrf_token": {tok}}); p.status != 404 {
		t.Fatalf("non-numeric id: %d", p.status)
	}

	// Without htmx: 303 to a validated return, never off-site.
	for i, c := range []struct{ ret, want string }{
		{"/events?host=web01&ack=all", "/events?host=web01&ack=all"},
		{"/hosts/web01", "/hosts/web01"},
		{"//evil.example/", "/events"},
		{"https://evil.example/", "/events"},
		{"/\\evil.example", "/events"},
		{"/events\r\nSet-Cookie: x=1", "/events"},
		{"/hosts/web01/../../admin/hosts", "/events"},
		{"/admin/hosts", "/events"},
		{"", "/events"},
	} {
		// The index makes path and agent id unique per case, so each case acknowledges a fresh event.
		id2 := recordEvent(t, e, hid, "/srv/ret"+strconv.Itoa(i), "Eicar", e.clock(), e.clock(), 100+i)
		if n := e.count(`SELECT count(*) FROM events WHERE id = ? AND ack_by IS NULL`, id2); n != 1 {
			t.Fatalf("return=%q: event %d is already acknowledged", c.ret, id2)
		}
		p := b.post("/events/"+strconv.FormatInt(id2, 10)+"/ack", url.Values{"csrf_token": {tok}, "return": {c.ret}})
		if p.status != 303 || p.header.Get("Location") != c.want {
			t.Errorf("return=%q: %d to %q, want 303 to %q", c.ret, p.status, p.header.Get("Location"), c.want)
		}
	}
}

// Acknowledging records who and when and leaves alerts and health alone: a
// delivery that is retrying is still sent, and the host's state is unchanged.
func TestAckDoesNotTouchAlertsOrHealth(t *testing.T) {
	hook := newHookRecv(t)
	e, al, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t), loopback: true})
	reg := registerHost(t, e, "web01")
	createWebhook(t, b, tok, "ops", hook.srv.URL+"/h", nil)
	hook.status.Store(503)
	if code := postEvent(t, e, reg, "/srv/eicar", e.clock()); code != 202 {
		t.Fatal(code)
	}
	e.runAlerts(al) // the first attempt fails and is retried later
	if n := e.count(`SELECT count(*) FROM alert_deliveries WHERE status = 'pending' AND kind = 'detection'`); n != 1 {
		t.Fatalf("%d pending detection deliveries", n)
	}
	before := e.count(`SELECT count(*) FROM state_changes`)
	rows, _ := e.st.ListEvents(context.Background(), store.EventFilter{})
	p := b.post("/events/"+strconv.FormatInt(rows[0].ID, 10)+"/ack", url.Values{"csrf_token": {tok}})
	if p.status != 303 {
		t.Fatal(p.status)
	}
	if n := e.count(`SELECT count(*) FROM alert_deliveries WHERE status = 'pending' AND kind = 'detection'`); n != 1 {
		t.Fatalf("the ack cancelled the delivery: %d pending", n)
	}
	hook.status.Store(204)
	e.advance(2 * time.Minute)
	e.runAlerts(al)
	if n := e.count(`SELECT count(*) FROM alert_deliveries WHERE status = 'sent' AND kind = 'detection'`); n != 1 {
		t.Fatalf("the acknowledged detection was not delivered: %d sent", n)
	}
	if after := e.count(`SELECT count(*) FROM state_changes`); after != before {
		t.Fatalf("an acknowledgement changed health: %d -> %d state changes", before, after)
	}
}

// Hostile text is shown as text with visible escapes; the raw characters never
// reach the HTML.
func TestPathDisplayEscapes(t *testing.T) {
	e := newEnv(t)
	e.addUser("view@example.com", "viewer", goodPW, false)
	registerHost(t, e, "web01")
	hid := hostID(t, e, "web01")
	now := e.clock()
	paths := []string{
		"/srv/<script>alert(1)</script>/x",
		"/srv/invoice\u202etxt.exe",
		"/srv/line\u2028break",
		"/srv/new\nline",
		`/srv/literal\\u{202E}name`, // a file literally named \u{202E}name (the agent doubled the backslash)
		`/srv/raw\xffbyte`,
	}
	for i, pth := range paths {
		recordEvent(t, e, hid, pth, "<img src=x onerror=alert(1)>", now, now, i+1)
	}
	b := e.browser()
	b.login("view@example.com", goodPW)
	p := b.get("/events")
	if p.status != 200 {
		t.Fatal(p.status)
	}
	for _, raw := range []string{"\u202e", "\u2028", "<script>alert", "<img src=x"} {
		if strings.Contains(p.body, raw) {
			t.Fatalf("the raw %q reached the page", raw)
		}
	}
	for _, want := range []string{`<span class="esc" title="U&#43;202E RIGHT-TO-LEFT OVERRIDE">\u{202E}</span>`, `\u{2028}</span>`, `\u{000A}</span>`, `<span class="esc" title="byte 0xFF, not valid UTF-8">\xff</span>`, `&lt;script&gt;alert(1)&lt;/script&gt;`, `&lt;img src=x onerror=alert(1)&gt;`} {
		if !strings.Contains(p.body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	// The literal text \u{202E} is plain text, not an escape element.
	if !strings.Contains(p.body, `literal\u{202E}name`) || strings.Contains(p.body, `>\u{202E}</span>name`) {
		t.Errorf("a file literally named \\u{202E} must show as plain text")
	}
}

func TestFleetAndHostShowOpenDetections(t *testing.T) {
	e := newReportEnv(t)
	b, tok := adminBrowser(t, e)
	registerHost(t, e, "web01")
	tok2 := registerHost(t, e, "db01")
	postReport(t, e, tok2, func(m map[string]any) { m["clamd"].(map[string]any)["virus_event"] = "none" })
	hid := hostID(t, e, "web01")
	now := e.clock()
	a := recordEvent(t, e, hid, "/srv/a", "Eicar", now, now, 1)
	recordEvent(t, e, hid, "/srv/b", "Eicar", now, now, 2)
	// An event with an occurrence count of 2.
	recordEvent(t, e, hid, "/srv/c", "Eicar", now, now, 3)
	recordEvent(t, e, hid, "/srv/c", "Eicar", now, now, 4)

	p := b.get("/")
	if !strings.Contains(p.body, `data-testid="fleet-open-web01">`) || !strings.Contains(between(p.body, `data-testid="fleet-open-web01"`, "</td>"), ">3<") {
		t.Fatalf("fleet open count:\n%s", between(p.body, `data-testid="fleet-open-web01"`, "</td>"))
	}
	if !strings.Contains(p.body, `data-testid="fleet-count-open"`) || !strings.Contains(between(p.body, `data-testid="fleet-count-open"`, "</a>"), "3 open detections") {
		t.Fatal("fleet counter")
	}
	if !strings.Contains(between(p.body, `data-testid="nav-events-count"`, "</span>"), ">3") {
		t.Fatal("nav badge")
	}
	if p := b.post("/events/"+strconv.FormatInt(a, 10)+"/ack", url.Values{"csrf_token": {tok}}); p.status != 303 {
		t.Fatal(p.status)
	}
	p = b.get("/")
	if !strings.Contains(between(p.body, `data-testid="fleet-open-web01"`, "</td>"), ">2<") || !strings.Contains(between(p.body, `data-testid="nav-events-count"`, "</span>"), ">2") {
		t.Fatal("counts after one ack")
	}
	// The host card.
	p = b.get("/hosts/web01")
	if !strings.Contains(p.body, `data-testid="host-events"`) || !strings.Contains(p.body, `data-testid="host-events-all"`) || strings.Count(p.body, `data-testid="event-row-`) != 3 {
		t.Fatalf("host card: %d rows", strings.Count(p.body, `data-testid="event-row-`))
	}
	if !strings.Contains(p.body, `×2`) && !strings.Contains(p.body, "&times;2") {
		t.Fatal("the x2 occurrence marker is missing")
	}
	// virusevent_missing and the line on the host page.
	p = b.get("/hosts/db01")
	if !strings.Contains(between(p.body, `data-testid="host-virusevent"`, "</dd>"), "not set") || !strings.Contains(p.body, "virusevent_missing") {
		t.Fatalf("VirusEvent line / reason:\n%s", between(p.body, `data-testid="host-reasons"`, "</ul>"))
	}
}

// Bulk acknowledgement acts on the set shown: a detection that arrives after the
// page was rendered stays open, and the notice counts what this call changed.
func TestBulkAckRespectsUpto(t *testing.T) {
	e := newEnv(t)
	b, tok := adminBrowser(t, e)
	registerHost(t, e, "web01")
	hid := hostID(t, e, "web01")
	now := e.clock()
	for i := 0; i < 5; i++ {
		recordEvent(t, e, hid, fmt.Sprintf("/srv/%d", i), "Eicar", now, now, i+1)
	}
	p := b.get("/events")
	if !strings.Contains(p.body, `data-testid="events-bulk-open"`) || !strings.Contains(between(p.body, `data-testid="events-bulk-expected"`, "</strong>"), ">5") {
		t.Fatalf("bulk block:\n%s", between(p.body, `data-testid="events-bulk-open"`, "</details>"))
	}
	upto := fieldValue(t, p.body, "upto")
	expected := fieldValue(t, p.body, "expected")
	if upto != "5" || expected != "5" {
		t.Fatalf("upto %s expected %s", upto, expected)
	}
	// A new detection arrives, and another admin acknowledges one of the five.
	late := recordEvent(t, e, hid, "/srv/late", "Eicar", now, now, 99)
	if _, _, err := e.st.AckEvent(context.Background(), 2, now, store.Audit{Kind: store.ActorUser, Actor: "other@example.com"}); err != nil {
		t.Fatal(err)
	}
	post := b.post("/events/ack", url.Values{"csrf_token": {tok}, "upto": {upto}, "expected": {expected}})
	if post.status != 303 {
		t.Fatalf("%d\n%s", post.status, post.body)
	}
	loc := post.header.Get("Location")
	page := b.get(loc)
	if !strings.Contains(page.body, "4 detections acknowledged.") || !strings.Contains(page.body, "1 of the 5 shown had already been acknowledged by someone else.") {
		t.Fatalf("notice:\n%s", between(page.body, `data-testid="notice"`, "</div>"))
	}
	if n := e.count(`SELECT count(*) FROM events WHERE ack_at IS NULL`); n != 1 {
		t.Fatalf("%d open, want only the late one (#%d)", n, late)
	}
	// upto is required: without it nothing is acknowledged.
	if p := b.post("/events/ack", url.Values{"csrf_token": {tok}, "expected": {"1"}}); p.status != 400 {
		t.Fatalf("no upto: %d", p.status)
	}
	if p := b.post("/events/ack", url.Values{"csrf_token": {tok}, "upto": {"0"}, "expected": {"1"}}); p.status != 400 {
		t.Fatalf("upto 0: %d", p.status)
	}
	if n := e.count(`SELECT count(*) FROM events WHERE ack_at IS NULL`); n != 1 {
		t.Fatal("a refused bulk request acknowledged something")
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'event.ack.bulk'`); n != 1 {
		t.Fatalf("%d bulk audit rows", n)
	}
}

func fieldValue(t *testing.T, body, name string) string {
	t.Helper()
	m := regexp.MustCompile(`name="` + name + `" value="([^"]*)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no field %s", name)
	}
	return m[1]
}

// The 3 new routes are in the route table with the right class, and a viewer
// cannot acknowledge.
func TestEventRoutesAreRegisteredWithTheRightClass(t *testing.T) {
	want := map[string]server.AuthClass{"GET /events": server.AuthUser, "POST /events/{id}/ack": server.AuthAdmin, "POST /events/ack": server.AuthAdmin}
	got := map[string]server.AuthClass{}
	for _, r := range server.Routes() {
		got[r.Method+" "+r.Path] = r.Auth
	}
	for k, c := range want {
		if got[k] != c {
			t.Errorf("%s: class %q, want %q", k, got[k], c)
		}
	}
	e := newEnv(t)
	e.addUser("view@example.com", "viewer", goodPW, false)
	registerHost(t, e, "web01")
	id := recordEvent(t, e, hostID(t, e, "web01"), "/p", "S", e.clock(), e.clock(), 1)
	v := e.browser()
	v.login("view@example.com", goodPW)
	vtok := csrf(t, v.get("/events"))
	for _, path := range []string{"/events/" + strconv.FormatInt(id, 10) + "/ack", "/events/ack"} {
		if p := v.post(path, url.Values{"csrf_token": {vtok}, "upto": {"1"}, "expected": {"1"}}); p.status != 403 {
			t.Errorf("viewer POST %s: %d, want 403", path, p.status)
		}
	}
	if n := e.count(`SELECT count(*) FROM events WHERE ack_at IS NOT NULL`); n != 0 {
		t.Fatal("a viewer acknowledged an event")
	}
}

// The burst field: a new target gets 10 when the form does not say, 0 is allowed,
// a bad value is refused with nothing written, and an update without the field
// keeps what is stored.
func TestAlertTargetBurstField(t *testing.T) {
	e, _, b, tok := alertEnv(t, alertOpts{keys: testKeyring(t), loopback: true})
	burst := func(name string) int {
		return e.count(`SELECT detection_burst FROM alert_targets WHERE name = ?`, name)
	}
	createWebhook(t, b, tok, "plain", "http://127.0.0.1:9/h", nil)
	if n := burst("plain"); n != 10 {
		t.Fatalf("default burst %d, want 10", n)
	}
	createWebhook(t, b, tok, "zero", "http://127.0.0.1:9/h", url.Values{"detection_burst": {"0"}})
	if n := burst("zero"); n != 0 {
		t.Fatalf("burst %d, want 0", n)
	}
	p := b.post("/admin/alerts", url.Values{"csrf_token": {tok}, "type": {"webhook"}, "name": {"bad"}, "url": {"http://127.0.0.1:9/h"}, "min_severity": {"WARN"}, "detection_burst": {"-1"}})
	if p.status != 400 || !strings.Contains(p.body, "detection burst must be a whole number") {
		t.Fatalf("%d", p.status)
	}
	if e.count(`SELECT count(*) FROM alert_targets WHERE name = 'bad'`) != 0 {
		t.Fatal("a target with a bad burst was created")
	}
	edit := func(extra url.Values) page {
		form := url.Values{"csrf_token": {tok}, "min_severity": {"WARN"}, "state_changes": {"1"}, "detections": {"1"}, "enabled": {"1"}}
		for k, v := range extra {
			form[k] = v
		}
		return b.post("/admin/alerts/plain", form)
	}
	if p := edit(url.Values{"detection_burst": {"3"}}); p.status != 303 || burst("plain") != 3 {
		t.Fatalf("update: %d burst %d", p.status, burst("plain"))
	}
	if p := edit(nil); p.status != 303 || burst("plain") != 3 {
		t.Fatalf("an update without the field must keep it: %d burst %d", p.status, burst("plain"))
	}
	if p := edit(url.Values{"detection_burst": {"1001"}}); p.status != 400 || burst("plain") != 3 {
		t.Fatalf("1001: %d burst %d", p.status, burst("plain"))
	}
	if p := b.get("/admin/alerts/plain"); !strings.Contains(p.body, `data-testid="alert-detection-burst"`) || !strings.Contains(p.body, `value="3"`) {
		t.Fatal("the edit form does not show the burst")
	}
	_ = time.Second
}

// An outage longer than the STALE window, then the agent comes back: the newest
// heartbeat (live) recovers the host, and six replayed ones, with evaluator ticks
// between them, change nothing: exactly two transitions in total after the
// outage (OK to STALE, STALE to OK), last_seen stays where the newest report put
// it, and the replays are kept as history. One replay carries clamd down, which
// would turn the host CRIT if it were evaluated; one repeats another's timestamp.
func TestReplayDoesNotMoveState(t *testing.T) {
	ctx := context.Background()
	e := newReportEnv(t)
	tok := registerHost(t, e, "web01")
	ev := health.New(e.st, e.clock, server.DefaultConfig().Health.Thresholds(), e.log)

	postReport(t, e, tok, nil) // live, ts = now - 10 s
	d := hostDetail(t, e)
	if d.State == nil || *d.State != "OK" || len(d.StateChanges) != 1 {
		t.Fatalf("baseline: %+v", d.StateChanges)
	}

	e.advance(20 * time.Minute) // longer than 3 x the 300 s interval
	if err := ev.All(ctx); err != nil {
		t.Fatal(err)
	}
	d = hostDetail(t, e)
	if d.State == nil || *d.State != "STALE" || len(d.StateChanges) != 2 {
		t.Fatalf("after the outage: state %v, %d changes", d.State, len(d.StateChanges))
	}
	reportsBefore := d.ReportCount

	// The agent is back: its newest heartbeat is live.
	postReport(t, e, tok, nil)
	d = hostDetail(t, e)
	if d.State == nil || *d.State != "OK" || len(d.StateChanges) != 3 {
		t.Fatalf("recovery on the newest report: state %v, %d changes", d.State, len(d.StateChanges))
	}
	lastSeen := *d.LastSeen
	lastReport := string(d.LastReport)
	agentVersion := d.AgentVersion

	// Six replays, oldest ts anywhere in the outage, with evaluator ticks between.
	replay := func(ago time.Duration, down bool) {
		t.Helper()
		e.advance(time.Second)
		postReport(t, e, tok, func(m map[string]any) {
			m["replay"] = true
			m["ts"] = e.clock().Add(-ago).UTC().Format(time.RFC3339)
			m["agent_version"] = "replayed"
			if down {
				setClamdDown(m)
			}
		})
		if err := ev.All(ctx); err != nil {
			t.Fatal(err)
		}
	}
	replay(18*time.Minute, false)
	replay(15*time.Minute, true) // clamd down: CRIT if evaluated
	replay(12*time.Minute, false)
	replay(9*time.Minute, false)
	replay(6*time.Minute, false)
	replay(3*time.Minute, false)
	replay(3*time.Minute+time.Second, false) // not a duplicate: one second apart
	// A duplicate of an existing replay (same ts): stored once.
	e.advance(0)
	postReport(t, e, tok, func(m map[string]any) {
		m["replay"] = true
		m["ts"] = e.clock().Add(-(3*time.Minute + time.Second) - time.Second).UTC().Format(time.RFC3339)
	})

	d = hostDetail(t, e)
	if len(d.StateChanges) != 3 || d.State == nil || *d.State != "OK" {
		t.Fatalf("a replay moved state: %d changes, state %v", len(d.StateChanges), d.State)
	}
	if !d.LastSeen.Equal(lastSeen) {
		t.Fatalf("last_seen moved from %v to %v during the replay", lastSeen, d.LastSeen)
	}
	if string(d.LastReport) != lastReport || d.AgentVersion != agentVersion {
		t.Fatal("the newest report changed during the replay")
	}
	if want := reportsBefore + 1 + 7; d.ReportCount != int64(want) {
		t.Fatalf("report_count %d, want %d (the newest and seven distinct replays)", d.ReportCount, want)
	}
}

func hostDetail(t *testing.T, e *env) store.HostDetail {
	t.Helper()
	d, err := e.st.HostByName(context.Background(), "web01")
	if err != nil {
		t.Fatal(err)
	}
	return d
}
