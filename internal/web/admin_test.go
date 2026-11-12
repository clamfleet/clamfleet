// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package web_test

import (
	"bytes"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

var tokenRE = regexp.MustCompile(`cfa_[A-Za-z0-9_-]{43}`)

// admin returns a signed-in admin browser and the CSRF token of its page.
func adminBrowser(t *testing.T, e *env) (*browser, string) {
	t.Helper()
	e.addUser("adm@example.com", "admin", goodPW, false)
	b := e.browser()
	b.login("adm@example.com", goodPW)
	return b, csrf(t, b.get("/admin/hosts"))
}

func TestRegisterHostShowsTokenOnce(t *testing.T) {
	e := newEnv(t)
	b, tok := adminBrowser(t, e)

	p := b.post("/admin/hosts", url.Values{"csrf_token": {tok}, "name": {"Web01"}})
	if p.status != 200 || p.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("register: %d, Cache-Control %q", p.status, p.header.Get("Cache-Control"))
	}
	tokens := tokenRE.FindAllString(p.body, -1)
	if len(tokens) != 1 {
		t.Fatalf("the page must contain exactly one agent token, found %d", len(tokens))
	}
	token := tokens[0]
	// Neither the log nor the database holds it in clear.
	if strings.Contains(e.logs.String(), token[4:]) {
		t.Error("the token is in the log")
	}
	var all []byte
	for _, suf := range []string{"", "-wal"} {
		if raw, err := os.ReadFile(e.dbPath + suf); err == nil {
			all = append(all, raw...)
		}
	}
	if bytes.Contains(all, []byte(token[4:])) {
		t.Error("the token is in the database file")
	}
	// The audit row names the user.
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='host.add' AND target='web01' AND actor_kind='user' AND actor='adm@example.com'`); n != 1 {
		t.Fatalf("%d host.add audit rows with actor_kind=user", n)
	}
	// The token works for the agent API at once...
	postReport(t, newReportEnvSharing(e), token, nil)
	// ...and no later page shows it again.
	for _, path := range []string{"/admin/hosts", "/hosts/web01", "/"} {
		if tokenRE.MatchString(b.get(path).body) {
			t.Errorf("GET %s shows an agent token", path)
		}
	}
	// Registering the same name again is a 409, not a second token.
	if p := b.post("/admin/hosts", url.Values{"csrf_token": {tok}, "name": {"web01"}}); p.status != 409 || tokenRE.MatchString(p.body) {
		t.Fatalf("duplicate: %d", p.status)
	}
	// Invalid names are refused with the typed value kept (escaped).
	if p := b.post("/admin/hosts", url.Values{"csrf_token": {tok}, "name": {`bad "name"<x>`}}); p.status != 400 || strings.Contains(p.body, "<x>") || !strings.Contains(p.body, "Invalid host name") {
		t.Fatalf("invalid name: %d", p.status)
	}
	if n := e.count(`SELECT count(*) FROM hosts`); n != 1 {
		t.Fatalf("%d hosts, want 1", n)
	}
}

// newReportEnvSharing lets postReport use an env created with the default
// clock: the ts it sends is derived from the env clock anyway.
func newReportEnvSharing(e *env) *env { return e }

func TestRotateRevokeDeleteThroughTheConsole(t *testing.T) {
	e := newEnv(t)
	b, tok := adminBrowser(t, e)
	oldTok := registerHost(t, e, "web01")
	registerHost(t, e, "keep01")

	// Rotate: a new token is shown once and the old one is dead at once.
	p := b.post("/admin/hosts/web01/rotate-token", url.Values{"csrf_token": {tok}})
	newTok := tokenRE.FindString(p.body)
	if p.status != 200 || newTok == "" || newTok == oldTok {
		t.Fatalf("rotate: %d token %q", p.status, newTok)
	}
	if code := reportStatus(t, e, oldTok); code != 401 {
		t.Fatalf("the old token still works after rotate: %d", code)
	}
	if code := reportStatus(t, e, newTok); code != 202 {
		t.Fatalf("the new token does not work: %d", code)
	}

	// Revoke: 303 back to the list with a notice; the host stays, its token is dead.
	p = b.post("/admin/hosts/web01/revoke-token", url.Values{"csrf_token": {tok}})
	if p.status != 303 || !strings.HasPrefix(p.header.Get("Location"), "/admin/hosts?") {
		t.Fatalf("revoke: %d %q", p.status, p.header.Get("Location"))
	}
	if code := reportStatus(t, e, newTok); code != 401 {
		t.Fatalf("the revoked token still works: %d", code)
	}
	list := b.get(p.header.Get("Location"))
	if !strings.Contains(list.body, "revoked") || !strings.Contains(list.body, `data-testid="notice"`) || !strings.Contains(list.body, "web01") {
		t.Fatalf("hosts page after revoke:\n%s", list.body)
	}

	// Delete needs the typed name: a wrong one deletes nothing.
	for _, bad := range []string{"", "web0", "keep01", "WEB01x"} {
		p = b.post("/admin/hosts/web01/delete", url.Values{"csrf_token": {tok}, "confirm": {bad}})
		if p.status != 400 || e.count(`SELECT count(*) FROM hosts WHERE name='web01'`) != 1 {
			t.Fatalf("delete with confirm %q: %d, host gone: %v", bad, p.status, e.count(`SELECT count(*) FROM hosts WHERE name='web01'`) != 1)
		}
	}
	p = b.post("/admin/hosts/web01/delete", url.Values{"csrf_token": {tok}, "confirm": {"Web01"}})
	if p.status != 303 {
		t.Fatalf("delete: %d", p.status)
	}
	if e.count(`SELECT count(*) FROM hosts WHERE name='web01'`) != 0 || e.count(`SELECT count(*) FROM hosts WHERE name='keep01'`) != 1 {
		t.Fatal("delete removed the wrong host or none")
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='host.delete' AND target='web01' AND actor_kind='user'`); n != 1 {
		t.Fatalf("%d host.delete audit rows", n)
	}
	for _, a := range []string{"host.token.rotate", "host.token.revoke"} {
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action=? AND actor_kind='user' AND actor='adm@example.com'`, a); n != 1 {
			t.Errorf("%d %s audit rows by the user", n, a)
		}
	}
	// Unknown host: 404, for every action.
	for _, act := range []string{"rotate-token", "revoke-token", "delete"} {
		if p := b.post("/admin/hosts/ghost/"+act, url.Values{"csrf_token": {tok}, "confirm": {"ghost"}}); p.status != 404 {
			t.Errorf("%s on an unknown host: %d", act, p.status)
		}
	}
}

func reportStatus(t *testing.T, e *env, token string) int {
	t.Helper()
	p := e.browser().do("POST", "/v1/report", map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}, nil)
	// An empty body is a 400 for a valid token and 401 for a bad one; send a real report for the 202.
	if p.status == 400 {
		postReport(t, e, token, nil)
		return 202
	}
	return p.status
}

func TestAdminPagesAreForAdminsOnly(t *testing.T) {
	e := newEnv(t)
	e.addUser("view@example.com", "viewer", goodPW, false)
	registerHost(t, e, "web01")
	b := e.browser()
	b.login("view@example.com", goodPW)
	home := b.get("/")
	if strings.Contains(home.body, "nav-admin") || strings.Contains(home.body, "/admin/hosts") {
		t.Error("a viewer sees the Hosts link")
	}
	if p := b.get("/admin/hosts"); p.status != 403 || !strings.Contains(p.body, `data-testid="error-page"`) {
		t.Errorf("viewer GET /admin/hosts: %d", p.status)
	}
	host := b.get("/hosts/web01")
	for _, forbidden := range []string{"rotate-token", "revoke-token", "/delete", "host-actions"} {
		if strings.Contains(host.body, forbidden) {
			t.Errorf("the host page of a viewer contains %q", forbidden)
		}
	}
	// With a valid viewer CSRF token the POST is still refused and nothing changes.
	vt := csrf(t, home)
	before := e.count(`SELECT count(*) FROM hosts`) + e.count(`SELECT count(*) FROM audit_log`)
	for _, c := range []struct {
		path string
		form url.Values
	}{
		{"/admin/hosts", url.Values{"csrf_token": {vt}, "name": {"intruder"}}},
		{"/admin/hosts/web01/rotate-token", url.Values{"csrf_token": {vt}}},
		{"/admin/hosts/web01/revoke-token", url.Values{"csrf_token": {vt}}},
		{"/admin/hosts/web01/delete", url.Values{"csrf_token": {vt}, "confirm": {"web01"}}},
	} {
		if p := b.post(c.path, c.form); p.status != 403 {
			t.Errorf("viewer POST %s: %d, want 403", c.path, p.status)
		}
	}
	if after := e.count(`SELECT count(*) FROM hosts`) + e.count(`SELECT count(*) FROM audit_log`); after != before {
		t.Errorf("a viewer's POST changed the database (%d -> %d rows)", before, after)
	}
}

func TestHostPageShowsActionsToAdmins(t *testing.T) {
	e := newEnv(t)
	b, _ := adminBrowser(t, e)
	registerHost(t, e, "web01")
	p := b.get("/hosts/web01")
	for _, want := range []string{`data-testid="host-actions-web01"`, `/admin/hosts/web01/rotate-token`, `/admin/hosts/web01/delete`, `data-testid="delete-confirm-web01"`} {
		if !strings.Contains(p.body, want) {
			t.Errorf("admin host page lacks %q", want)
		}
	}
}
