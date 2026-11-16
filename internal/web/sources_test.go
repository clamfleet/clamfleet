// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package web_test

import (
	"database/sql"
	"net/http"
	"net/url"
	"testing"

	"github.com/clamfleet/clamfleet/internal/server"
)

// rawWrite runs one statement on the test database through a second connection, to put the
// store into a state no code path of this build can produce (a source nobody has heard of).
func rawWrite(t *testing.T, e *env, query string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+e.dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

// carry returns a browser of server e2 that holds the session cookie of b (a restart with new settings).
func carry(t *testing.T, e, e2 *env, b *browser) *browser {
	t.Helper()
	nb := e2.browser()
	u, _ := url.Parse(e.srv.URL)
	nb.c.Jar.SetCookies(mustURL(e2.srv.URL), b.c.Jar.Cookies(u))
	return nb
}

// Plan 6.3 (the gate and sources, through the real router): a session whose user has a source this
// build does not know is no session (303 to /login), and so is a local session once
// auth.local.enabled is switched off. Decision 21; the second is an M3 behaviour change, in the CHANGELOG.
func TestSessionOfAnUnknownOrSwitchedOffSourceIsNoSession(t *testing.T) {
	e := newEnv(t)
	e.addUser("ann@example.com", "admin", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW)
	if p := b.get("/"); p.status != 200 {
		t.Fatalf("signed in: %d", p.status)
	}

	// Local sessions end when auth.local.enabled is switched off (a restart with the new setting).
	e2 := e.another(console(func(a *server.Auth) { a.Local.Enabled = false }))
	if p := carry(t, e, e2, b).get("/"); p.status != http.StatusSeeOther || p.header.Get("Location") != "/login" {
		t.Fatalf("local session with auth.local.enabled: false: %d %q, want 303 to /login", p.status, p.header.Get("Location"))
	}

	// The user's source changes to one this build has never heard of ("saml"): its session is gone too,
	// with TOTP not even asked about.
	rawWrite(t, e, `UPDATE users SET auth_source='saml' WHERE email='ann@example.com'`)
	if p := b.get("/"); p.status != http.StatusSeeOther || p.header.Get("Location") != "/login" {
		t.Fatalf("saml session: %d %q, want 303 to /login", p.status, p.header.Get("Location"))
	}
	if p := b.get("/admin/hosts"); p.status != http.StatusSeeOther {
		t.Fatalf("saml session on an admin page: %d", p.status)
	}
}
