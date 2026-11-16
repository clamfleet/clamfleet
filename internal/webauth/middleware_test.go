// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package webauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

// fakeSessions is an in-memory SessionStore keyed by token hash.
type fakeSessions struct {
	byHash map[string]store.SessionPrincipal
	err    error
	touch  int
}

func (f *fakeSessions) CreateSession(_ context.Context, s store.Session) error {
	f.byHash[string(s.TokenHash)] = store.SessionPrincipal{SessionID: 1, UserID: s.UserID, CSRF: s.CSRF}
	return nil
}

func (f *fakeSessions) SessionByTokenHash(_ context.Context, h []byte, _ time.Time, _ time.Duration) (store.SessionPrincipal, error) {
	if f.err != nil {
		return store.SessionPrincipal{}, f.err
	}
	p, ok := f.byHash[string(h)]
	if !ok {
		return store.SessionPrincipal{}, store.ErrNotFound
	}
	return p, nil
}
func (f *fakeSessions) TouchSession(context.Context, int64, time.Time) error { f.touch++; return nil }
func (f *fakeSessions) DeleteSession(_ context.Context, h []byte) error {
	delete(f.byHash, string(h))
	return nil
}

var clk = time.Date(2031, 1, 1, 12, 0, 0, 0, time.UTC)

func newMgr(f *fakeSessions) *Manager {
	return &Manager{
		Store: f, Now: func() time.Time { return clk }, MaxAge: 12 * time.Hour, Idle: time.Hour, Secure: true,
		Sources: map[string]bool{store.AuthLocal: true, store.AuthLDAP: true, store.AuthOIDC: true},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// signedIn registers a session with the given role and returns its cookie and principal.
func signedIn(t *testing.T, f *fakeSessions, m *Manager, role string, mustChange bool) (*http.Cookie, Principal) {
	t.Helper()
	tok, err := m.Create(context.Background(), 7, "h", 0)
	if err != nil {
		t.Fatal(err)
	}
	h := string(HashToken(tok))
	sp := f.byHash[h]
	sp.Role, sp.Email, sp.MustChange, sp.AuthSource = role, "u@example.com", mustChange, store.AuthLocal
	f.byHash[h] = sp
	return NewCookie(tok, true), Principal{csrf: sp.CSRF}
}

func do(h http.Handler, method, target string, c *http.Cookie, hdr map[string]string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c != nil {
		r.AddCookie(c)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

var ok200 = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	w.Write([]byte("hello " + p.Email))
})

func TestRequireUserWithoutSession(t *testing.T) {
	f := &fakeSessions{byHash: map[string]store.SessionPrincipal{}}
	h := newMgr(f).RequireUser(ok200)
	if w := do(h, "GET", "/hosts/web01?x=1", nil, nil, ""); w.Code != 303 || w.Header().Get("Location") != "/login?next="+url.QueryEscape("/hosts/web01?x=1") {
		t.Fatalf("GET: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := do(h, "GET", "/", nil, nil, ""); w.Code != 303 || w.Header().Get("Location") != "/login" {
		t.Fatalf("GET /: %d %q", w.Code, w.Header().Get("Location"))
	}
	w := do(h, "GET", "/fleet/rows", nil, map[string]string{"HX-Request": "true"}, "")
	if w.Code != 401 || w.Header().Get("HX-Redirect") != "/login" {
		t.Fatalf("htmx: %d %v", w.Code, w.Header())
	}
	if w := do(h, "POST", "/x", nil, nil, "a=b"); w.Code != 401 {
		t.Fatalf("POST: %d", w.Code)
	}
	// Garbage, an unknown token and a bearer agent token are all "no session".
	for name, c := range map[string]*http.Cookie{
		"garbage":           {Name: CookieNameSecure, Value: "nonsense"},
		"unknown":           NewCookie("cfs_"+strings.Repeat("A", 43), true),
		"wrong cookie name": {Name: CookieNamePlain, Value: "cfs_" + strings.Repeat("A", 43)},
	} {
		if w := do(h, "GET", "/", c, nil, ""); w.Code != 303 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if w := do(h, "GET", "/", nil, map[string]string{"Authorization": "Bearer cfa_" + strings.Repeat("A", 43)}, ""); w.Code != 303 {
		t.Fatalf("an agent bearer token opened a UI route: %d", w.Code)
	}
}

func TestRequireUserStoreFailureIs503NotRedirect(t *testing.T) {
	f := &fakeSessions{byHash: map[string]store.SessionPrincipal{}}
	m := newMgr(f)
	c, _ := signedIn(t, f, m, "viewer", false)
	f.err = errors.New("db down")
	if w := do(m.RequireUser(ok200), "GET", "/", c, nil, ""); w.Code != 503 {
		t.Fatalf("%d, want 503 (a database error must not look like a logout)", w.Code)
	}
}

func TestRequireUserAndAdmin(t *testing.T) {
	f := &fakeSessions{byHash: map[string]store.SessionPrincipal{}}
	m := newMgr(f)
	viewer, _ := signedIn(t, f, m, "viewer", false)
	admin, _ := signedIn(t, f, m, "admin", false)
	if w := do(m.RequireUser(ok200), "GET", "/", viewer, nil, ""); w.Code != 200 || w.Body.String() != "hello u@example.com" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	adm := m.RequireAdmin(ok200)
	if w := do(adm, "GET", "/admin/hosts", viewer, nil, ""); w.Code != 403 {
		t.Fatalf("viewer on admin: %d", w.Code)
	}
	if w := do(adm, "GET", "/admin/hosts", admin, nil, ""); w.Code != 200 {
		t.Fatalf("admin on admin: %d", w.Code)
	}
	if w := do(adm, "GET", "/admin/hosts", nil, nil, ""); w.Code != 303 {
		t.Fatalf("anonymous on admin: %d", w.Code)
	}
}

func TestMustChangePasswordIsEnforced(t *testing.T) {
	f := &fakeSessions{byHash: map[string]store.SessionPrincipal{}}
	m := newMgr(f)
	c, _ := signedIn(t, f, m, "admin", true)
	h := m.RequireUser(ok200)
	if w := do(h, "GET", "/", c, nil, ""); w.Code != 303 || w.Header().Get("Location") != "/account" {
		t.Fatalf("GET /: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := do(h, "GET", "/hosts/web01", c, nil, ""); w.Code != 303 {
		t.Fatalf("GET host: %d", w.Code)
	}
	if w := do(h, "POST", "/admin/hosts", c, nil, "a=b"); w.Code != 403 {
		t.Fatalf("POST: %d", w.Code)
	}
	if w := do(h, "GET", "/fleet/rows", c, map[string]string{"HX-Request": "true"}, ""); w.Code != 403 || w.Header().Get("HX-Redirect") != "/account" {
		t.Fatalf("htmx: %d %v", w.Code, w.Header())
	}
	for _, p := range []string{"/account", "/account/password", "/logout"} {
		if w := do(h, "GET", p, c, nil, ""); w.Code != 200 {
			t.Errorf("%s blocked while the password must change: %d", p, w.Code)
		}
	}
}

func TestCSRFTokenRequiredOnNonGet(t *testing.T) {
	f := &fakeSessions{byHash: map[string]store.SessionPrincipal{}}
	m := newMgr(f)
	c, p := signedIn(t, f, m, "admin", false)
	h := m.RequireUser(m.CSRF(ok200))
	valid := p.CSRFToken()
	other, _ := signedIn(t, f, m, "admin", false)
	_ = other
	foreign := Principal{csrf: bytes.Repeat([]byte{1}, 32)}.CSRFToken()

	if w := do(h, "GET", "/", c, nil, ""); w.Code != 200 {
		t.Fatalf("GET needs no token: %d", w.Code)
	}
	form := func(tok string) string { return url.Values{CSRFField: {tok}, "x": {"1"}}.Encode() }
	cases := []struct {
		name string
		hdr  map[string]string
		body string
		want int
	}{
		{"no token", nil, "x=1", 403},
		{"empty token", nil, form(""), 403},
		{"wrong token", nil, form(foreign), 403},
		{"valid form field", nil, form(valid), 200},
		{"valid header", map[string]string{CSRFHeader: valid}, "x=1", 200},
		{"wrong header, right field", map[string]string{CSRFHeader: foreign}, form(valid), 403},
		{"token in the query string only", nil, "x=1", 403},
	}
	for _, tc := range cases {
		target := "/x"
		if tc.name == "token in the query string only" {
			target += "?" + CSRFField + "=" + valid
		}
		if w := do(h, "POST", target, c, tc.hdr, tc.body); w.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, w.Code, tc.want)
		}
	}
	// DELETE and PUT are non-safe too.
	if w := do(h, "DELETE", "/x", c, nil, ""); w.Code != 403 {
		t.Errorf("DELETE without token: %d", w.Code)
	}
	// A route wired with CSRF but without RequireUser fails closed.
	if w := do(m.CSRF(ok200), "POST", "/x", nil, map[string]string{CSRFHeader: valid}, ""); w.Code != 403 {
		t.Errorf("CSRF without a principal: %d", w.Code)
	}
}

func TestCrossOriginProtection(t *testing.T) {
	m := newMgr(&fakeSessions{byHash: map[string]store.SessionPrincipal{}})
	h := m.CrossOrigin(ok200)
	post := func(hdr map[string]string) int { return do(h, "POST", "/login", nil, hdr, "a=b").Code }
	if c := post(map[string]string{"Sec-Fetch-Site": "cross-site"}); c != 403 {
		t.Errorf("cross-site POST: %d", c)
	}
	if c := post(map[string]string{"Sec-Fetch-Site": "same-site"}); c != 403 {
		t.Errorf("same-site (a sibling subdomain) POST: %d", c)
	}
	if c := post(map[string]string{"Origin": "https://evil.example"}); c != 403 {
		t.Errorf("foreign Origin POST: %d", c)
	}
	if c := post(map[string]string{"Sec-Fetch-Site": "same-origin"}); c != 200 {
		t.Errorf("same-origin POST: %d", c)
	}
	if c := post(nil); c != 200 {
		t.Errorf("non-browser POST: %d", c)
	}
	if w := do(h, "GET", "/", nil, map[string]string{"Sec-Fetch-Site": "cross-site"}, ""); w.Code != 200 {
		t.Errorf("cross-site GET (a safe method) refused: %d", w.Code)
	}
}

func TestCreateIssuesFreshTokenAndIgnoresRequestCookie(t *testing.T) {
	f := &fakeSessions{byHash: map[string]store.SessionPrincipal{}}
	m := newMgr(f)
	a, err := m.Create(context.Background(), 1, "h", 0)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := m.Create(context.Background(), 1, "h", 0)
	if a == b || ParseToken(a) != nil {
		t.Fatalf("tokens %q %q", a, b)
	}
	// The raw token is never what the store holds.
	for h := range f.byHash {
		if h == a || strings.Contains(h, a[4:]) {
			t.Fatal("the store received the raw token")
		}
	}
}

// Ordinary requests must not open a write transaction: a touch is only attempted
// when the last one is a minute old.
func TestTouchOnlyWhenTheLastOneIsOld(t *testing.T) {
	f := &fakeSessions{byHash: map[string]store.SessionPrincipal{}}
	m := newMgr(f)
	c, _ := signedIn(t, f, m, "viewer", false)
	h := string(HashToken(c.Value))
	set := func(lastSeen time.Time) {
		sp := f.byHash[h]
		sp.LastSeen = lastSeen
		f.byHash[h] = sp
	}
	h2 := m.RequireUser(ok200)
	for name, c2 := range map[string]struct {
		lastSeen time.Time
		touches  int
	}{
		"just seen":        {clk, 0},
		"59 s ago":         {clk.Add(-59 * time.Second), 0},
		"exactly a minute": {clk.Add(-time.Minute), 1},
		"an hour ago":      {clk.Add(-time.Hour), 1},
	} {
		set(c2.lastSeen)
		f.touch = 0
		if w := do(h2, "GET", "/", c, nil, ""); w.Code != 200 {
			t.Fatalf("%s: %d", name, w.Code)
		}
		if f.touch != c2.touches {
			t.Errorf("%s: %d touches, want %d", name, f.touch, c2.touches)
		}
	}
}

// signedInAs is signedIn with the fields the TOTP gate reads.
func signedInAs(t *testing.T, f *fakeSessions, m *Manager, source string, mustChange, totp bool) *http.Cookie {
	t.Helper()
	c, _ := signedIn(t, f, m, "viewer", mustChange)
	h := string(HashToken(c.Value))
	sp := f.byHash[h]
	sp.AuthSource, sp.TOTPEnabled = source, totp
	f.byHash[h] = sp
	return c
}

// Rule: with totp_required a local user without TOTP reaches only the enrolment
// pages and logout; the MustChange gate comes first; external users and users
// with TOTP are untouched; the gate is off when the setting is.
func TestTOTPEnrolmentGate(t *testing.T) {
	allowed := []string{"/account/totp", "/account/totp/setup", "/account/totp/confirm", "/logout"}
	blocked := []string{"/", "/fleet/rows", "/hosts/web01", "/admin/hosts", "/account", "/account/password", "/account/totp/disable", "/account/totp/recovery-codes", "/account/totp/", "/account/totp/setup/x"}
	f := &fakeSessions{byHash: map[string]store.SessionPrincipal{}}
	m := newMgr(f)
	m.TOTPRequired = true
	h := m.RequireUser(ok200)

	c := signedInAs(t, f, m, "local", false, false)
	for _, path := range allowed {
		if w := do(h, "GET", path, c, nil, ""); w.Code != 200 {
			t.Errorf("GET %s: %d, want 200 (it must stay reachable or the user is locked out of enrolling)", path, w.Code)
		}
	}
	for _, path := range blocked {
		w := do(h, "GET", path, c, nil, "")
		if w.Code != 303 || w.Header().Get("Location") != "/account/totp" {
			t.Errorf("GET %s: %d %q, want 303 to /account/totp", path, w.Code, w.Header().Get("Location"))
		}
		hx := do(h, "GET", path, c, map[string]string{"HX-Request": "true"}, "")
		if hx.Code != 403 || hx.Header().Get("HX-Redirect") != "/account/totp" {
			t.Errorf("htmx %s: %d %q", path, hx.Code, hx.Header().Get("HX-Redirect"))
		}
		if post := do(h, "POST", path, c, nil, "a=b"); post.Code != 403 {
			t.Errorf("POST %s: %d, want 403", path, post.Code)
		}
	}
	// Not gated: users with TOTP, external users, and everyone when the setting is off.
	if w := do(h, "GET", "/", signedInAs(t, f, m, "local", false, true), nil, ""); w.Code != 200 {
		t.Errorf("a user with TOTP: %d", w.Code)
	}
	for _, src := range []string{"ldap", "oidc"} {
		if w := do(h, "GET", "/", signedInAs(t, f, m, src, false, false), nil, ""); w.Code != 200 {
			t.Errorf("a %s user is gated although the provider owns the second factor: %d", src, w.Code)
		}
	}
	off := newMgr(f)
	if w := do(off.RequireUser(ok200), "GET", "/", signedInAs(t, f, off, "local", false, false), nil, ""); w.Code != 200 {
		t.Errorf("the gate is on although totp_required is off: %d", w.Code)
	}
	// MustChange first: the password page, not the enrolment page, until it is changed.
	mc := signedInAs(t, f, m, "local", true, false)
	if w := do(h, "GET", "/", mc, nil, ""); w.Code != 303 || w.Header().Get("Location") != "/account" {
		t.Errorf("must-change + required: %d %q, want 303 to /account", w.Code, w.Header().Get("Location"))
	}
	if w := do(h, "GET", "/account/totp", mc, nil, ""); w.Code != 303 || w.Header().Get("Location") != "/account" {
		t.Errorf("enrolment page before the password change: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := do(h, "GET", "/account", mc, nil, ""); w.Code != 200 {
		t.Errorf("the password page must stay reachable: %d", w.Code)
	}
}

// Rule (M6 decision 21): the exempt list is explicit. A source that is not on it is GATED, so a source
// a later milestone adds ("saml") fails safe. The session check below is the first line; this test
// opens it (Sources lists saml) to prove the second line holds on its own.
func TestTOTPGateGatesAnUnknownSource(t *testing.T) {
	f := &fakeSessions{byHash: map[string]store.SessionPrincipal{}}
	m := newMgr(f)
	m.TOTPRequired = true
	m.Sources["saml"] = true
	h := m.RequireUser(ok200)
	c := signedInAs(t, f, m, "saml", false, false)
	if w := do(h, "GET", "/", c, nil, ""); w.Code != 303 || w.Header().Get("Location") != "/account/totp" {
		t.Fatalf("an unknown source without TOTP: %d %q, want 303 to /account/totp", w.Code, w.Header().Get("Location"))
	}
	if w := do(h, "GET", "/", signedInAs(t, f, m, "saml", false, true), nil, ""); w.Code != 200 {
		t.Fatalf("an unknown source with TOTP enrolled must pass: %d", w.Code)
	}
}

// Rule: a session whose user's source is unknown, or switched off since, is no session at all
// (303 to /login), whatever else the user is entitled to.
func TestSessionOfASourceThatIsNotEnabledIsNoSession(t *testing.T) {
	f := &fakeSessions{byHash: map[string]store.SessionPrincipal{}}
	m := newMgr(f)
	h := m.RequireUser(ok200)
	saml := signedInAs(t, f, m, "saml", false, true) // unknown to this build, even with TOTP
	if w := do(h, "GET", "/", saml, nil, ""); w.Code != 303 || w.Header().Get("Location") != "/login" {
		t.Fatalf("an unknown source: %d %q, want 303 to /login", w.Code, w.Header().Get("Location"))
	}
	oidc := signedInAs(t, f, m, "oidc", false, false)
	if w := do(h, "GET", "/", oidc, nil, ""); w.Code != 200 {
		t.Fatalf("oidc while enabled: %d", w.Code)
	}
	m.Sources["oidc"] = false // auth.oidc.enabled switched off
	if w := do(h, "GET", "/", oidc, nil, ""); w.Code != 303 {
		t.Fatalf("oidc after it was switched off: %d, want no session", w.Code)
	}
	local := signedInAs(t, f, m, "local", false, false)
	m.Sources["local"] = false // auth.local.enabled: false ends local sessions too (an M3 behaviour change)
	if w := do(h, "GET", "/", local, nil, ""); w.Code != 303 {
		t.Fatalf("local after auth.local.enabled: false: %d, want no session", w.Code)
	}
	// Fail closed: a Manager that was never told which sources are on accepts no session.
	bare := newMgr(f)
	bare.Sources = nil
	if w := do(bare.RequireUser(ok200), "GET", "/", signedInAs(t, f, bare, "local", false, false), nil, ""); w.Code != 303 {
		t.Fatalf("no Sources configured: %d, want no session", w.Code)
	}
}

// The refusal is logged once per user and hour, not once per request.
func TestSourceRefusalIsLoggedOncePerUserPerHour(t *testing.T) {
	f := &fakeSessions{byHash: map[string]store.SessionPrincipal{}}
	var logs bytes.Buffer
	now := clk
	m := newMgr(f)
	m.Now = func() time.Time { return now }
	m.Log = slog.New(slog.NewTextHandler(&logs, nil))
	h := m.RequireUser(ok200)
	c := signedInAs(t, f, m, "saml", false, false)
	for i := 0; i < 5; i++ {
		do(h, "GET", "/", c, nil, "")
	}
	if n := strings.Count(logs.String(), "session refused"); n != 1 {
		t.Fatalf("%d warnings in one hour, want 1:\n%s", n, logs.String())
	}
	now = now.Add(61 * time.Minute)
	do(h, "GET", "/", c, nil, "")
	if n := strings.Count(logs.String(), "session refused"); n != 2 {
		t.Fatalf("%d warnings after an hour, want 2", n)
	}
}

// Plan 6.3: the gate compares r.URL.Path exactly. Alternate spellings and other methods of the
// enrolment paths never reach a handler that is not on the list: each is a gate redirect or 403.
// (Go's mux cleans or redirects most of these before any handler; this pins the gate on its own.)
func TestTOTPGateDoesNotMatchAlternateSpellings(t *testing.T) {
	f := &fakeSessions{byHash: map[string]store.SessionPrincipal{}}
	m := newMgr(f)
	m.TOTPRequired = true
	reached := false
	h := m.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	c := signedInAs(t, f, m, "local", false, false)
	for _, path := range []string{"/account/totp/", "/account//totp", "/ACCOUNT/totp", "/account/totp/../../events", "/account/totp/setup/", "/Account/Totp"} {
		reached = false
		do(h, "GET", path, c, nil, "")
		if reached {
			t.Errorf("GET %s reached the handler of a gated user", path)
		}
	}
	// The allowed paths with another method are still only as allowed as the router makes them:
	// the gate lets the path through (the mux answers 405), which is no handler of ours.
	// What must hold is that a non-allowed path is not opened by a method.
	for _, method := range []string{"HEAD", "PUT", "DELETE", "POST"} {
		reached = false
		do(h, method, "/account/password", c, nil, "a=b")
		if reached {
			t.Errorf("%s /account/password reached the handler of a gated user", method)
		}
	}
}
