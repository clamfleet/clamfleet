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
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	sp.Role, sp.Email, sp.MustChange = role, "u@example.com", mustChange
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
