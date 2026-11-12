// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// These tests go through the real router: an httptest TLS server around
// server.NewHandler, a real http.Client with a cookie jar, real SQLite, an
// injected clock and a log buffer. TLS, because the production cookie is
// Secure and __Host- prefixed and a plain-HTTP client would never send it back:
// the tests see exactly what a browser sees. A test that called a handler
// directly could not notice an unmounted route or a missing middleware (a
// release once shipped with a 404 on a button that way).
package web_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/health"
	"github.com/clamfleet/clamfleet/internal/server"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

// t0 is the injected server clock. It is far from the real date on purpose:
// anything stamped from the wall clock instead would be visibly wrong.
var t0 = time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// countingHasher wraps the real hasher and counts how often it is used.
type countingHasher struct {
	*webauth.Hasher
	verifies, dummies, hashes atomic.Int32
	// gate, when set, makes Verify and VerifyDummy block until it is closed.
	gate chan struct{}
}

func (c *countingHasher) Verify(ctx context.Context, pw, phc string) (bool, bool, error) {
	c.verifies.Add(1)
	if c.gate != nil {
		<-c.gate
	}
	return c.Hasher.Verify(ctx, pw, phc)
}

func (c *countingHasher) VerifyDummy(ctx context.Context, pw string) error {
	c.dummies.Add(1)
	if c.gate != nil {
		<-c.gate
	}
	return c.Hasher.VerifyDummy(ctx, pw)
}

func (c *countingHasher) Hash(ctx context.Context, pw string) (string, error) {
	c.hashes.Add(1)
	return c.Hasher.Hash(ctx, pw)
}

type env struct {
	t      *testing.T
	srv    *httptest.Server
	st     *sqlite.Store
	dbPath string
	logs   *syncBuf
	hasher *countingHasher

	mu  sync.Mutex
	now time.Time
}

func (e *env) clock() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now }
func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	e.now = e.now.Add(d)
	e.mu.Unlock()
}

type opt func(*server.Deps)

func newEnv(t *testing.T, opts ...opt) *env { return newEnvAt(t, t0, opts...) }

// newEnvAt starts the injected clock at the given time. Tests that post the
// golden agent report start it right after the report's own timestamp, so the
// signatures are fresh and the baseline state is not CRIT.
func newEnvAt(t *testing.T, at time.Time, opts ...opt) *env {
	t.Helper()
	path := filepath.Join(t.TempDir(), "web.db")
	ctx := context.Background()
	st, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, st: st, dbPath: path, logs: &syncBuf{}, now: at, hasher: &countingHasher{Hasher: webauth.NewHasher()}}
	log := slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	d := server.Deps{Store: st, Now: e.clock, Log: log, Hasher: e.hasher, Version: "9.9.9-test"}
	// The evaluator runs after every accepted report, as in the real binary.
	ev := health.New(st, e.clock, server.DefaultConfig().Health.Thresholds(), log)
	d.AfterReport = ev.Host
	for _, o := range opts {
		o(&d)
	}
	h := server.NewHandler(d)
	if d.Console.Local.Enabled && !d.Console.CookieSecure {
		e.srv = httptest.NewServer(h) // development mode: plain HTTP
	} else {
		e.srv = httptest.NewTLSServer(h)
	}
	t.Cleanup(func() { e.srv.Close(); st.Close() })
	return e
}

// console returns Deps.Console settings with the defaults, adjusted by mut.
func console(mut func(a *server.Auth)) opt {
	return func(d *server.Deps) {
		d.Console = server.DefaultConfig().Auth
		if mut != nil {
			mut(&d.Console)
		}
	}
}

const goodPW = "correct horse battery staple"

var cliAudit = store.Audit{Kind: store.ActorCLI, Actor: "test"}

func (e *env) addUser(email, role, password string, mustChange bool) store.User {
	e.t.Helper()
	hash, err := webauth.NewHasher().Hash(context.Background(), password)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := e.st.CreateUser(context.Background(), store.NewUser{Email: email, Role: role, PasswordHash: hash, MustChange: mustChange}, e.clock(), cliAudit)
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

// browser is an http.Client with a cookie jar that does not follow redirects,
// so tests see every 303.
type browser struct {
	t *testing.T
	e *env
	c *http.Client
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{
		Transport: e.srv.Client().Transport, Jar: jar, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &browser{t: e.t, e: e, c: c}
}

type page struct {
	status int
	body   string
	header http.Header
}

func (b *browser) do(method, path string, hdr map[string]string, form url.Values) page {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, b.e.srv.URL+path, body)
	if err != nil {
		b.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return page{resp.StatusCode, string(raw), resp.Header}
}

func (b *browser) get(path string) page { return b.do("GET", path, nil, nil) }

// post sends a same-origin form POST, as a browser would (Sec-Fetch-Site).
func (b *browser) post(path string, form url.Values) page {
	return b.do("POST", path, map[string]string{"Sec-Fetch-Site": "same-origin"}, form)
}

var csrfRE = regexp.MustCompile(`<meta name="csrf-token" content="([^"]+)">`)

// csrf reads the token from a page, like the viewer e2e test does.
func csrf(t *testing.T, p page) string {
	t.Helper()
	m := csrfRE.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no csrf meta tag in page (status %d):\n%s", p.status, p.body)
	}
	return m[1]
}

// login signs in and fails the test if it does not work.
func (b *browser) login(email, password string) {
	b.t.Helper()
	p := b.post("/login", url.Values{"email": {email}, "password": {password}})
	if p.status != 303 {
		b.t.Fatalf("login %s: status %d\n%s", email, p.status, p.body)
	}
}

func (e *env) cookieFor(b *browser) *http.Cookie {
	u, _ := url.Parse(e.srv.URL)
	for _, c := range b.c.Jar.Cookies(u) {
		if strings.HasSuffix(c.Name, "clamfleet_session") {
			return c
		}
	}
	return nil
}

func (e *env) count(query string, args ...any) int {
	e.t.Helper()
	raw, err := openRaw(e.dbPath)
	if err != nil {
		e.t.Fatal(err)
	}
	defer raw.Close()
	var n int
	if err := raw.QueryRow(query, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func TestLoginFlowThroughRouter(t *testing.T) {
	e := newEnv(t)
	registerHost(t, e, "web01")
	e.addUser("ann@example.com", "admin", goodPW, false)
	b := e.browser()

	if p := b.get("/login"); p.status != 200 || !strings.Contains(p.body, `data-testid="login-form"`) {
		t.Fatalf("GET /login: %d", p.status)
	}
	// A wrong password: 200, the generic text, no session cookie, an audit row.
	p := b.post("/login", url.Values{"email": {"ann@example.com"}, "password": {"wrong wrong wrong wrong"}})
	if p.status != 200 || !strings.Contains(p.body, "Invalid email or password.") || p.header.Get("Set-Cookie") != "" {
		t.Fatalf("wrong password: %d, cookie %q", p.status, p.header.Get("Set-Cookie"))
	}
	if e.cookieFor(b) != nil {
		t.Fatal("a session cookie was set by a failed login")
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.login.failed' AND target='ann@example.com'`); n != 1 {
		t.Fatalf("%d user.login.failed rows, want 1", n)
	}
	// The right one: 303 to /, a cookie with every flag.
	p = b.post("/login", url.Values{"email": {"Ann@Example.com"}, "password": {goodPW}})
	if p.status != 303 || p.header.Get("Location") != "/" {
		t.Fatalf("login: %d -> %q", p.status, p.header.Get("Location"))
	}
	sc := p.header.Get("Set-Cookie")
	for _, want := range []string{"__Host-clamfleet_session=cfs_", "HttpOnly", "Secure", "SameSite=Lax", "Path=/"} {
		if !strings.Contains(sc, want) {
			t.Errorf("Set-Cookie %q lacks %q", sc, want)
		}
	}
	if strings.Contains(sc, "Max-Age") || strings.Contains(sc, "Expires") || strings.Contains(sc, "Domain") {
		t.Errorf("Set-Cookie %q must be a host-only session cookie", sc)
	}
	if p := b.get("/"); p.status != 200 || !strings.Contains(p.body, `data-testid="fleet-row-web01"`) {
		t.Fatalf("GET /: %d (the fleet page must list the host)", p.status)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.login' AND actor='ann@example.com' AND actor_kind='user' AND detail LIKE '%127.0.0.1%'`); n != 1 {
		t.Fatalf("%d user.login rows with the client IP, want 1", n)
	}
	// A signed-in user visiting /login is sent on.
	if p := b.get("/login?next=/account"); p.status != 303 || p.header.Get("Location") != "/account" {
		t.Fatalf("GET /login while signed in: %d %q", p.status, p.header.Get("Location"))
	}
}

func TestLoginFailureIsTheSameForEveryCause(t *testing.T) {
	e := newEnv(t)
	e.addUser("ann@example.com", "viewer", goodPW, false)
	off := e.addUser("off@example.com", "viewer", goodPW, false)
	if err := e.st.SetDisabled(context.Background(), off.ID, true, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	// An external-style account without a local password.
	if _, err := e.st.CreateUser(context.Background(), store.NewUser{Email: "nopw@example.com", Role: "viewer"}, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	var bodies []string
	for _, c := range []struct{ email, pw, reason string }{
		{"ann@example.com", "not the password at all", "bad password"},
		{"ghost@example.com", goodPW, "unknown user"},
		{"off@example.com", goodPW, "user disabled"},
		{"nopw@example.com", goodPW, "no local password"},
		{"not-an-email", goodPW, "unknown user"},
		{"ann@example.com", strings.Repeat("x", 300), "bad password"},
	} {
		before := e.hasher.verifies.Load() + e.hasher.dummies.Load()
		p := e.browser().post("/login", url.Values{"email": {c.email}, "password": {c.pw}})
		if p.status != 200 || !strings.Contains(p.body, "Invalid email or password.") {
			t.Fatalf("%s: %d", c.reason, p.status)
		}
		if got := e.hasher.verifies.Load() + e.hasher.dummies.Load() - before; got != 1 {
			t.Errorf("%s: %d hash verifications, want exactly 1 (no timing oracle)", c.reason, got)
		}
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.login.failed' AND detail LIKE ?`, "%"+c.reason+"%"); n == 0 {
			t.Errorf("no audit row with reason %q", c.reason)
		}
		bodies = append(bodies, stripVolatile(p.body))
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Errorf("response %d differs from response 0: the page leaks the cause", i)
		}
	}
	// Failures are logged with the client IP and without the typed email.
	logs := e.logs.String()
	if !strings.Contains(logs, `"msg":"login failed"`) || !strings.Contains(logs, `"client_ip":"127.0.0.1"`) {
		t.Fatalf("no login-failed log line with the IP:\n%s", logs)
	}
	if strings.Contains(logs, "ghost@example.com") {
		t.Fatal("a typed email reached the log stream (it belongs in the audit row only)")
	}
}

// stripVolatile removes the per-rendering CSRF-free parts: the login page has none, but keep it explicit.
func stripVolatile(s string) string { return s }

func TestLoginThrottleRefusesBeforeHashing(t *testing.T) {
	e := newEnv(t)
	e.addUser("ann@example.com", "viewer", goodPW, false)
	bad := url.Values{"email": {"ann@example.com"}, "password": {"wrong wrong wrong wrong"}}
	for i := 0; i < 5; i++ {
		if p := e.browser().post("/login", bad); p.status != 200 {
			t.Fatalf("failure %d: %d", i+1, p.status)
		}
	}
	hashed := e.hasher.verifies.Load() + e.hasher.dummies.Load()
	// Now even the RIGHT password is refused, without any hashing.
	p := e.browser().post("/login", url.Values{"email": {"ann@example.com"}, "password": {goodPW}})
	if p.status != 429 || p.header.Get("Retry-After") == "" || !strings.Contains(p.body, "Too many failed attempts") {
		t.Fatalf("throttled login: %d retry-after %q", p.status, p.header.Get("Retry-After"))
	}
	if e.hasher.verifies.Load()+e.hasher.dummies.Load() != hashed {
		t.Fatal("a throttled attempt still cost a hash")
	}
	// An unknown email is throttled the same way (no oracle).
	for i := 0; i < 5; i++ {
		e.browser().post("/login", url.Values{"email": {"ghost@example.com"}, "password": {"x"}})
	}
	if p := e.browser().post("/login", url.Values{"email": {"ghost@example.com"}, "password": {"x"}}); p.status != 429 {
		t.Fatalf("unknown email after 5 failures: %d", p.status)
	}
	// After the delay the right password works again and resets the counter.
	e.advance(31 * time.Second)
	if p := e.browser().post("/login", url.Values{"email": {"ann@example.com"}, "password": {goodPW}}); p.status != 303 {
		t.Fatalf("after the delay: %d", p.status)
	}
}

func TestSessionFixationPreLoginCookieIsReplaced(t *testing.T) {
	e := newEnv(t)
	e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW)
	first := e.cookieFor(b).Value

	// Log in again from a browser that already holds a session cookie: the
	// presented token must neither be reused nor stay valid.
	p := b.post("/login", url.Values{"email": {"ann@example.com"}, "password": {goodPW}})
	if p.status != 303 {
		t.Fatalf("second login: %d", p.status)
	}
	second := e.cookieFor(b).Value
	if first == second {
		t.Fatal("the session token was reused at login (session fixation)")
	}
	other := e.browser()
	u, _ := url.Parse(e.srv.URL)
	other.c.Jar.SetCookies(u, []*http.Cookie{webauth.NewCookie(first, true)})
	if p := other.get("/"); p.status != 303 {
		t.Fatalf("the pre-login session still works: %d", p.status)
	}
	// A cookie value the attacker chose (never issued) is not adopted either.
	planted := "cfs_" + strings.Repeat("A", 43)
	c := e.browser()
	c.c.Jar.SetCookies(u, []*http.Cookie{webauth.NewCookie(planted, true)})
	c.login("ann@example.com", goodPW)
	if got := e.cookieFor(c).Value; got == planted {
		t.Fatal("a planted cookie value became the session")
	}
}

func TestSessionTokenIsNotStoredInClear(t *testing.T) {
	e := newEnv(t)
	e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW)
	tok := e.cookieFor(b).Value
	var all []byte
	for _, suf := range []string{"", "-wal"} {
		if raw, err := os.ReadFile(e.dbPath + suf); err == nil {
			all = append(all, raw...)
		}
	}
	if bytes.Contains(all, []byte(tok)) || bytes.Contains(all, []byte(tok[4:])) {
		t.Fatal("the raw session token is in the database file")
	}
	if strings.Contains(e.logs.String(), tok[4:]) {
		t.Fatal("the session token is in the log")
	}
}

func TestSessionLifetime(t *testing.T) {
	e := newEnv(t)
	e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW)

	// Activity keeps an idle session alive, up to the absolute limit.
	for i := 0; i < 14; i++ {
		e.advance(50 * time.Minute)
		if p := b.get("/"); p.status != 200 {
			t.Fatalf("active session dead after %d x 50 min: %d", i+1, p.status)
		}
	}
	e.advance(50 * time.Minute) // 12h 30min in: past the absolute limit although active
	if p := b.get("/"); p.status != 303 {
		t.Fatalf("absolute limit not enforced: %d", p.status)
	}

	// Idle: one hour without a request ends it.
	b2 := e.browser()
	b2.login("ann@example.com", goodPW)
	e.advance(59 * time.Minute)
	if p := b2.get("/"); p.status != 200 {
		t.Fatalf("59 min idle: %d", p.status)
	}
	e.advance(61 * time.Minute)
	if p := b2.get("/"); p.status != 303 {
		t.Fatalf("61 min idle: %d", p.status)
	}

}

// Disable, role change and reset take effect on the very next request: the
// router reads the session and its user from the store on every request.
func TestChangesApplyToTheNextRequest(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(e *env, u store.User){
		"disable": func(e *env, u store.User) { e.st.SetDisabled(ctx, u.ID, true, e.clock(), cliAudit) },
		"reset-password": func(e *env, u store.User) {
			e.st.SetPassword(ctx, u.ID, store.PasswordChange{Hash: "x"}, e.clock(), cliAudit)
		},
		"set-role": func(e *env, u store.User) { e.st.SetRole(ctx, u.ID, "admin", e.clock(), cliAudit) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			u := e.addUser("ann@example.com", "viewer", goodPW, false)
			b := e.browser()
			b.login("ann@example.com", goodPW)
			if p := b.get("/"); p.status != 200 {
				t.Fatalf("before the change: %d", p.status)
			}
			change(e, u)
			if p := b.get("/"); p.status != 303 {
				t.Fatalf("%s: the old session still works: %d", name, p.status)
			}
		})
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	e := newEnv(t)
	e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW)
	tok := e.cookieFor(b).Value
	tokenCopy := e.browser()
	u, _ := url.Parse(e.srv.URL)
	tokenCopy.c.Jar.SetCookies(u, []*http.Cookie{webauth.NewCookie(tok, true)})

	home := b.get("/")
	p := b.post("/logout", url.Values{"csrf_token": {csrf(t, home)}})
	if p.status != 303 || p.header.Get("Location") != "/login" {
		t.Fatalf("logout: %d %q", p.status, p.header.Get("Location"))
	}
	// "Back" shows the login page, and a copy of the old cookie is dead on the server.
	if p := b.get("/"); p.status != 303 {
		t.Fatalf("after logout GET /: %d", p.status)
	}
	if p := tokenCopy.get("/"); p.status != 303 {
		t.Fatalf("a copied cookie works after logout: %d", p.status)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.logout' AND actor='ann@example.com'`); n != 1 {
		t.Fatalf("%d logout audit rows", n)
	}
	if n := e.count(`SELECT count(*) FROM user_sessions`); n != 0 {
		t.Fatalf("%d session rows left", n)
	}
}

func TestMustChangePasswordFlow(t *testing.T) {
	e := newEnv(t)
	e.addUser("ann@example.com", "admin", "one-time-password-1", true)
	b := e.browser()
	p := b.post("/login", url.Values{"email": {"ann@example.com"}, "password": {"one-time-password-1"}})
	if p.status != 303 || p.header.Get("Location") != "/account" {
		t.Fatalf("login of a must-change user: %d %q", p.status, p.header.Get("Location"))
	}
	if p := b.get("/"); p.status != 303 || p.header.Get("Location") != "/account" {
		t.Fatalf("GET / while the password must change: %d %q", p.status, p.header.Get("Location"))
	}
	acct := b.get("/account")
	if acct.status != 200 || !strings.Contains(acct.body, `data-testid="must-change"`) {
		t.Fatalf("account page: %d", acct.status)
	}
	tok := csrf(t, acct)
	change := func(cur, n1, n2 string) page {
		return b.post("/account/password", url.Values{"csrf_token": {tok}, "current_password": {cur}, "new_password": {n1}, "new_password2": {n2}})
	}
	for name, c := range map[string]struct{ cur, n1, n2, want string }{
		"wrong current": {"nope-nope-nope-nope", "a-brand-new-password", "a-brand-new-password", "current password is not correct"},
		"mismatch":      {"one-time-password-1", "a-brand-new-password", "a-brand-new-passwordX", "do not match"},
		"too short":     {"one-time-password-1", "short", "short", "at least 15"},
		"same":          {"one-time-password-1", "one-time-password-1", "one-time-password-1", "different"},
	} {
		if p := change(c.cur, c.n1, c.n2); p.status != 200 || !strings.Contains(p.body, c.want) {
			t.Errorf("%s: %d, want a page saying %q", name, p.status, c.want)
		}
	}
	// A second browser with an older session of the same user ends when the password changes.
	older := e.browser()
	older.post("/login", url.Values{"email": {"ann@example.com"}, "password": {"one-time-password-1"}})

	if p := change("one-time-password-1", "a-brand-new-password", "a-brand-new-password"); p.status != 303 {
		t.Fatalf("valid change: %d\n%s", p.status, p.body)
	}
	if p := b.get("/"); p.status != 200 {
		t.Fatalf("the current session must survive the change: %d", p.status)
	}
	if p := older.get("/"); p.status != 303 {
		t.Fatalf("another session of the user survived the change: %d", p.status)
	}
	if p := e.browser().post("/login", url.Values{"email": {"ann@example.com"}, "password": {"one-time-password-1"}}); p.status != 200 {
		t.Fatalf("the old password still works: %d", p.status)
	}
	if p := e.browser().post("/login", url.Values{"email": {"ann@example.com"}, "password": {"a-brand-new-password"}}); p.status != 303 || p.header.Get("Location") != "/" {
		t.Fatalf("login with the new password: %d %q", p.status, p.header.Get("Location"))
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.password.change' AND actor='ann@example.com'`); n != 1 {
		t.Fatalf("%d password-change audit rows", n)
	}
}

func TestRehashOnLogin(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("ann@example.com", "viewer", goodPW, false)
	// Replace the stored hash with one made with lighter parameters.
	if _, err := e.st.RehashPassword(context.Background(), u.ID, u.PasswordHash, weakHash(t, goodPW), t0); err != nil {
		t.Fatal(err)
	}
	e.browser().login("ann@example.com", goodPW)
	got, _ := e.st.UserByEmail(context.Background(), "ann@example.com")
	if !strings.HasPrefix(got.PasswordHash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash not upgraded at login: %s", got.PasswordHash[:40])
	}
	if e.hasher.hashes.Load() != 1 {
		t.Fatalf("%d rehashes", e.hasher.hashes.Load())
	}
}

func TestLocalLoginDisabled(t *testing.T) {
	e := newEnv(t, console(func(a *server.Auth) { a.Local.Enabled = false }))
	e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	if p := b.get("/login"); p.status != 200 || !strings.Contains(p.body, `data-testid="login-disabled"`) {
		t.Fatalf("%d", p.status)
	}
	if p := b.post("/login", url.Values{"email": {"ann@example.com"}, "password": {goodPW}}); p.status != 403 || e.cookieFor(b) != nil {
		t.Fatalf("login with auth.local.enabled=false: %d", p.status)
	}
}

func TestCookieSecureOffForDevelopment(t *testing.T) {
	e := newEnv(t, console(func(a *server.Auth) { a.CookieSecure = false }))
	e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	p := b.post("/login", url.Values{"email": {"ann@example.com"}, "password": {goodPW}})
	sc := p.header.Get("Set-Cookie")
	if p.status != 303 || !strings.HasPrefix(sc, "clamfleet_session=cfs_") || strings.Contains(sc, "Secure") || !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "SameSite=Lax") {
		t.Fatalf("%d %q", p.status, sc)
	}
	if p := b.get("/"); p.status != 200 {
		t.Fatalf("development cookie not accepted: %d", p.status)
	}
}

func TestOpenRedirectIsClosed(t *testing.T) {
	e := newEnv(t)
	e.addUser("ann@example.com", "viewer", goodPW, false)
	for next, want := range map[string]string{
		"/account": "/account", "//evil.example": "/", "/\\evil.example": "/", "https://evil.example/": "/",
		"javascript:alert(1)": "/", "": "/", "evil": "/",
	} {
		p := e.browser().post("/login", url.Values{"email": {"ann@example.com"}, "password": {goodPW}, "next": {next}})
		if p.status != 303 || p.header.Get("Location") != want {
			t.Errorf("next=%q -> %d %q, want %q", next, p.status, p.header.Get("Location"), want)
		}
	}
	// The same rule on the redirect from a protected page to the login page.
	p := e.browser().get("/account")
	if p.status != 303 || p.header.Get("Location") != "/login?next=%2Faccount" {
		t.Fatalf("%d %q", p.status, p.header.Get("Location"))
	}
}

func TestCSRFThroughRouter(t *testing.T) {
	e := newEnv(t)
	e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW)

	// Each case gets its own signed-in browser; tokenOf yields what the case sends.
	same := map[string]string{"Sec-Fetch-Site": "same-origin"}
	cases := []struct {
		name string
		hdr  func(tok string) map[string]string
		form func(tok string) url.Values
		want int
	}{
		{"missing token", func(string) map[string]string { return same }, func(string) url.Values { return url.Values{} }, 403},
		{"wrong token", func(string) map[string]string { return same }, func(t string) url.Values { return url.Values{"csrf_token": {flipFirst(t)}} }, 403},
		{"cross-site with a valid token", func(string) map[string]string { return map[string]string{"Sec-Fetch-Site": "cross-site"} }, func(t string) url.Values { return url.Values{"csrf_token": {t}} }, 403},
		{"foreign Origin with a valid token", func(string) map[string]string { return map[string]string{"Origin": "https://evil.example"} }, func(t string) url.Values { return url.Values{"csrf_token": {t}} }, 403},
		{"valid token in the form", func(string) map[string]string { return same }, func(t string) url.Values { return url.Values{"csrf_token": {t}} }, 303},
		{"valid token in the header (htmx)", func(t string) map[string]string {
			return map[string]string{"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": t}
		}, func(string) url.Values { return url.Values{} }, 303},
	}
	for _, c := range cases {
		// logout is the cheapest CSRF-protected POST.
		bb := e.browser()
		bb.login("ann@example.com", goodPW)
		tk := csrf(t, bb.get("/"))
		if p := bb.do("POST", "/logout", c.hdr(tk), c.form(tk)); p.status != c.want {
			t.Errorf("%s: %d, want %d", c.name, p.status, c.want)
		}
	}
	// A cross-site POST /login is refused before any credential is looked at.
	before := e.hasher.verifies.Load() + e.hasher.dummies.Load()
	p := e.browser().do("POST", "/login", map[string]string{"Sec-Fetch-Site": "cross-site"}, url.Values{"email": {"ann@example.com"}, "password": {goodPW}})
	if p.status != 403 || e.hasher.verifies.Load()+e.hasher.dummies.Load() != before {
		t.Fatalf("cross-site login: %d", p.status)
	}
	// A token from another session does not work.
	other := e.browser()
	other.login("ann@example.com", goodPW)
	otherTok := csrf(t, other.get("/"))
	if p := b.post("/logout", url.Values{"csrf_token": {otherTok}}); p.status != 403 {
		t.Fatalf("a CSRF token of another session was accepted: %d", p.status)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW)
	for _, path := range []string{"/login", "/", "/account", "/static/app.css"} {
		p := b.get(path)
		if path == "/login" {
			p = e.browser().get(path) // signed-out: the form, not the redirect
		}
		h := p.header
		if p.status != 200 && path != "/login" {
			t.Fatalf("%s: %d", path, p.status)
		}
		csp := h.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'self'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q lacks %q", path, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-") {
			t.Errorf("%s: CSP allows %q", path, csp)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "same-origin" {
			t.Errorf("%s: headers %v", path, h)
		}
		if path != "/static/app.css" && h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", path, h.Get("Cache-Control"))
		}
	}
	// Not on the agent API.
	for _, c := range []struct{ method, path string }{{"GET", "/healthz"}, {"POST", "/v1/report"}} {
		p := b.do(c.method, c.path, nil, nil)
		if p.header.Get("Content-Security-Policy") != "" || p.header.Get("X-Content-Type-Options") != "" {
			t.Errorf("%s %s carries UI security headers", c.method, c.path)
		}
	}
	// Pages carry no inline script or style (the CSP would block it and break the page).
	home := b.get("/").body
	if regexp.MustCompile(`(?i)<style|<script[^>]*>[^<]|\sstyle=|\sonclick=|javascript:`).MatchString(home) {
		t.Errorf("inline script or style in a page:\n%s", home)
	}
}

// vendoredHash is the SHA-256 recorded in static/README.md. It is repeated
// here on purpose: editing the file AND the README in one commit still fails
// this test unless the constant changes too.
const vendoredHash = "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717"

func TestStaticHtmxPinned(t *testing.T) {
	e := newEnv(t)
	p := e.browser().get("/static/htmx-2.0.11.min.js")
	if p.status != 200 || !strings.Contains(p.header.Get("Content-Type"), "javascript") {
		t.Fatalf("%d %q", p.status, p.header.Get("Content-Type"))
	}
	sum := sha256.Sum256([]byte(p.body))
	if hex.EncodeToString(sum[:]) != vendoredHash {
		t.Fatalf("served htmx has SHA-256 %x, want %s", sum, vendoredHash)
	}
	readme, err := os.ReadFile("static/README.md")
	if err != nil || !strings.Contains(string(readme), vendoredHash) {
		t.Fatalf("static/README.md does not record the pinned hash: %v", err)
	}
	if cc := p.header.Get("Cache-Control"); !strings.Contains(cc, "max-age=86400") {
		t.Errorf("Cache-Control %q", cc)
	}
	// Only listed asset files are served: not the README, not a path escape.
	for _, path := range []string{"/static/README.md", "/static/..%2f..%2fweb.go", "/static/nope.js", "/static/"} {
		if p := e.browser().get(path); p.status == 200 {
			t.Errorf("GET %s: %d", path, p.status)
		}
	}
}

func TestUnknownPath404(t *testing.T) {
	e := newEnv(t)
	e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW)
	for _, path := range []string{"/nope", "/hosts", "/fleet", "/admin"} {
		if p := b.get(path); p.status != 404 {
			t.Errorf("GET %s while signed in: %d, want 404 (GET / must be registered as GET /{$})", path, p.status)
		}
	}
}

func TestCredentialsDoNotCross(t *testing.T) {
	e := newEnv(t)
	e.addUser("ann@example.com", "admin", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW)
	cookie := e.cookieFor(b)

	// A valid session cookie is not an agent credential.
	for _, path := range []string{"/v1/report", "/v1/event"} {
		p := b.do("POST", path, map[string]string{"Content-Type": "application/json", "Cookie": cookie.Name + "=" + cookie.Value}, nil)
		if p.status != 401 {
			t.Errorf("POST %s with a session cookie: %d, want 401", path, p.status)
		}
	}
	// A session token as a bearer token is not accepted either.
	if p := e.browser().do("POST", "/v1/report", map[string]string{"Authorization": "Bearer " + cookie.Value}, nil); p.status != 401 {
		t.Errorf("session token as bearer: %d", p.status)
	}
	// And an agent bearer token does not open the console.
	tok := registerHost(t, e, "web01")
	if p := e.browser().do("GET", "/", map[string]string{"Authorization": "Bearer " + tok}, nil); p.status != 303 {
		t.Errorf("agent bearer on /: %d, want 303 to login", p.status)
	}
	if p := e.browser().do("GET", "/account", map[string]string{"Authorization": "Bearer " + tok}, nil); p.status != 303 {
		t.Errorf("agent bearer on /account: %d", p.status)
	}
}

// TestUIRouteTable probes every console route in server.Routes() by behaviour:
// no session, htmx without a session, a viewer on admin routes (403, database
// unchanged), a session without a CSRF token. It also enforces, by path, that
// everything under /admin/ is class admin. The declared class of every route is
// pinned by internal/api TestRouteTable; this test does not repeat that pin.
func TestUIRouteTable(t *testing.T) {
	e := newEnv(t)
	e.addUser("view@example.com", "viewer", goodPW, false)
	e.addUser("adm@example.com", "admin", goodPW, false)
	registerHost(t, e, "web01")

	concrete := strings.NewReplacer("{$}", "", "{file}", "app.css", "{name}", "web01")
	unauth := e.browser()
	viewer := e.browser()
	viewer.login("view@example.com", goodPW)
	vtok := csrf(t, viewer.get("/"))
	admin := e.browser()
	admin.login("adm@example.com", goodPW)

	counts := func() [4]int {
		return [4]int{e.count(`SELECT count(*) FROM hosts`), e.count(`SELECT count(*) FROM audit_log`), e.count(`SELECT count(*) FROM users`), e.count(`SELECT count(*) FROM user_sessions`)}
	}
	classes := map[server.AuthClass]bool{}
	for _, rt := range server.Routes() {
		classes[rt.Auth] = true
		path := concrete.Replace(rt.Path)
		name := rt.Method + " " + rt.Path
		// Rule: everything under /admin/ is admin-only. Checked here by path, not
		// by the declared class alone, so a route mis-classed as user is caught by
		// behaviour (the viewer probe below), independent of the table.
		if strings.HasPrefix(rt.Path, "/admin/") && rt.Auth != server.AuthAdmin {
			t.Errorf("%s is under /admin/ but has class %q", name, rt.Auth)
			rt.Auth = server.AuthAdmin // keep probing it as an admin route: the viewer probe must see a 403
		}
		switch rt.Auth {
		case server.AuthAgent, server.AuthNone:
			continue // covered by internal/api TestRouteTable
		case server.AuthPublic:
			if p := unauth.do(rt.Method, path, map[string]string{"Sec-Fetch-Site": "same-origin"}, url.Values{}); p.status == 401 || p.status == 303 && rt.Path != "/login" {
				t.Errorf("%s (public): %d without a session", name, p.status)
			}
		case server.AuthUser, server.AuthAdmin:
			// No session.
			p := unauth.do(rt.Method, path, map[string]string{"Sec-Fetch-Site": "same-origin"}, url.Values{})
			wantNo := 401
			if rt.Method == "GET" {
				wantNo = 303
			}
			if p.status != wantNo {
				t.Errorf("%s without a session: %d, want %d", name, p.status, wantNo)
			}
			if rt.Method == "GET" && !strings.HasPrefix(p.header.Get("Location"), "/login") {
				t.Errorf("%s without a session redirects to %q", name, p.header.Get("Location"))
			}
			// The htmx form of the same request: 401 + HX-Redirect, so the tab leaves the page.
			px := unauth.do(rt.Method, path, map[string]string{"HX-Request": "true", "Sec-Fetch-Site": "same-origin"}, url.Values{})
			if px.status != 401 || px.header.Get("HX-Redirect") != "/login" {
				t.Errorf("%s htmx without a session: %d %q", name, px.status, px.header.Get("HX-Redirect"))
			}
			// A viewer on an admin route: 403, nothing written.
			if rt.Auth == server.AuthAdmin {
				before := counts()
				form := url.Values{"csrf_token": {vtok}, "name": {"intruder"}, "confirm": {"web01"}}
				pv := viewer.do(rt.Method, path, map[string]string{"Sec-Fetch-Site": "same-origin"}, form)
				if pv.status != 403 {
					t.Errorf("%s as a viewer: %d, want 403", name, pv.status)
				}
				if after := counts(); after != before {
					t.Errorf("%s as a viewer changed the database: %v -> %v", name, before, after)
				}
			}
			// Valid session, no CSRF token, on every non-GET: 403 and nothing written.
			if rt.Method != "GET" {
				who := viewer
				if rt.Auth == server.AuthAdmin {
					who = admin
				}
				before := counts()
				pc := who.do(rt.Method, path, map[string]string{"Sec-Fetch-Site": "same-origin"}, url.Values{"name": {"intruder"}, "confirm": {"web01"}})
				if pc.status != 403 {
					t.Errorf("%s with a session but no CSRF token: %d, want 403", name, pc.status)
				}
				if after := counts(); after != before {
					t.Errorf("%s without a token changed the database: %v -> %v", name, before, after)
				}
			}
		default:
			t.Errorf("%s: unknown auth class %q", name, rt.Auth)
		}
	}
	for _, c := range []server.AuthClass{server.AuthUser, server.AuthPublic, server.AuthAgent, server.AuthNone} {
		if !classes[c] {
			t.Errorf("no route of class %s: the table test would pass vacuously", c)
		}
	}
}

// A burst of parallel logins for one email must not all reach the hasher: the
// attempt is counted before it is verified, so at most the free failures get in.
func TestParallelLoginsCannotBypassTheThrottle(t *testing.T) {
	for _, email := range []string{"ann@example.com", "ghost@example.com"} { // a real and an unknown account
		t.Run(email, func(t *testing.T) {
			e := newEnv(t)
			e.addUser("ann@example.com", "viewer", goodPW, false)
			e.hasher.gate = make(chan struct{}) // verifications stay in flight until released
			var release sync.Once
			open := func() { release.Do(func() { close(e.hasher.gate) }) }
			t.Cleanup(open) // a failing run must not leave blocked requests that stall the server's shutdown
			const n = 20
			results := make(chan int, n)
			for i := 0; i < n; i++ {
				go func() {
					p := e.browser().post("/login", url.Values{"email": {email}, "password": {"wrong wrong wrong wrong"}})
					results <- p.status
				}()
			}
			// The refused ones answer at once; the admitted ones are blocked in the hasher.
			refused := 0
			for refused < n-5 {
				select {
				case st := <-results:
					if st != 429 {
						t.Fatalf("an early answer was %d, want 429", st)
					}
					refused++
				case <-time.After(20 * time.Second):
					t.Fatalf("only %d of %d requests were refused while %d reached the hasher", refused, n-5, e.hasher.verifies.Load()+e.hasher.dummies.Load())
				}
			}
			if got := e.hasher.verifies.Load() + e.hasher.dummies.Load(); got > 5 {
				t.Fatalf("%d parallel attempts reached the hasher, want at most 5 (the free failures)", got)
			}
			open()
			for i := 0; i < 5; i++ {
				if st := <-results; st != 200 {
					t.Errorf("an admitted attempt answered %d", st)
				}
			}
		})
	}
}

// raceLogin starts a login whose verification blocks in the hasher, runs
// during (a password reset by an admin) while it is blocked, then releases it.
func raceLogin(t *testing.T, e *env, email, password string, during func()) (*browser, page) {
	t.Helper()
	e.hasher.gate = make(chan struct{})
	var release sync.Once
	open := func() { release.Do(func() { close(e.hasher.gate) }) }
	t.Cleanup(open)
	b := e.browser()
	res := make(chan page, 1)
	before := e.hasher.verifies.Load()
	go func() { res <- b.post("/login", url.Values{"email": {email}, "password": {password}}) }()
	for e.hasher.verifies.Load() == before { // the login is now inside the hasher
		time.Sleep(5 * time.Millisecond)
	}
	during()
	open()
	return b, <-res
}

// A password reset that commits while a login is verifying the OLD password
// must not leave that login with a working session.
func TestLoginRacingAPasswordResetGetsNoWorkingSession(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("ann@example.com", "viewer", goodPW, false)
	b, p := raceLogin(t, e, "ann@example.com", goodPW, func() {
		// Same second as the login's start: no clock comparison may be what saves us.
		if err := e.st.SetPassword(context.Background(), u.ID, store.PasswordChange{Hash: "reset-hash", MustChange: true}, e.clock(), cliAudit); err != nil {
			t.Error(err)
		}
	})
	if p.status != 200 || !strings.Contains(p.body, "Invalid email or password.") || e.cookieFor(b) != nil {
		t.Fatalf("a login that raced a reset must fail without a cookie: %d", p.status)
	}
	if g := b.get("/"); g.status != 303 {
		t.Fatalf("a session exists for a login that raced a reset: %d", g.status)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.login.failed' AND detail LIKE '%credential changed%'`); n != 1 {
		t.Fatalf("%d audit rows for the raced login", n)
	}
}

// A login that upgrades the hash must not overwrite a password reset that
// committed while it was hashing.
func TestRehashRacingAResetDoesNotOverwriteIt(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("ann@example.com", "viewer", goodPW, false)
	if _, err := e.st.RehashPassword(context.Background(), u.ID, u.PasswordHash, weakHash(t, goodPW), t0); err != nil {
		t.Fatal(err)
	}
	raceLogin(t, e, "ann@example.com", goodPW, func() {
		if err := e.st.SetPassword(context.Background(), u.ID, store.PasswordChange{Hash: "reset-hash", MustChange: true}, e.clock(), cliAudit); err != nil {
			t.Error(err)
		}
	})
	got, _ := e.st.UserByEmail(context.Background(), "ann@example.com")
	if got.PasswordHash != "reset-hash" {
		t.Fatalf("the reset was overwritten by the rehash of the old password: %.30s", got.PasswordHash)
	}
}

// A self-service password change racing an admin reset must not overwrite the
// reset: the user gets an error, the reset stands, and the stale session is dead.
func TestSelfPasswordChangeRacingAResetDoesNotOverwriteIt(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW)
	tok := csrf(t, b.get("/account"))

	e.hasher.gate = make(chan struct{})
	var release sync.Once
	open := func() { release.Do(func() { close(e.hasher.gate) }) }
	t.Cleanup(open)
	before := e.hasher.verifies.Load()
	res := make(chan page, 1)
	go func() {
		res <- b.post("/account/password", url.Values{"csrf_token": {tok}, "current_password": {goodPW}, "new_password": {"a-brand-new-password"}, "new_password2": {"a-brand-new-password"}})
	}()
	for e.hasher.verifies.Load() == before { // the change is now verifying the current password
		time.Sleep(5 * time.Millisecond)
	}
	if err := e.st.SetPassword(context.Background(), u.ID, store.PasswordChange{Hash: "reset-hash", MustChange: true}, e.clock(), cliAudit); err != nil {
		t.Fatal(err)
	}
	open()
	p := <-res
	if p.status != 409 || !strings.Contains(p.body, "changed elsewhere") {
		t.Fatalf("the user must see an error, got %d", p.status)
	}
	got, _ := e.st.UserByEmail(context.Background(), "ann@example.com")
	if got.PasswordHash != "reset-hash" || !got.MustChange {
		t.Fatalf("the admin reset was overwritten by the self-service change: %.30s", got.PasswordHash)
	}
	if g := b.get("/"); g.status != 303 {
		t.Fatalf("the stale session still works: %d", g.status)
	}
}

// failingLogin makes RecordLogin fail, like a full disk would.
type failingLogin struct{ store.Store }

func (failingLogin) RecordLogin(context.Context, int64, time.Time, store.Audit, map[string]string) error {
	return errors.New("disk full")
}

// If the login cannot be recorded, nobody is signed in: 500, no cookie, and the
// session that was already created is removed again.
func TestLoginThatCannotBeRecordedLeavesNoSession(t *testing.T) {
	e := newEnv(t, func(d *server.Deps) { d.Store = failingLogin{d.Store} })
	e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	p := b.post("/login", url.Values{"email": {"ann@example.com"}, "password": {goodPW}})
	if p.status != 500 || p.header.Get("Set-Cookie") != "" || e.cookieFor(b) != nil {
		t.Fatalf("%d, Set-Cookie %q", p.status, p.header.Get("Set-Cookie"))
	}
	if n := e.count(`SELECT count(*) FROM user_sessions`); n != 0 {
		t.Fatalf("%d session rows left behind by a login that could not be recorded", n)
	}
}

// swapHash replaces the user's stored hash behind the handlers' back, without
// touching sessions (a reset would delete them), through the real store.
func swapHash(t *testing.T, e *env, u store.User, to string) {
	t.Helper()
	if ok, err := e.st.RehashPassword(context.Background(), u.ID, u.PasswordHash, to, e.clock()); err != nil || !ok {
		t.Fatalf("swapHash: applied=%v err=%v", ok, err)
	}
}

// failures drives n wrong-password logins for ann, each answered 200 (admitted).
func failures(t *testing.T, e *env, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if p := e.browser().post("/login", url.Values{"email": {"ann@example.com"}, "password": {"wrong wrong wrong wrong"}}); p.status != 200 {
			t.Fatalf("failure %d: %d", i+1, p.status)
		}
	}
}

// assertFourFailuresStand: the next wrong attempt is admitted (the 5th) and the one after is refused,
// so exactly four failures were on record before. A raced attempt that counted
// as a failure makes the first one 429; one that reset the count makes the second 200.
func assertFourFailuresStand(t *testing.T, e *env) {
	t.Helper()
	wrong := url.Values{"email": {"ann@example.com"}, "password": {"wrong wrong wrong wrong"}}
	if p := e.browser().post("/login", wrong); p.status != 200 {
		t.Fatalf("the 5th wrong attempt was %d: the raced attempt counted as a failure", p.status)
	}
	if p := e.browser().post("/login", wrong); p.status != 429 {
		t.Fatalf("the 6th wrong attempt was %d, want 429: the raced attempt reset the failures", p.status)
	}
}

func TestRacedLoginDoesNotCountAsAFailureOrAReset(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("ann@example.com", "viewer", goodPW, false)
	failures(t, e, 4)
	other, _ := webauth.NewHasher().Hash(context.Background(), "some other password entirely")
	// The raced login is the 5th attempt, verified with the RIGHT password, then loses the race.
	b, p := raceLogin(t, e, "ann@example.com", goodPW, func() { swapHash(t, e, u, other) })
	if p.status != 200 || e.cookieFor(b) != nil {
		t.Fatalf("raced login: %d", p.status)
	}
	assertFourFailuresStand(t, e)
}

func TestRacedPasswordChangeDoesNotCountAsAFailureOrAReset(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW) // success: no failures on record
	tok := csrf(t, b.get("/account"))
	change := func(cur string) page {
		return b.post("/account/password", url.Values{"csrf_token": {tok}, "current_password": {cur}, "new_password": {"a-brand-new-password"}, "new_password2": {"a-brand-new-password"}})
	}
	for i := 0; i < 4; i++ {
		if p := change("wrong wrong wrong wrong"); p.status != 200 {
			t.Fatalf("failure %d: %d", i+1, p.status)
		}
	}
	other, _ := webauth.NewHasher().Hash(context.Background(), "some other password entirely")
	e.hasher.gate = make(chan struct{})
	var release sync.Once
	open := func() { release.Do(func() { close(e.hasher.gate) }) }
	t.Cleanup(open)
	before := e.hasher.verifies.Load()
	res := make(chan page, 1)
	go func() { res <- change(goodPW) }() // the 5th attempt, right password
	for e.hasher.verifies.Load() == before {
		time.Sleep(5 * time.Millisecond)
	}
	swapHash(t, e, u, other)
	open()
	if p := <-res; p.status != 409 {
		t.Fatalf("raced change: %d", p.status)
	}
	// The stored hash is now `other`; a wrong current password is admitted once more (5th) and then refused.
	if p := change("wrong wrong wrong wrong"); p.status != 200 {
		t.Fatalf("5th wrong attempt: %d (the 409 counted as a failure)", p.status)
	}
	if p := change("wrong wrong wrong wrong"); p.status != 429 {
		t.Fatalf("6th wrong attempt: %d (the 409 reset the failures)", p.status)
	}
}

// flipFirst returns a token that certainly differs from t: the first character
// is part of the random mask, so the unmasked secret changes.
func flipFirst(t string) string {
	c := "A"
	if t[0] == 'A' {
		c = "B"
	}
	return c + t[1:]
}

// Closes the M3 known limit: a disable followed by an enable while the login is
// hashing leaves the password hash unchanged, so only auth_version can refuse it.
func TestLoginRacingDisableEnableGetsNoSession(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("ann@example.com", "viewer", goodPW, false)
	b, p := raceLogin(t, e, "ann@example.com", goodPW, func() {
		for _, off := range []bool{true, false} {
			if err := e.st.SetDisabled(context.Background(), u.ID, off, e.clock(), cliAudit); err != nil {
				t.Error(err)
			}
		}
	})
	if p.status != 200 || !strings.Contains(p.body, "Invalid email or password.") || e.cookieFor(b) != nil {
		t.Fatalf("a login that raced disable+enable must fail without a cookie: %d", p.status)
	}
	if g := b.get("/"); g.status != 303 {
		t.Fatalf("a session exists for a login that raced disable+enable: %d", g.status)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.login.failed' AND detail LIKE '%credential changed%'`); n != 1 {
		t.Fatalf("%d audit rows for the raced login", n)
	}
	// The user can sign in normally afterwards.
	e.browser().login("ann@example.com", goodPW)
}
