// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Second-factor tests, through the real router like the rest of this package:
// a TLS server around server.NewHandler, a cookie jar, real SQLite, an injected
// clock far from the real date. The TOTP codes are made by an independent
// implementation (testCode), not by the code under test.
package web_test

import (
	"context"
	"github.com/clamfleet/clamfleet/internal/server"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

func codeNow(u totpUser, e *env, offset int64) string {
	return testCode(u.secret, stepAt(e.clock())+offset)
}

func (b *browser) code(code string) page { return b.post("/login/totp", url.Values{"code": {code}}) }

func TestTOTPLoginFlowThroughRouter(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	registerHost(t, e, "web01")
	u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)

	b, p := e.passwordStep("ann@example.com", goodPW)
	if p.status != 303 || p.header.Get("Location") != "/login/totp" {
		t.Fatalf("password step: %d -> %q", p.status, p.header.Get("Location"))
	}
	// The cookie of the pending login has every flag, and there is NO session cookie.
	var loginCookie string
	for _, c := range p.header.Values("Set-Cookie") {
		if strings.HasPrefix(c, "__Host-clamfleet_login=cfp_") {
			loginCookie = c
		}
		if strings.HasPrefix(c, "__Host-clamfleet_session=cfs_") {
			t.Fatalf("the password step set a session cookie: %q", c)
		}
	}
	for _, want := range []string{"HttpOnly", "Secure", "SameSite=Lax", "Path=/"} {
		if !strings.Contains(loginCookie, want) {
			t.Errorf("challenge cookie %q lacks %q", loginCookie, want)
		}
	}
	if strings.Contains(loginCookie, "Max-Age") || strings.Contains(loginCookie, "Domain") {
		t.Errorf("challenge cookie %q must be host-only and session-scoped", loginCookie)
	}
	if e.cookieFor(b) != nil {
		t.Fatal("a session cookie is in the jar after the password step")
	}
	// A pending login is not a session.
	if g := b.get("/"); g.status != 303 || !strings.HasPrefix(g.header.Get("Location"), "/login") {
		t.Fatalf("GET / with only a challenge: %d %q", g.status, g.header.Get("Location"))
	}
	if g := b.do("GET", "/fleet/rows", map[string]string{"HX-Request": "true"}, nil); g.status != 401 {
		t.Fatalf("GET /fleet/rows with only a challenge: %d", g.status)
	}
	if n := e.count(`SELECT count(*) FROM user_sessions`); n != 0 {
		t.Fatalf("%d session rows after the password step", n)
	}
	if g := b.get("/login/totp"); g.status != 200 || !strings.Contains(g.body, `data-testid="totp-code"`) {
		t.Fatalf("GET /login/totp: %d", g.status)
	}

	// A wrong code: 200 with the error, audited, counted.
	p = b.code(wrongCode(u.secret, e.clock()))
	if p.status != 200 || !strings.Contains(p.body, "That code is not valid") {
		t.Fatalf("wrong code: %d", p.status)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.login.failed' AND detail LIKE '%bad code%' AND actor='ann@example.com'`); n != 1 {
		t.Fatalf("%d user.login.failed {bad code} rows", n)
	}
	if n := e.count(`SELECT totp_failures FROM users WHERE id=?`, u.ID); n != 1 {
		t.Fatalf("totp_failures %d, want 1", n)
	}
	if e.cookieFor(b) != nil {
		t.Fatal("a wrong code produced a session")
	}

	// The right code: 303 to next, a session, the challenge cookie cleared, counters reset.
	p = b.code(codeNow(u, e, 0))
	if p.status != 303 || p.header.Get("Location") != "/" {
		t.Fatalf("right code: %d -> %q\n%s", p.status, p.header.Get("Location"), p.body)
	}
	sc, cleared := "", false
	for _, c := range p.header.Values("Set-Cookie") {
		if strings.HasPrefix(c, "__Host-clamfleet_session=cfs_") {
			sc = c
		}
		if strings.HasPrefix(c, "__Host-clamfleet_login=;") && strings.Contains(c, "Max-Age=0") {
			cleared = true
		}
	}
	for _, want := range []string{"HttpOnly", "Secure", "SameSite=Lax", "Path="} {
		if !strings.Contains(sc, want) {
			t.Errorf("session cookie %q lacks %q", sc, want)
		}
	}
	if !cleared {
		t.Errorf("the challenge cookie was not cleared: %v", p.header.Values("Set-Cookie"))
	}
	if n := e.count(`SELECT count(*) FROM user_login_challenges`); n != 0 {
		t.Fatalf("%d challenges left", n)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.login' AND actor='ann@example.com' AND detail LIKE '%"mfa":"totp"%' AND detail LIKE '%127.0.0.1%'`); n != 1 {
		t.Fatalf("%d user.login {mfa: totp} rows", n)
	}
	if n := e.count(`SELECT totp_failures FROM users WHERE id=?`, u.ID); n != 0 {
		t.Fatalf("totp_failures %d after a success", n)
	}
	if g := b.get("/"); g.status != 200 || !strings.Contains(g.body, `data-testid="fleet-row-web01"`) {
		t.Fatalf("GET / after the second step: %d", g.status)
	}
	// The challenge is gone: the same form cannot be replayed.
	if g := b.get("/login/totp"); g.status != 303 {
		t.Fatalf("GET /login/totp while signed in: %d", g.status)
	}
}

func TestChallengeTokenIsNotASession(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	e.addUser("bob@example.com", "viewer", goodPW, false)

	b, _ := e.passwordStep("ann@example.com", goodPW)
	challenge := e.cookie(b, "clamfleet_login")
	if !strings.HasPrefix(challenge, "cfp_") {
		t.Fatalf("no challenge cookie: %q", challenge)
	}
	// The challenge value presented as a session cookie.
	asSession := e.browser()
	u := mustURL(e.srv.URL)
	asSession.c.Jar.SetCookies(u, []*http.Cookie{{Name: "__Host-clamfleet_session", Value: challenge, Path: "/", Secure: true}})
	if g := asSession.get("/"); g.status != 303 || !strings.HasPrefix(g.header.Get("Location"), "/login") {
		t.Fatalf("a challenge token worked as a session cookie: %d", g.status)
	}
	// A real session token presented as the challenge cookie.
	bob := e.browser()
	bob.login("bob@example.com", goodPW)
	session := e.cookie(bob, "clamfleet_session")
	asChallenge := e.browser()
	asChallenge.c.Jar.SetCookies(u, []*http.Cookie{{Name: "__Host-clamfleet_login", Value: session, Path: "/", Secure: true}})
	if g := asChallenge.get("/login/totp"); g.status != 303 || g.header.Get("Location") != "/login" {
		t.Fatalf("a session token worked as a challenge: %d %q", g.status, g.header.Get("Location"))
	}
}

func TestLoginTOTPRoutesNeedAChallenge(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	hashes := e.hasher.verifies.Load() + e.hasher.dummies.Load()
	if p := b.get("/login/totp"); p.status != 303 || p.header.Get("Location") != "/login" {
		t.Fatalf("GET without a challenge: %d %q", p.status, p.header.Get("Location"))
	}
	p := b.code("123456")
	if p.status != 303 || p.header.Get("Location") != "/login?expired=1" {
		t.Fatalf("POST without a challenge: %d %q", p.status, p.header.Get("Location"))
	}
	if e.hasher.verifies.Load()+e.hasher.dummies.Load() != hashes {
		t.Fatal("the hasher ran for a request without a challenge")
	}
	if n := e.count(`SELECT count(*) FROM audit_log`); n != 0 {
		t.Fatalf("%d audit rows for requests without a challenge", n)
	}
	if g := b.get("/login?expired=1"); !strings.Contains(g.body, "Sign-in timed out") {
		t.Fatal("the expired notice is not shown")
	}
	// A cross-site POST is refused like any other (CrossOrigin).
	if p := b.do("POST", "/login/totp", map[string]string{"Sec-Fetch-Site": "cross-site"}, url.Values{"code": {"123456"}}); p.status != 403 {
		t.Fatalf("cross-site POST: %d", p.status)
	}
}

func TestTOTPReplayRefused(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	code := codeNow(u, e, 0)

	b, _ := e.passwordStep("ann@example.com", goodPW)
	if p := b.code(code); p.status != 303 {
		t.Fatalf("first use: %d", p.status)
	}
	// A second password login and the SAME code, inside its window.
	b2, _ := e.passwordStep("ann@example.com", goodPW)
	p := b2.code(code)
	if p.status != 200 || !strings.Contains(p.body, "already used") || e.cookieFor(b2) != nil {
		t.Fatalf("replay: %d", p.status)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.login.failed' AND detail LIKE '%code already used%'`); n != 1 {
		t.Fatalf("%d 'code already used' rows", n)
	}
	// The code of the next step is accepted.
	if p := b2.code(codeNow(u, e, 1)); p.status != 303 {
		t.Fatalf("next step's code: %d", p.status)
	}
}

// The window is judged on the INJECTED clock, which is years from the real date.
func TestTOTPSkewWindowUsesInjectedClock(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	for _, c := range []struct {
		off int64
		ok  bool
	}{{-2, false}, {2, false}, {-1, true}, {1, true}} {
		e.advance(time.Hour) // a fresh throttle window and fresh steps for each case
		e.exec(`UPDATE users SET totp_last_step = ? WHERE id = ?`, stepAt(e.clock())-10, u.ID)
		b, _ := e.passwordStep("ann@example.com", goodPW)
		p := b.code(codeNow(u, e, c.off))
		if got := p.status == 303; got != c.ok {
			t.Errorf("code at offset %d: accepted=%v, want %v (status %d)", c.off, got, c.ok, p.status)
		}
	}
	// A code made for the REAL current time is not accepted at 2031.
	e.advance(time.Hour)
	e.exec(`UPDATE users SET totp_last_step = 0 WHERE id = ?`, u.ID)
	b, _ := e.passwordStep("ann@example.com", goodPW)
	if p := b.code(testCode(u.secret, time.Now().Unix()/30)); p.status == 303 {
		t.Fatal("a code for the wall-clock time was accepted: the handler reads the real clock")
	}
}

// 20 parallel wrong codes reach the verifier at most 5 times (the free failures); the rest are 429.
func TestParallelTOTPCodesCannotBypassTheThrottle(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	var browsers []*browser
	for i := 0; i < 3; i++ { // spread over 3 challenges of the same user
		b, _ := e.passwordStep("ann@example.com", goodPW)
		browsers = append(browsers, b)
	}
	wrong := wrongCode(u.secret, e.clock())
	var wg sync.WaitGroup
	var mu sync.Mutex
	statuses := map[int]int{}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(b *browser) {
			defer wg.Done()
			p := b.code(wrong)
			mu.Lock()
			statuses[p.status]++
			mu.Unlock()
		}(browsers[i%3])
	}
	wg.Wait()
	// Each admitted attempt is verified and audited as a failure; each refused one is a 429.
	verified := e.count(`SELECT count(*) FROM audit_log WHERE action='user.login.failed' AND detail LIKE '%bad code%'`)
	if verified > 5 || statuses[200] != verified || statuses[429] != 20-verified {
		t.Fatalf("%d codes verified (statuses %v), want at most 5 and the rest 429", verified, statuses)
	}
	if n := e.count(`SELECT totp_failures FROM users WHERE id=?`, u.ID); n != verified {
		t.Fatalf("totp_failures %d, verified %d", n, verified)
	}
	// 429 carries Retry-After.
	if p := browsers[0].code(wrong); p.status != 429 || p.header.Get("Retry-After") == "" {
		t.Fatalf("%d %q", p.status, p.header.Get("Retry-After"))
	}
}

// 10 parallel POSTs with the right code on ONE challenge: one session, one audit row.
func TestParallelCorrectCodeYieldsOneSession(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	b, _ := e.passwordStep("ann@example.com", goodPW)
	code := codeNow(u, e, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var redirects []string
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := b.code(code)
			mu.Lock()
			redirects = append(redirects, p.header.Get("Location")+"|"+itoa(p.status))
			mu.Unlock()
		}()
	}
	wg.Wait()
	won := 0
	for _, r := range redirects {
		switch {
		case r == "/|303":
			won++
		case r == "/login?expired=1|303", strings.HasSuffix(r, "|429"):
		default:
			t.Errorf("unexpected answer %q", r)
		}
	}
	if won != 1 {
		t.Fatalf("%d requests got a session: %v", won, redirects)
	}
	if n := e.count(`SELECT count(*) FROM user_sessions`); n != 1 {
		t.Fatalf("%d session rows", n)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.login'`); n != 1 {
		t.Fatalf("%d user.login rows", n)
	}
	// The losers were not wrong guesses.
	if n := e.count(`SELECT totp_failures FROM users WHERE id=?`, u.ID); n != 0 {
		t.Fatalf("totp_failures %d", n)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.login.failed'`); n != 0 {
		t.Fatalf("%d failed-login rows for requests that only lost a race", n)
	}
}

func TestSecondFactorLock(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	e.exec(`UPDATE users SET totp_failures = 99 WHERE id = ?`, u.ID)

	b, _ := e.passwordStep("ann@example.com", goodPW)
	if p := b.code(wrongCode(u.secret, e.clock())); p.status != 200 {
		t.Fatalf("%d", p.status)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.totp.locked'`); n != 1 {
		t.Fatalf("%d user.totp.locked rows", n)
	}
	// Now even the right code is refused.
	p := b.code(codeNow(u, e, 0))
	if p.status != 200 || !strings.Contains(p.body, "Ask an administrator") || e.cookieFor(b) != nil {
		t.Fatalf("a locked user with the right code: %d", p.status)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.login.failed' AND detail LIKE '%second factor locked%'`); n != 1 {
		t.Fatalf("%d 'second factor locked' rows", n)
	}
	// A restart (new server, fresh throttles) is still locked: the lock is in the database.
	e2 := e.another(withKeys(ring))
	b2, _ := e2.passwordStep("ann@example.com", goodPW)
	if p := b2.code(codeNow(u, e, 1)); p.status != 200 || !strings.Contains(p.body, "Ask an administrator") {
		t.Fatalf("after a restart: %d", p.status)
	}
	// An admin password reset lifts it.
	if err := e.st.SetPassword(context.Background(), u.ID, store.PasswordChange{Hash: hashOf(t, "a new password for ann"), MustChange: true}, e.clock(), cliAudit); err != nil {
		t.Fatal(err)
	}
	e.advance(2 * time.Minute)
	b3, _ := e2.passwordStep("ann@example.com", "a new password for ann")
	if p := b3.code(codeNow(u, e, 0)); p.status != 303 {
		t.Fatalf("after the reset: %d", p.status)
	}
}

// Rule: a challenge belongs to the account state the password step saw.
func TestChallengeBoundToCredential(t *testing.T) {
	ring := testRing(t)
	for name, change := range map[string]func(e *env, u totpUser){
		"password reset": func(e *env, u totpUser) {
			_ = e.st.SetPassword(context.Background(), u.ID, store.PasswordChange{Hash: "reset", MustChange: true}, e.clock(), cliAudit)
		},
		"disable": func(e *env, u totpUser) {
			_ = e.st.SetDisabled(context.Background(), u.ID, true, e.clock(), cliAudit)
		},
		"disable and enable": func(e *env, u totpUser) {
			_ = e.st.SetDisabled(context.Background(), u.ID, true, e.clock(), cliAudit)
			_ = e.st.SetDisabled(context.Background(), u.ID, false, e.clock(), cliAudit)
		},
		"reset-totp": func(e *env, u totpUser) {
			_ = e.st.DisableTOTP(context.Background(), u.ID, nil, store.ActionTOTPReset, e.clock(), cliAudit)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, withKeys(ring))
			u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
			b, _ := e.passwordStep("ann@example.com", goodPW)
			change(e, u)
			p := b.code(codeNow(u, e, 0))
			if p.status != 303 || p.header.Get("Location") != "/login?expired=1" || e.cookieFor(b) != nil {
				t.Fatalf("a challenge survived %s: %d %q", name, p.status, p.header.Get("Location"))
			}
			if g := b.get("/"); g.status != 303 {
				t.Fatalf("a session exists after %s", name)
			}
			if n := e.count(`SELECT count(*) FROM user_sessions`); n != 0 {
				t.Fatalf("%d sessions", n)
			}
			// Not a wrong guess: nothing counted.
			if n := e.count(`SELECT totp_failures FROM users WHERE id=?`, u.ID); n != 0 {
				t.Fatalf("totp_failures %d", n)
			}
		})
	}
}

func TestChallengeExpires(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	b, _ := e.passwordStep("ann@example.com", goodPW)
	e.advance(5*time.Minute + time.Second)
	// Looked at before the POST: the POST's own answer clears the cookie.
	if g := b.get("/login/totp"); g.status != 303 || g.header.Get("Location") != "/login" {
		t.Fatalf("GET /login/totp with an expired challenge: %d %q", g.status, g.header.Get("Location"))
	}
	p := b.code(codeNow(u, e, 0))
	if p.status != 303 || p.header.Get("Location") != "/login?expired=1" || e.cookieFor(b) != nil {
		t.Fatalf("an expired challenge: %d %q", p.status, p.header.Get("Location"))
	}
	if n := e.count(`SELECT count(*) FROM user_sessions`); n != 0 {
		t.Fatalf("%d sessions", n)
	}
}

func TestRecoveryCodeLogin(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	b, _ := e.passwordStep("ann@example.com", goodPW)
	// Upper case with spaces: the form is forgiving.
	typed := strings.ToUpper(strings.ReplaceAll(u.codes[3], "-", " "))
	p := b.code(typed)
	if p.status != 303 || !strings.Contains(p.header.Get("Location"), "recovery_left=9") {
		t.Fatalf("recovery code: %d %q", p.status, p.header.Get("Location"))
	}
	if g := b.get(p.header.Get("Location")); g.status != 200 || !strings.Contains(g.body, "9 recovery codes left") {
		t.Fatalf("the notice is not shown: %d", g.status)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.login' AND detail LIKE '%"mfa":"recovery_code"%'`); n != 1 {
		t.Fatalf("%d user.login {recovery_code} rows", n)
	}
	// The same code again is refused and counted.
	b2, _ := e.passwordStep("ann@example.com", goodPW)
	p = b2.code(u.codes[3])
	if p.status != 200 || e.cookieFor(b2) != nil {
		t.Fatalf("a used recovery code: %d", p.status)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.login.failed' AND detail LIKE '%bad recovery code%'`); n != 1 {
		t.Fatalf("%d 'bad recovery code' rows", n)
	}
	if n := e.count(`SELECT totp_failures FROM users WHERE id=?`, u.ID); n != 1 {
		t.Fatalf("totp_failures %d", n)
	}
	// Garbage of the wrong shape is a failed attempt too, not an error.
	if p := b2.code("not a code at all"); p.status != 200 {
		t.Fatalf("%d", p.status)
	}
	// Neither the recovery codes nor their plaintext are in the database file.
	raw := readFile(t, e.dbPath)
	for _, c := range u.codes {
		if strings.Contains(raw, strings.ReplaceAll(c, "-", "")) || strings.Contains(raw, c) {
			t.Fatalf("recovery code %q is in the database file", c)
		}
	}
}

// A secret copied into another user's row must not decrypt there (AAD binds the user id).
func TestSwappedSecretDoesNotDecrypt(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	a := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	bob := e.addTOTPUser(ring, "bob@example.com", "viewer", goodPW)
	e.exec(`UPDATE users SET totp_secret = (SELECT totp_secret FROM users WHERE id = ?) WHERE id = ?`, a.ID, bob.ID)
	b, _ := e.passwordStep("bob@example.com", goodPW)
	p := b.code(codeNow(a, e, 0)) // ann's secret, her valid code
	if p.status != 500 || e.cookieFor(b) != nil {
		t.Fatalf("a swapped secret: %d, want 500 and no session", p.status)
	}
	if n := e.count(`SELECT count(*) FROM user_sessions`); n != 0 {
		t.Fatalf("%d sessions", n)
	}
	// A 500 is a server fault, not bob's wrong guess.
	if n := e.count(`SELECT totp_failures FROM users WHERE id=?`, bob.ID); n != 0 {
		t.Fatalf("totp_failures %d", n)
	}
}

// With no key the code path says so (503); it never falls back to "password only".
func TestNoKeyMeansNoTOTPButNeverPasswordOnly(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t) // no Keys
	u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	b, p := e.passwordStep("ann@example.com", goodPW)
	if p.status != 303 || p.header.Get("Location") != "/login/totp" || e.cookieFor(b) != nil {
		t.Fatalf("password step without a key: %d %q", p.status, p.header.Get("Location"))
	}
	p = b.code(codeNow(u, e, 0))
	if p.status != 503 || !strings.Contains(p.body, "unavailable") || e.cookieFor(b) != nil {
		t.Fatalf("code without a key: %d", p.status)
	}
	if g := b.get("/"); g.status != 303 {
		t.Fatalf("a session exists without a key: %d", g.status)
	}
	// An unavailable service is not a wrong guess.
	if n := e.count(`SELECT totp_failures FROM users WHERE id=?`, u.ID); n != 0 {
		t.Fatalf("totp_failures %d", n)
	}
	// A recovery code still works: it does not depend on the key.
	if p := b.code(u.codes[0]); p.status != 303 {
		t.Fatalf("recovery code without a key: %d", p.status)
	}
}

func TestNoSecretOrCodeInLogsOrAuditAtLogin(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	right := codeNow(u, e, 0)
	wrong := wrongCode(u.secret, e.clock())
	b, _ := e.passwordStep("ann@example.com", goodPW)
	b.code(wrong)
	b.code("zzzz-zzzz-zzzz-zzzz")
	b.code(right)
	b2, _ := e.passwordStep("ann@example.com", goodPW)
	b2.code(u.codes[0])
	dump := e.logs.String() + "\n" + auditDump(t, e)
	for _, secret := range []string{right, wrong, u.codes[0], strings.ReplaceAll(u.codes[0], "-", ""), "zzzz-zzzz-zzzz-zzzz"} {
		if strings.Contains(dump, secret) {
			t.Fatalf("%q is in the logs or the audit log", secret)
		}
	}
	for _, secret := range []string{webauthSecretText(u.secret), webauthSecretGrouped(u.secret)} {
		if strings.Contains(dump, secret) {
			t.Fatal("the TOTP secret is in the logs or the audit log")
		}
	}
}

// lockOnComplete makes the failure count reach the limit just before
// CompleteLogin runs: the lock lands between the handler's read and the store's check.
type lockOnComplete struct {
	store.Store
	lock func()
}

func (l lockOnComplete) CompleteLogin(ctx context.Context, c store.CompleteLogin, now time.Time, d map[string]string) error {
	l.lock()
	return l.Store.CompleteLogin(ctx, c, now, d)
}

func TestLockLandingMidLoginRefusesTheSession(t *testing.T) {
	ring := testRing(t)
	var e *env
	e = newEnv(t, withKeys(ring), func(d *server.Deps) {
		d.Store = lockOnComplete{d.Store, func() {
			e.exec(`UPDATE users SET totp_failures = 100`)
		}}
	})
	u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	b, _ := e.passwordStep("ann@example.com", goodPW)
	p := b.code(codeNow(u, e, 0))
	if p.status != 200 || !strings.Contains(p.body, "Ask an administrator") || e.cookieFor(b) != nil {
		t.Fatalf("a lock that landed mid-login: %d", p.status)
	}
	if n := e.count(`SELECT count(*) FROM user_sessions`); n != 0 {
		t.Fatalf("%d sessions", n)
	}
}
