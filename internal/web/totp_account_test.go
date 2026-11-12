// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package web_test

import (
	"context"
	"encoding/base32"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/server"
)

var (
	secretRE = regexp.MustCompile(`data-testid="totp-secret">([^<]+)</code>`)
	uriRE    = regexp.MustCompile(`value="(otpauth://[^"]+)" aria-label="Setup URI"`)
	codesRE  = regexp.MustCompile(`(?s)data-testid="recovery-codes">(.*?)</pre>`)
)

// setupSecret starts an enrolment with the password and returns the secret bytes
// and the page.
func setupSecret(t *testing.T, b *browser, password string) ([]byte, page) {
	t.Helper()
	tok := csrf(t, b.get("/account/totp"))
	p := b.post("/account/totp/setup", url.Values{"csrf_token": {tok}, "current_password": {password}})
	if p.status != 200 {
		t.Fatalf("setup: %d\n%s", p.status, p.body)
	}
	m := secretRE.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no secret on the setup page:\n%s", p.body)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(m[1], " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return raw, p
}

func confirm(b *browser, tok, code string) page {
	return b.post("/account/totp/confirm", url.Values{"csrf_token": {tok}, "code": {code}})
}

func recoveryCodes(t *testing.T, p page) []string {
	t.Helper()
	m := codesRE.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no recovery codes on the page:\n%s", p.body)
	}
	return strings.Fields(m[1])
}

func TestEnrolmentFlowThroughRouter(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	registerHost(t, e, "web01")
	u := e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW)
	other := e.browser() // a second session of the same user
	other.login("ann@example.com", goodPW)
	tok := csrf(t, b.get("/account/totp"))
	if p := b.get("/account"); !strings.Contains(p.body, `data-testid="account-totp-card"`) {
		t.Fatal("the account page has no two-factor card")
	}

	// A wrong password is refused, enables nothing and is counted in the PASSWORD backoff.
	for i := 0; i < 5; i++ {
		p := b.post("/account/totp/setup", url.Values{"csrf_token": {tok}, "current_password": {"not the password at all"}})
		if p.status != 200 || !strings.Contains(p.body, "current password is not correct") || secretRE.MatchString(p.body) {
			t.Fatalf("wrong password %d: %d", i, p.status)
		}
	}
	if p := b.post("/account/totp/setup", url.Values{"csrf_token": {tok}, "current_password": {goodPW}}); p.status != 429 {
		t.Fatalf("after 5 wrong passwords the next attempt is refused by the shared backoff: %d", p.status)
	}
	e.advance(time.Minute)

	secret, setup := setupSecret(t, b, goodPW)
	if !strings.Contains(setup.header.Get("Cache-Control"), "no-store") {
		t.Errorf("the setup page is cacheable: %q", setup.header.Get("Cache-Control"))
	}
	if len(secret) != 20 {
		t.Errorf("secret of %d bytes", len(secret))
	}
	m := uriRE.FindStringSubmatch(setup.body)
	if m == nil || !strings.Contains(m[1], "secret="+base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)) ||
		!strings.Contains(m[1], "issuer=ClamFleet") || !strings.Contains(m[1], "ann@example.com") {
		t.Fatalf("setup URI %v", m)
	}
	if strings.Contains(setup.body, `href="otpauth`) || strings.Contains(setup.body, "ZgotmplZ") {
		t.Error("the setup page has an otpauth: link (html/template filters that scheme)")
	}
	// Nothing is enabled before the confirming code.
	if st, _ := e.st.UserTOTP(context.Background(), u.ID); st.Enabled {
		t.Fatal("TOTP enabled by the setup step alone")
	}

	// A wrong confirm code enables nothing and shows the setup page again.
	tok = csrf(t, setup)
	p := confirm(b, tok, wrongCode(secret, e.clock()))
	if p.status != 200 || !strings.Contains(p.body, "That code is not valid") || !secretRE.MatchString(p.body) {
		t.Fatalf("wrong confirm code: %d", p.status)
	}
	if st, _ := e.st.UserTOTP(context.Background(), u.ID); st.Enabled {
		t.Fatal("TOTP enabled by a wrong code")
	}

	// The right code enables it.
	p = confirm(b, tok, testCode(secret, stepAt(e.clock())))
	if p.status != 200 {
		t.Fatalf("confirm: %d\n%s", p.status, p.body)
	}
	if !strings.Contains(p.header.Get("Cache-Control"), "no-store") {
		t.Errorf("the recovery codes page is cacheable: %q", p.header.Get("Cache-Control"))
	}
	codes := recoveryCodes(t, p)
	if len(codes) != 10 {
		t.Fatalf("%d recovery codes shown", len(codes))
	}
	if g := b.get("/"); g.status != 200 {
		t.Fatalf("the enrolling session must survive: %d", g.status)
	}
	if g := other.get("/"); g.status != 303 {
		t.Fatalf("another session of the user must end: %d", g.status)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.totp.enable' AND actor='ann@example.com'`); n != 1 {
		t.Fatalf("%d user.totp.enable rows", n)
	}
	// Shown once: a reload re-posts into "no setup in progress".
	if r := confirm(b, csrf(t, b.get("/account/totp")), testCode(secret, stepAt(e.clock()))); !strings.Contains(r.body, "No setup in progress") {
		t.Fatalf("re-posting the confirmation: %d", r.status)
	}
	// Neither the secret nor any recovery code is in the database file.
	raw := readFile(t, e.dbPath)
	forms := []string{string(secret), base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)}
	for _, c := range codes {
		forms = append(forms, c, strings.ReplaceAll(c, "-", ""))
	}
	for _, f := range forms {
		if strings.Contains(raw, f) {
			t.Fatalf("%q is stored in clear", f)
		}
	}
	// And the new authenticator works at the next sign-in; the confirming code does not
	// (its step is already used), the next step's code does.
	b2, _ := e.passwordStep("ann@example.com", goodPW)
	if r := b2.code(testCode(secret, stepAt(e.clock()))); r.status != 200 || !strings.Contains(r.body, "already used") {
		t.Fatalf("the confirming code was accepted again: %d", r.status)
	}
	if r := b2.code(testCode(secret, stepAt(e.clock())+1)); r.status != 303 {
		t.Fatalf("sign-in with the new authenticator: %d", r.status)
	}
}

func TestPendingEnrolmentIsBoundToItsSession(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	u := e.addUser("ann@example.com", "viewer", goodPW, false)
	a, b := e.browser(), e.browser()
	a.login("ann@example.com", goodPW)
	b.login("ann@example.com", goodPW)
	secret, _ := setupSecret(t, a, goodPW)
	code := testCode(secret, stepAt(e.clock()))

	// Session B of the same user cannot confirm session A's pending secret.
	p := confirm(b, csrf(t, b.get("/account/totp")), code)
	if !strings.Contains(p.body, "No setup in progress") {
		t.Fatalf("session B confirmed A's enrolment: %d", p.status)
	}
	if st, _ := e.st.UserTOTP(context.Background(), u.ID); st.Enabled {
		t.Fatal("TOTP enabled through the wrong session")
	}
	// A pending secret older than 15 minutes is refused, for its own session too.
	e.advance(15*time.Minute + time.Second)
	if p := confirm(a, csrf(t, a.get("/account/totp")), testCode(secret, stepAt(e.clock()))); !strings.Contains(p.body, "No setup in progress") {
		t.Fatalf("an expired pending secret was accepted: %d", p.status)
	}
	// Starting again replaces it, and then it works.
	secret2, setup := setupSecret(t, a, goodPW)
	if p := confirm(a, csrf(t, setup), testCode(secret2, stepAt(e.clock()))); p.status != 200 || len(recoveryCodes(t, p)) != 10 {
		t.Fatalf("confirm after a fresh setup: %d", p.status)
	}
}

func TestReplaceAndRegenerateRecoveryCodes(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	b, _ := e.passwordStep("ann@example.com", goodPW)
	if p := b.code(codeNow(u, e, 0)); p.status != 303 {
		t.Fatalf("sign-in: %d", p.status)
	}
	tok := csrf(t, b.get("/account/totp"))
	if p := b.get("/account/totp"); !strings.Contains(p.body, `data-testid="totp-codes-left">10<`) {
		t.Fatalf("status page: %s", p.body)
	}

	// New recovery codes need the password; then the old ones are dead.
	if p := b.post("/account/totp/recovery-codes", url.Values{"csrf_token": {tok}, "current_password": {"nope nope nope nope"}}); p.status != 200 || strings.Contains(p.body, `data-testid="recovery-codes"`) {
		t.Fatalf("regeneration with a wrong password: %d", p.status)
	}
	p := b.post("/account/totp/recovery-codes", url.Values{"csrf_token": {tok}, "current_password": {goodPW}})
	if p.status != 200 || !strings.Contains(p.header.Get("Cache-Control"), "no-store") {
		t.Fatalf("regeneration: %d", p.status)
	}
	fresh := recoveryCodes(t, p)
	if len(fresh) != 10 || fresh[0] == u.codes[0] {
		t.Fatalf("new codes: %v", fresh)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.totp.recovery.regenerate'`); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
	e.advance(time.Minute)
	b2, _ := e.passwordStep("ann@example.com", goodPW)
	if r := b2.code(u.codes[0]); r.status != 200 || e.cookieFor(b2) != nil {
		t.Fatalf("an old recovery code still works: %d", r.status)
	}
	if r := b2.code(fresh[0]); r.status != 303 {
		t.Fatalf("a new recovery code: %d", r.status)
	}

	// Replace the authenticator: the old secret stops working, the audit says replace.
	e.advance(time.Minute)
	b3, _ := e.passwordStep("ann@example.com", goodPW)
	if r := b3.code(codeNow(u, e, 0)); r.status != 303 {
		t.Fatalf("sign-in before the replacement: %d", r.status)
	}
	newSecret, setup := setupSecret(t, b3, goodPW)
	if r := confirm(b3, csrf(t, setup), testCode(newSecret, stepAt(e.clock()))); r.status != 200 {
		t.Fatalf("replace: %d", r.status)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.totp.replace'`); n != 1 {
		t.Fatalf("%d user.totp.replace rows", n)
	}
	e.advance(time.Minute)
	b4, _ := e.passwordStep("ann@example.com", goodPW)
	if r := b4.code(codeNow(u, e, 0)); r.status == 303 {
		t.Fatal("the replaced authenticator still signs in")
	}
	if r := b4.code(testCode(newSecret, stepAt(e.clock()))); r.status != 303 {
		t.Fatalf("the new authenticator: %d", r.status)
	}
}

func TestDisableTOTP(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	b, _ := e.passwordStep("ann@example.com", goodPW)
	b.code(codeNow(u, e, 0))
	e.advance(time.Minute)
	other, _ := e.passwordStep("ann@example.com", goodPW)
	other.code(codeNow(u, e, 0))
	tok := csrf(t, b.get("/account/totp"))

	if p := b.post("/account/totp/disable", url.Values{"csrf_token": {tok}, "current_password": {"wrong wrong wrong"}}); p.status != 200 || !strings.Contains(p.body, "not correct") {
		t.Fatalf("wrong password: %d", p.status)
	}
	if st, _ := e.st.UserTOTP(context.Background(), u.ID); !st.Enabled {
		t.Fatal("turned off with a wrong password")
	}
	p := b.post("/account/totp/disable", url.Values{"csrf_token": {tok}, "current_password": {goodPW}})
	if p.status != 303 || p.header.Get("Location") != "/account/totp?disabled=1" {
		t.Fatalf("disable: %d %q", p.status, p.header.Get("Location"))
	}
	if st, _ := e.st.UserTOTP(context.Background(), u.ID); st.Enabled || st.Sealed != nil {
		t.Fatalf("still enabled: %+v", st)
	}
	if g := b.get("/"); g.status != 200 {
		t.Fatalf("the current session must survive: %d", g.status)
	}
	if g := other.get("/"); g.status != 303 {
		t.Fatalf("another session must end: %d", g.status)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action='user.totp.disable' AND actor='ann@example.com'`); n != 1 {
		t.Fatalf("%d user.totp.disable rows", n)
	}
	// Password-only sign-in again.
	e.advance(time.Minute)
	if _, p := e.passwordStep("ann@example.com", goodPW); p.header.Get("Location") != "/" {
		t.Fatalf("after turn-off: %q", p.header.Get("Location"))
	}
}

func requireTOTP() opt {
	return console(func(a *server.Auth) { a.Local.TOTPRequired = true })
}

func TestDisableRefusedWhenRequired(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring), requireTOTP())
	u := e.addTOTPUser(ring, "ann@example.com", "viewer", goodPW)
	b, _ := e.passwordStep("ann@example.com", goodPW)
	b.code(codeNow(u, e, 0))
	tok := csrf(t, b.get("/account/totp"))
	if p := b.get("/account/totp"); strings.Contains(p.body, `data-testid="totp-disable-form"`) {
		t.Error("the turn-off form is offered although TOTP is required")
	}
	p := b.post("/account/totp/disable", url.Values{"csrf_token": {tok}, "current_password": {goodPW}})
	if p.status != 409 || !strings.Contains(p.body, "requires two-factor") {
		t.Fatalf("%d", p.status)
	}
	if st, _ := e.st.UserTOTP(context.Background(), u.ID); !st.Enabled {
		t.Fatal("TOTP was turned off although the server requires it")
	}
}

func TestForcedEnrolment(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring), requireTOTP())
	registerHost(t, e, "web01")
	e.addUser("adm@example.com", "admin", goodPW, false)
	b := e.browser()
	b.login("adm@example.com", goodPW) // password-only: they have no TOTP yet (trust on first use)

	// Everything but the enrolment pages and logout is closed, on the server.
	if p := b.get("/"); p.status != 303 || p.header.Get("Location") != "/account/totp" {
		t.Fatalf("GET /: %d %q", p.status, p.header.Get("Location"))
	}
	if p := b.do("GET", "/fleet/rows", map[string]string{"HX-Request": "true"}, nil); p.status != 403 || p.header.Get("HX-Redirect") != "/account/totp" {
		t.Fatalf("htmx: %d %q", p.status, p.header.Get("HX-Redirect"))
	}
	hosts := e.count(`SELECT count(*) FROM hosts`)
	tok := csrf(t, b.get("/account/totp"))
	if p := b.post("/admin/hosts", url.Values{"csrf_token": {tok}, "name": {"intruder"}}); p.status != 403 || e.count(`SELECT count(*) FROM hosts`) != hosts {
		t.Fatalf("an admin POST while un-enrolled: %d", p.status)
	}
	if p := b.get("/account/totp"); p.status != 200 || !strings.Contains(p.body, `data-testid="totp-required-notice"`) {
		t.Fatalf("the enrolment page: %d", p.status)
	}
	// Enrolment itself is not locked out (the setup and confirm pages are open).
	secret, setup := setupSecret(t, b, goodPW)
	if p := confirm(b, csrf(t, setup), testCode(secret, stepAt(e.clock()))); p.status != 200 {
		t.Fatalf("enrolment under the gate: %d", p.status)
	}
	if p := b.get("/"); p.status != 200 {
		t.Fatalf("after enrolment: %d", p.status)
	}
	// Logout works while gated.
	b2 := e.browser()
	b2.login("adm@example.com", goodPW) // already enrolled now: this is a TOTP user
}

func TestForcedEnrolmentLogoutAndMustChangeOrder(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring), requireTOTP())
	e.addUser("newbie@example.com", "viewer", goodPW, true)
	b := e.browser()
	b.login("newbie@example.com", goodPW)
	// The password comes first.
	if p := b.get("/account/totp"); p.status != 303 || p.header.Get("Location") != "/account" {
		t.Fatalf("enrolment page before the password change: %d %q", p.status, p.header.Get("Location"))
	}
	tok := csrf(t, b.get("/account"))
	const newPW = "a different long password"
	p := b.post("/account/password", url.Values{"csrf_token": {tok}, "current_password": {goodPW}, "new_password": {newPW}, "new_password2": {newPW}})
	if p.status != 303 {
		t.Fatalf("password change: %d", p.status)
	}
	// Then the enrolment, in the same session.
	if p := b.get("/"); p.status != 303 || p.header.Get("Location") != "/account/totp" {
		t.Fatalf("after the password change: %d %q", p.status, p.header.Get("Location"))
	}
	// Logout is allowed while gated.
	tok = csrf(t, b.get("/account/totp"))
	if p := b.post("/logout", url.Values{"csrf_token": {tok}}); p.status != 303 || p.header.Get("Location") != "/login" {
		t.Fatalf("logout while gated: %d", p.status)
	}
}

// Switching the setting on applies to sessions that already exist (the gate reads the join).
func TestRequiringTOTPAppliesToExistingSessions(t *testing.T) {
	e := newEnv(t)
	e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW)
	if p := b.get("/"); p.status != 200 {
		t.Fatalf("setup: %d", p.status)
	}
	e2 := e.another(requireTOTP(), withKeys(testRing(t)))
	b.c.Transport = e2.srv.Client().Transport
	b.e = e2
	// The cookie jar is per origin; carry the session cookie to the second server.
	u1, u2 := mustURL(e.srv.URL), mustURL(e2.srv.URL)
	b.c.Jar.SetCookies(u2, b.c.Jar.Cookies(u1))
	if p := b.get("/"); p.status != 303 || p.header.Get("Location") != "/account/totp" {
		t.Fatalf("an existing session after totp_required was switched on: %d %q", p.status, p.header.Get("Location"))
	}
}

func TestNoSecretOrCodeInLogsOrAuditAtEnrolment(t *testing.T) {
	ring := testRing(t)
	e := newEnv(t, withKeys(ring))
	e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW)
	secret, setup := setupSecret(t, b, goodPW)
	wrong := wrongCode(secret, e.clock())
	right := testCode(secret, stepAt(e.clock()))
	confirm(b, csrf(t, setup), wrong)
	p := confirm(b, csrf(t, setup), right)
	codes := recoveryCodes(t, p)
	dump := e.logs.String() + "\n" + auditDump(t, e)
	forms := []string{wrong, right, webauthSecretText(secret), webauthSecretGrouped(secret), "otpauth://", string(secret)}
	for _, c := range codes {
		forms = append(forms, c, strings.ReplaceAll(c, "-", ""))
	}
	for _, f := range forms {
		if strings.Contains(dump, f) {
			t.Fatalf("%q is in the logs or the audit log", f)
		}
	}
}

func TestNoKeyMakesSetupUnavailable(t *testing.T) {
	e := newEnv(t) // no key file
	e.addUser("ann@example.com", "viewer", goodPW, false)
	b := e.browser()
	b.login("ann@example.com", goodPW)
	if p := b.get("/account/totp"); p.status != 200 || !strings.Contains(p.body, `data-testid="totp-unavailable"`) || strings.Contains(p.body, `data-testid="totp-setup-form"`) {
		t.Fatalf("status page without a key: %d", p.status)
	}
	tok := csrf(t, b.get("/account/totp"))
	if p := b.post("/account/totp/setup", url.Values{"csrf_token": {tok}, "current_password": {goodPW}}); p.status != 503 {
		t.Fatalf("setup without a key: %d", p.status)
	}
	if p := b.post("/account/totp/confirm", url.Values{"csrf_token": {tok}, "code": {"123456"}}); p.status != 503 {
		t.Fatalf("confirm without a key: %d", p.status)
	}
}
