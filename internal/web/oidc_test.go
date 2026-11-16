// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package web_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/extauth"
	"github.com/clamfleet/clamfleet/internal/server"
	"github.com/clamfleet/clamfleet/internal/testoidc"
	"github.com/clamfleet/clamfleet/internal/testtls"
	"github.com/clamfleet/clamfleet/internal/web"
)

// lateOIDC lets the console be built before the real client: the client needs the console's own URL
// (the redirect URI), which only exists once the test server is up.
type lateOIDC struct {
	mu sync.Mutex
	p  web.OIDCProvider
}

func (l *lateOIDC) get() web.OIDCProvider { l.mu.Lock(); defer l.mu.Unlock(); return l.p }
func (l *lateOIDC) Begin(ctx context.Context) (extauth.AuthRequest, error) {
	return l.get().Begin(ctx)
}
func (l *lateOIDC) Exchange(ctx context.Context, code, verifier, nonce string) (extauth.Identity, error) {
	return l.get().Exchange(ctx, code, verifier, nonce)
}

type oidcRig struct {
	e    *env
	idp  *testoidc.Server
	pool *x509.CertPool
	idpC *http.Client // plays the browser's visit to the identity provider
	cb   string
	cfg  server.Config
}

func newOIDCRig(t *testing.T, mut func(*server.Config)) *oidcRig {
	t.Helper()
	dir := t.TempDir()
	b, err := testtls.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := &oidcRig{}
	var e *env
	idp, err := testoidc.Start(testoidc.Options{CertFile: b.Cert, KeyFile: b.Key, Now: func() time.Time { return e.clock() }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)
	secretFile := filepath.Join(dir, "client-secret")
	if err := os.WriteFile(secretFile, []byte(testoidc.ClientSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := server.DefaultConfig()
	cfg.PublicURL = "https://console.example" // replaced below once the console's URL is known
	o := &cfg.Auth.OIDC
	o.Enabled, o.Issuer, o.ClientID, o.ClientSecretFile, o.CAFile = true, idp.Issuer(), testoidc.ClientID, secretFile, b.CA
	o.AdminValues, o.ViewerValues, o.Timeout = []string{"clamfleet-admins"}, []string{"clamfleet-viewers"}, 2*time.Second
	if mut != nil {
		mut(&cfg)
	}
	late := &lateOIDC{}
	e = newEnv(t, func(d *server.Deps) {
		d.Console = cfg.Auth
		d.OIDC = late
	})
	cfg.PublicURL = e.srv.URL
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the rig's configuration is invalid: %v", err)
	}
	client, err := server.BuildOIDC(cfg, e.clock)
	if err != nil {
		t.Fatal(err)
	}
	late.p = client
	r.cb = e.srv.URL + "/login/oidc/callback"
	idp.AllowRedirect(r.cb)
	idp.AddUser("ann", map[string]any{"name": "Ann Example", "email": "ann@example.org", "email_verified": true, "groups": []string{"clamfleet-admins"}})
	idp.AddUser("bob", map[string]any{"email": "bob@example.org", "email_verified": false, "groups": []string{"clamfleet-viewers"}})
	idp.AddUser("carol", map[string]any{"email": "carol@example.org", "email_verified": true})
	pem, _ := os.ReadFile(b.CA)
	r.pool = x509.NewCertPool()
	r.pool.AppendCertsFromPEM(pem)
	r.e, r.idp, r.cfg = e, idp, cfg
	r.idpC = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: r.pool, MinVersion: tls.VersionTLS12}}}
	return r
}

// start posts the SSO form and returns the 303 response.
func (r *oidcRig) start(b *browser, next string) page {
	f := url.Values{}
	if next != "" {
		f.Set("next", next)
	}
	return b.post("/login/oidc", f)
}

var continueRE = regexp.MustCompile(`data-testid="sso-continue"`)
var hrefRE = regexp.MustCompile(`<a href="([^"]+)" data-testid="sso-continue"`)
var metaRE = regexp.MustCompile(`<meta http-equiv="refresh" content="0; url=([^"]+)">`)

// authURL reads where the start page sends the browser: the meta refresh and the link must agree.
func authURL(t *testing.T, p page) string {
	t.Helper()
	if p.status != 200 || !continueRE.MatchString(p.body) {
		t.Fatalf("start: %d\n%s", p.status, p.body)
	}
	m, l := metaRE.FindStringSubmatch(p.body), hrefRE.FindStringSubmatch(p.body)
	if m == nil || l == nil || html.UnescapeString(m[1]) != html.UnescapeString(l[1]) {
		t.Fatalf("the meta refresh and the link differ: %v %v", m, l)
	}
	return html.UnescapeString(m[1])
}

// choose plays the visit to the identity provider: open the page, click the user, and return the URL
// (path and query) of the console callback the provider sent the browser to.
func (r *oidcRig) choose(t *testing.T, authURL, user string) string {
	t.Helper()
	resp, err := r.idpC.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("authorization endpoint: %d", resp.StatusCode)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	q.Set("user", user)
	resp, err = r.idpC.Get(r.idp.Issuer() + "/authorize/pick?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != 302 {
		t.Fatalf("pick: %d", resp.StatusCode)
	}
	return loc.RequestURI()
}

// signIn runs the whole flow for user in browser b and returns the callback response.
func (r *oidcRig) signIn(t *testing.T, b *browser, user, next string) page {
	t.Helper()
	cb := r.choose(t, authURL(t, r.start(b, next)), user)
	return b.get(cb)
}

func TestOIDCFullFlowThroughTheRouter(t *testing.T) {
	r := newOIDCRig(t, nil)
	e := r.e
	b := e.browser()

	// The start form: a page that takes the browser to the provider (not a 303: Chromium blocks a redirect
	// out of a form under form-action 'self'), with S256, a state and a nonce; the state cookie's attributes.
	p := r.start(b, "/events")
	if csp := p.header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self'") || strings.Contains(csp, "form-action 'self' ") {
		t.Fatalf("the policy must stay strict: %q", csp)
	}
	authLoc := authURL(t, p)
	loc, _ := url.Parse(authLoc)
	q := loc.Query()
	if loc.Host != strings.TrimPrefix(r.idp.Issuer(), "https://") || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		q.Get("state") == "" || q.Get("nonce") == "" || q.Get("response_mode") != "" || q.Get("redirect_uri") != r.cb || q.Get("client_id") != testoidc.ClientID {
		t.Fatalf("%s", loc)
	}
	var sc *http.Cookie
	for _, c := range (&http.Response{Header: p.header}).Cookies() {
		if c.Name == "__Host-clamfleet_oidc" {
			sc = c
		}
	}
	if sc == nil || !sc.Secure || !sc.HttpOnly || sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" || sc.Domain != "" || sc.MaxAge != 600 || !strings.HasPrefix(sc.Value, "cfo_") {
		t.Fatalf("state cookie: %+v", sc)
	}
	if e.count(`SELECT count(*) FROM oidc_login_states`) != 1 {
		t.Fatal("no state row")
	}
	if strings.Contains(e.dbHas("oidc_login_states", "token_hash"), sc.Value) {
		t.Fatal("the state cookie token is stored in clear")
	}

	// The callback: a session, the state row gone, the user created from iss + sub, and the next path kept.
	cb := r.choose(t, authLoc, "ann")
	done := b.get(cb)
	if done.status != 303 || done.header.Get("Location") != "/events" || e.cookieFor(b) == nil {
		t.Fatalf("callback: %d %q", done.status, done.header.Get("Location"))
	}
	if e.count(`SELECT count(*) FROM oidc_login_states`) != 0 {
		t.Fatal("the state row survived its use")
	}
	if e.count(`SELECT count(*) FROM users WHERE auth_source='oidc' AND external_id=? AND external_name='ann' AND password_hash IS NULL AND role='admin' AND email='ann@example.org'`, r.idp.Issuer()+" ann") != 1 {
		t.Fatal("the user row is not what an OIDC sign-in must leave")
	}
	if got := e.auditDetails("user.login"); len(got) != 1 || !strings.Contains(got[0], `"source":"oidc"`) {
		t.Fatalf("%v", got)
	}
	home := b.get("/")
	if home.status != 200 || !strings.Contains(home.body, `data-testid="current-user">ann@example.org (admin)`) || !strings.Contains(home.body, `data-testid="nav-admin"`) {
		t.Fatalf("%d", home.status)
	}
	acc := b.get("/account")
	if !strings.Contains(acc.body, `data-testid="account-source">OpenID Connect<`) || strings.Contains(acc.body, `data-testid="account-form"`) {
		t.Fatal("the account page of an OIDC user")
	}
}

// The callback URL works once. A copy of it, replayed with the same cookie, finds no state row.
func TestOIDCReplayedCallbackIsRefused(t *testing.T) {
	r := newOIDCRig(t, nil)
	e := r.e
	b := e.browser()
	p := r.start(b, "")
	cb := r.choose(t, authURL(t, p), "ann")
	cookie := stateCookie(t, e, b)
	if done := b.get(cb); done.status != 303 {
		t.Fatalf("%d", done.status)
	}
	// The attacker (or a back button) sends the same URL with the same cookie again.
	attacker := e.browser()
	req, _ := http.NewRequest("GET", e.srv.URL+cb, nil)
	req.AddCookie(cookie)
	resp, err := attacker.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("a replayed callback: %d, want the expired page", resp.StatusCode)
	}
	if e.count(`SELECT count(*) FROM user_sessions`) != 1 {
		t.Fatalf("%d sessions after a replay", e.count(`SELECT count(*) FROM user_sessions`))
	}
}

// The right state parameter with another browser's cookie (or none): refused, and the original browser's
// sign-in is not harmed by it.
func TestOIDCCallbackInAnotherBrowserIsRefused(t *testing.T) {
	r := newOIDCRig(t, nil)
	e := r.e
	victim := e.browser()
	p := r.start(victim, "")
	cb := r.choose(t, authURL(t, p), "ann")

	other := e.browser()
	if got := other.get(cb); got.status != 400 || !strings.Contains(got.body, `data-testid="error-sso-expired"`) || e.cookieFor(other) != nil {
		t.Fatalf("no cookie: %d", got.status)
	}
	// A state cookie of a sign-in this browser started itself does not help either.
	mine := r.start(other, "")
	_ = mine
	if got := other.get(cb); got.status != 400 || e.cookieFor(other) != nil {
		t.Fatalf("another browser's own state: %d", got.status)
	}
	if e.count(`SELECT count(*) FROM users`) != 0 {
		t.Fatal("a user was created")
	}
	// The victim's own callback still works.
	if got := victim.get(cb); got.status != 303 || e.cookieFor(victim) == nil {
		t.Fatalf("the victim's sign-in was spoiled: %d", got.status)
	}
}

// A wrong state parameter ends the sign-in, and the state row is gone: the right one cannot be retried.
func TestOIDCStateParameterMismatchBurnsTheState(t *testing.T) {
	r := newOIDCRig(t, nil)
	e := r.e
	b := e.browser()
	p := r.start(b, "")
	cb := r.choose(t, authURL(t, p), "ann")
	bad := strings.Replace(cb, "state=", "state=x", 1)
	if got := b.get(bad); got.status != 400 || !strings.Contains(got.body, `data-testid="error-sso-expired"`) || e.cookieFor(b) != nil {
		t.Fatalf("%d", got.status)
	}
	if e.count(`SELECT count(*) FROM oidc_login_states`) != 0 {
		t.Fatal("the state row survived a failed callback")
	}
	if got := b.get(cb); got.status != 400 {
		t.Fatalf("the right URL after a failed one: %d", got.status)
	}
}

func TestOIDCExpiredStateIsRefused(t *testing.T) {
	r := newOIDCRig(t, nil)
	b := r.e.browser()
	p := r.start(b, "")
	cb := r.choose(t, authURL(t, p), "ann")
	r.e.advance(11 * time.Minute)
	if got := b.get(cb); got.status != 400 || r.e.cookieFor(b) != nil {
		t.Fatalf("%d", got.status)
	}
}

// The fake misbehaves; every bad ID token is refused and creates no user and no session.
func TestOIDCBadTokensCreateNoUser(t *testing.T) {
	for name, sc := range map[string]testoidc.Script{
		"wrong iss":   {Claims: func(c map[string]any) { c["iss"] = "https://evil.example" }},
		"wrong aud":   {Claims: func(c map[string]any) { c["aud"] = "other" }},
		"wrong azp":   {Claims: func(c map[string]any) { c["azp"] = "other" }},
		"wrong nonce": {Claims: func(c map[string]any) { c["nonce"] = "replayed" }},
		"expired":     {Claims: func(c map[string]any) { c["exp"] = int64(1) }},
		"alg none":    {Header: func(h map[string]any) { h["alg"] = "none" }},
		"a JWE":       {RawIDToken: "a.b.c.d.e"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newOIDCRig(t, nil)
			r.idp.SetScript(sc)
			b := r.e.browser()
			got := r.signIn(t, b, "ann", "")
			if got.status != 403 || r.e.cookieFor(b) != nil {
				t.Fatalf("%d\n%s", got.status, got.body)
			}
			if r.e.count(`SELECT count(*) FROM users`) != 0 || r.e.count(`SELECT count(*) FROM user_sessions`) != 0 {
				t.Fatal("a user or a session was created from a bad token")
			}
			if len(r.e.auditDetails("user.login.failed")) != 1 {
				t.Fatal("the refusal was not audited")
			}
		})
	}
}

func TestOIDCNoRoleIsRefusedWithAMessage(t *testing.T) {
	r := newOIDCRig(t, nil)
	b := r.e.browser()
	got := r.signIn(t, b, "carol", "") // carol has no groups claim at all
	if got.status != 403 || !strings.Contains(got.body, `data-testid="error-no-role"`) || r.e.cookieFor(b) != nil || r.e.count(`SELECT count(*) FROM users`) != 0 {
		t.Fatalf("%d", got.status)
	}
}

// An unverified email is not stored; the actor label is then oidc:<name>.
func TestOIDCUnverifiedEmailIsNotStored(t *testing.T) {
	r := newOIDCRig(t, nil)
	e := r.e
	b := e.browser()
	if got := r.signIn(t, b, "bob", ""); got.status != 303 {
		t.Fatalf("%d", got.status)
	}
	if e.count(`SELECT count(*) FROM users WHERE external_name='bob' AND email IS NULL AND role='viewer'`) != 1 {
		t.Fatal("the unverified email was stored")
	}
	home := b.get("/")
	if !strings.Contains(home.body, `data-testid="current-user">oidc:bob (viewer)`) {
		t.Fatal("the actor label is not oidc:bob")
	}
	if got := e.auditDetails("user.login"); len(got) != 1 || !strings.HasPrefix(got[0], "oidc:bob | oidc:bob |") {
		t.Fatalf("%v", got)
	}
	// An admin action by this user is attributed to oidc:bob (here: logout).
	if p := b.post("/logout", url.Values{"csrf_token": {csrf(t, home)}}); p.status != 303 {
		t.Fatalf("%d", p.status)
	}
	if got := e.auditDetails("user.logout"); len(got) != 1 || !strings.HasPrefix(got[0], "oidc:bob | oidc:bob |") {
		t.Fatalf("%v", got)
	}
}

// Decision 19, router level: the email an IdP presents may not belong to another user, however it arrives.
func TestOIDCEmailCollisionsAreRefused(t *testing.T) {
	r := newOIDCRig(t, nil)
	e := r.e
	boss := e.addUser("boss@example.org", "admin", goodPW, false)
	bossBrowser := e.browser()
	bossBrowser.login("boss@example.org", goodPW)

	// 1. An existing external user whose IdP email moves to the local admin's address.
	b := e.browser()
	if got := r.signIn(t, b, "ann", ""); got.status != 303 {
		t.Fatalf("first sign-in: %d", got.status)
	}
	r.idp.SetClaim("ann", "email", "boss@example.org")
	b2 := e.browser()
	if got := r.signIn(t, b2, "ann", ""); got.status != 403 || e.cookieFor(b2) != nil {
		t.Fatalf("collision with a local admin: %d", got.status)
	}
	if e.count(`SELECT count(*) FROM users WHERE external_name='ann' AND email='ann@example.org'`) != 1 {
		t.Fatal("the external user's stored email changed")
	}
	if e.count(`SELECT count(*) FROM users WHERE id=? AND auth_source='local' AND role='admin' AND email='boss@example.org'`, boss.ID) != 1 {
		t.Fatal("the local admin changed")
	}
	if bossBrowser.get("/").status != 200 {
		t.Fatal("the local admin's session was touched")
	}
	if got := e.auditDetails("user.login.failed"); len(got) != 1 || !strings.Contains(got[0], "email in use") {
		t.Fatalf("%v", got)
	}

	// 2. A new external user presenting another external user's address.
	r.idp.AddUser("eve", map[string]any{"email": "ann@example.org", "email_verified": true, "groups": []string{"clamfleet-viewers"}})
	b3 := e.browser()
	if got := r.signIn(t, b3, "eve", ""); got.status != 403 || e.cookieFor(b3) != nil || e.count(`SELECT count(*) FROM users`) != 2 {
		t.Fatalf("collision with another external user: %d", got.status)
	}
}

// error=access_denied: an error page that shows the provider's description escaped and cut to 200 bytes.
func TestOIDCProviderErrorPage(t *testing.T) {
	r := newOIDCRig(t, nil)
	b := r.e.browser()
	p := r.start(b, "")
	loc, _ := url.Parse(authURL(t, p))
	st := loc.Query().Get("state")
	long := "<script>alert(1)</script>" + strings.Repeat("x", 400)
	got := b.get("/login/oidc/callback?error=access_denied&error_description=" + url.QueryEscape(long) + "&state=" + url.QueryEscape(st))
	if got.status != 403 || r.e.cookieFor(b) != nil || strings.Contains(got.body, "<script>alert(1)") || !strings.Contains(got.body, "&lt;script&gt;alert(1)") {
		t.Fatalf("%d\n%s", got.status, got.body)
	}
	if strings.Count(got.body, "x") > 200+80 { // 200 bytes of description plus the letters of the page's own text
		t.Fatal("the description was not cut")
	}
	if r.e.count(`SELECT count(*) FROM oidc_login_states`) != 0 {
		t.Fatal("the state survived an error callback")
	}
	// An error callback with the wrong state is the expired page, not the provider's text.
	_ = r.start(b, "")
	if got := b.get("/login/oidc/callback?error=access_denied&state=nope"); got.status != 400 {
		t.Fatalf("%d", got.status)
	}
}

// The provider is down when the first sign-in starts: SSO shows an error, the console works, and SSO comes back.
func TestOIDCProviderDownThenUp(t *testing.T) {
	r := newOIDCRig(t, nil)
	e := r.e
	r.idp.SetScript(testoidc.Script{DiscoveryRedirectTo: "https://nowhere.example/"})
	b := e.browser()
	if lp := b.get("/login"); lp.status != 200 || !strings.Contains(lp.body, `data-testid="login-sso-submit"`) {
		t.Fatalf("the login page: %d", lp.status)
	}
	if p := r.start(b, ""); p.status != 503 || !strings.Contains(p.body, `data-testid="error-sso-unavailable"`) {
		t.Fatalf("%d", p.status)
	}
	if e.count(`SELECT count(*) FROM oidc_login_states`) != 0 {
		t.Fatal("a state row for a sign-in that never started")
	}
	r.idp.SetScript(testoidc.Script{})
	if got := r.signIn(t, b, "ann", ""); got.status != 303 {
		t.Fatalf("after the provider came back: %d", got.status)
	}
}

func TestOIDCDiscoveryFaultsShowAnError(t *testing.T) {
	for name, sc := range map[string]testoidc.Script{
		"issuer differs":   {DiscoveryIssuer: "https://other.example"},
		"plain http token": {TokenEndpoint: "http://idp.example/token"},
		"257 KiB":          {DiscoveryPadBytes: 257 << 10},
		"not json":         {DiscoveryContentType: "text/plain"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newOIDCRig(t, nil)
			r.idp.SetScript(sc)
			if p := r.start(r.e.browser(), ""); p.status != 503 {
				t.Fatalf("%d", p.status)
			}
		})
	}
}

func TestOIDCOffMeansNoRoutesAndNoButton(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	if lp := b.get("/login"); strings.Contains(lp.body, "login-sso") {
		t.Fatal("an SSO button although OIDC is off")
	}
	if p := b.post("/login/oidc", url.Values{}); p.status != 404 {
		t.Fatalf("%d", p.status)
	}
	if p := b.get("/login/oidc/callback?code=x&state=y"); p.status != 404 {
		t.Fatalf("%d", p.status)
	}
}

// The start form is a cross-site POST target only for the console's own pages: a cross-site one is refused.
func TestOIDCStartRefusesCrossSitePosts(t *testing.T) {
	r := newOIDCRig(t, nil)
	b := r.e.browser()
	p := b.do("POST", "/login/oidc", map[string]string{"Sec-Fetch-Site": "cross-site"}, url.Values{})
	if p.status != 403 {
		t.Fatalf("%d", p.status)
	}
	if r.e.count(`SELECT count(*) FROM oidc_login_states`) != 0 {
		t.Fatal("a state row for a cross-site start")
	}
}

// Decision 21: an OIDC user is not gated by totp_required (the provider owns the second factor).
func TestOIDCUsersAreNotTOTPGated(t *testing.T) {
	r := newOIDCRig(t, func(c *server.Config) { c.Auth.Local.TOTPRequired = true })
	b := r.e.browser()
	if got := r.signIn(t, b, "ann", ""); got.status != 303 || got.header.Get("Location") != "/" {
		t.Fatalf("%d", got.status)
	}
	if p := b.get("/"); p.status != 200 {
		t.Fatalf("an OIDC user is gated: %d", p.status)
	}
}

// Switching OIDC off ends the OIDC users' sessions.
func TestOIDCSessionsEndWhenOIDCIsSwitchedOff(t *testing.T) {
	r := newOIDCRig(t, nil)
	b := r.e.browser()
	r.signIn(t, b, "ann", "")
	e2 := r.e.another(console(nil))
	if p := carry(t, r.e, e2, b).get("/"); p.status != http.StatusSeeOther || p.header.Get("Location") != "/login" {
		t.Fatalf("%d %q", p.status, p.header.Get("Location"))
	}
}

// With local sign-in and LDAP off, the form is hidden and the SSO button is the way in.
func TestOIDCOnlyLoginPage(t *testing.T) {
	r := newOIDCRig(t, func(c *server.Config) { c.Auth.Local.Enabled = false })
	lp := r.e.browser().get("/login")
	if !strings.Contains(lp.body, `data-testid="login-disabled"`) || strings.Contains(lp.body, `data-testid="login-form"`) || !strings.Contains(lp.body, `data-testid="login-sso-submit">Single sign-on<`) {
		t.Fatal("login page")
	}
	b := r.e.browser()
	if got := r.signIn(t, b, "ann", ""); got.status != 303 {
		t.Fatalf("%d", got.status)
	}
}

// Nothing secret in a log line or an audit row: the client secret, the code, the tokens, the verifier,
// the state and the nonce. (The request log records the path only, never the query.)
func TestOIDCNoSecretInLogsAndAudit(t *testing.T) {
	r := newOIDCRig(t, nil)
	e := r.e
	b := e.browser()
	p := r.start(b, "")
	authLoc := authURL(t, p)
	loc, _ := url.Parse(authLoc)
	state, nonce := loc.Query().Get("state"), loc.Query().Get("nonce")
	cb := r.choose(t, authLoc, "ann")
	code := mustURL("http://x" + cb).Query().Get("code")
	if got := b.get(cb); got.status != 303 {
		t.Fatalf("%d", got.status)
	}
	// A failing one too, so the failure paths are in the logs.
	r.idp.SetScript(testoidc.Script{Claims: func(c map[string]any) { c["nonce"] = "wrong" }})
	r.signIn(t, e.browser(), "ann", "")
	tk := r.idp.Tokens()
	if len(tk) != 2 || tk[0].IDToken == "" || !tk[0].HasVerifier {
		t.Fatalf("%+v", tk)
	}
	logs := e.logs.String()
	var audit strings.Builder
	for _, a := range []string{"user.login", "user.login.failed", "user.add"} {
		audit.WriteString(strings.Join(e.auditDetails(a), "\n"))
	}
	for name, secret := range map[string]string{"client secret": testoidc.ClientSecret, "code": code, "verifier": tk[0].Verifier,
		"id token": tk[0].IDToken, "access token": tk[0].AccessToken, "state": state, "nonce": nonce, "bad id token": tk[1].IDToken} {
		if secret == "" {
			t.Fatalf("%s: empty, the test would pass vacuously", name)
		}
		if strings.Contains(logs, secret) || strings.Contains(audit.String(), secret) {
			t.Fatalf("the %s is in a log line or the audit log", name)
		}
	}
}

// helpers ---------------------------------------------------------------------------------------------------

// stateCookie returns the OIDC state cookie the browser holds.
func stateCookie(t *testing.T, e *env, b *browser) *http.Cookie {
	t.Helper()
	u, _ := url.Parse(e.srv.URL)
	for _, c := range b.c.Jar.Cookies(u) {
		if strings.HasSuffix(c.Name, "clamfleet_oidc") {
			return c
		}
	}
	t.Fatal("no state cookie")
	return nil
}

// dbHas returns the text of a column of every row, for "is it stored in clear" checks.
func (e *env) dbHas(table, col string) string {
	e.t.Helper()
	raw, err := openRaw(e.dbPath)
	if err != nil {
		e.t.Fatal(err)
	}
	defer raw.Close()
	rows, err := raw.Query(`SELECT cast(` + col + ` as text) FROM ` + table)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var sb strings.Builder
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		sb.WriteString(s + "\n")
	}
	return sb.String()
}

// The refusal paths log too ("oidc: sign-in refused"), and the callback URL they are about carries the
// code and the state: neither may reach a log line or an audit row on the replayed, expired and
// state-mismatch paths, nor the provider's error text path.
func TestOIDCRefusalPathsLogNoCodeOrState(t *testing.T) {
	r := newOIDCRig(t, nil)
	e := r.e
	secrets := map[string]string{}
	note := func(name, cb string) {
		q := mustURL("http://x" + cb).Query()
		secrets[name+" code"], secrets[name+" state"] = q.Get("code"), q.Get("state")
	}

	// Replayed: the callback works once, then the same URL with the same cookie again.
	b := e.browser()
	authLoc := authURL(t, r.start(b, ""))
	cb := r.choose(t, authLoc, "ann")
	note("replayed", cb)
	cookie := stateCookie(t, e, b)
	if got := b.get(cb); got.status != 303 {
		t.Fatalf("%d", got.status)
	}
	again, _ := http.NewRequest("GET", e.srv.URL+cb, nil)
	again.AddCookie(cookie)
	resp, err := e.browser().c.Do(again)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("replay: %d", resp.StatusCode)
	}

	// Expired.
	b = e.browser()
	cb = r.choose(t, authURL(t, r.start(b, "")), "ann")
	note("expired", cb)
	e.advance(11 * time.Minute)
	if got := b.get(cb); got.status != 400 {
		t.Fatalf("expired: %d", got.status)
	}

	// State parameter mismatch: the tampered value is a secret of the attacker's request, too.
	b = e.browser()
	cb = r.choose(t, authURL(t, r.start(b, "")), "ann")
	note("mismatch", cb)
	bad := strings.Replace(cb, "state=", "state=tampered-state-value-", 1)
	secrets["mismatch tampered state"] = mustURL("http://x" + bad).Query().Get("state")
	if got := b.get(bad); got.status != 400 {
		t.Fatalf("mismatch: %d", got.status)
	}

	// Refused by Exchange: the code is redeemed but the ID token fails a check (a wrong nonce), which logs
	// "oidc: sign-in refused" with the check's reason from the Exchange branch.
	r.idp.SetScript(testoidc.Script{Claims: func(c map[string]any) { c["nonce"] = "wrong" }})
	b = e.browser()
	cb = r.choose(t, authURL(t, r.start(b, "")), "ann")
	note("exchange-refused", cb)
	if got := b.get(cb); got.status != 403 {
		t.Fatalf("exchange refusal: %d", got.status)
	}
	if tk := r.idp.Tokens(); tk[len(tk)-1].IDToken == "" {
		t.Fatal("the provider did not issue the token the test is about")
	} else {
		secrets["exchange-refused id token"] = tk[len(tk)-1].IDToken
	}
	r.idp.SetScript(testoidc.Script{})

	// The provider's error path.
	b = e.browser()
	loc := mustURL(authURL(t, r.start(b, "")))
	st := loc.Query().Get("state")
	secrets["provider-error state"] = st
	if got := b.get("/login/oidc/callback?error=access_denied&state=" + url.QueryEscape(st)); got.status != 403 {
		t.Fatalf("provider error: %d", got.status)
	}

	logs := e.logs.String()
	if !strings.Contains(logs, "oidc: sign-in refused") {
		t.Fatal("the refusal log line is not there: the test would pass vacuously")
	}
	var audit strings.Builder
	for _, a := range []string{"user.login", "user.login.failed"} {
		audit.WriteString(strings.Join(e.auditDetails(a), "\n"))
	}
	for name, secret := range secrets {
		if len(secret) < 8 {
			t.Fatalf("%s is %q: the test would pass vacuously", name, secret)
		}
		if strings.Contains(logs, secret) || strings.Contains(audit.String(), secret) {
			t.Fatalf("the %s is in a log line or the audit log", name)
		}
	}
}

// Only the code flow exists: the callback never reads an id_token (or access_token) from the URL, however
// well formed and however mapped to an admin. A front-channel token would need signature verification, which
// this implementation does not do (decision 17, docs/auth.md), so accepting one would be a forgery hole.
func TestOIDCCallbackIgnoresAFrontChannelIDToken(t *testing.T) {
	r := newOIDCRig(t, nil)
	e := r.e
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	forged := enc(map[string]any{"alg": "RS256"}) + "." + enc(map[string]any{
		"iss": r.idp.Issuer(), "aud": testoidc.ClientID, "sub": "forged", "preferred_username": "forged",
		"iat": e.clock().Unix(), "exp": e.clock().Add(time.Hour).Unix(), "groups": []string{"clamfleet-admins"},
	}) + ".c2ln"
	for name, extra := range map[string]string{
		"no code":      "",
		"a bogus code": "&code=not-a-code-the-provider-issued",
	} {
		b := e.browser()
		loc, _ := url.Parse(authURL(t, r.start(b, "")))
		st := url.QueryEscape(loc.Query().Get("state"))
		got := b.get("/login/oidc/callback?state=" + st + "&id_token=" + url.QueryEscape(forged) + "&access_token=x" + extra)
		if got.status == http.StatusSeeOther || e.cookieFor(b) != nil {
			t.Fatalf("%s: a front-channel id_token signed someone in (%d)", name, got.status)
		}
		if e.count(`SELECT count(*) FROM users`) != 0 || e.count(`SELECT count(*) FROM user_sessions`) != 0 {
			t.Fatalf("%s: a user or a session was created from a front-channel token", name)
		}
	}
}

// One client IP may have only MaxOIDCStartsPerIP sign-ins in progress, so a single host cannot fill the
// table of states and switch SSO off for everybody. The 16th start is refused (429) and stores nothing; the
// slots come back when the states expire.
func TestOIDCStartsAreBoundedPerClientIP(t *testing.T) {
	r := newOIDCRig(t, nil)
	e := r.e
	for i := 0; i < server.MaxOIDCStartsPerIP; i++ {
		if p := r.start(e.browser(), ""); p.status != 200 {
			t.Fatalf("start %d: %d", i, p.status)
		}
	}
	p := r.start(e.browser(), "")
	if p.status != http.StatusTooManyRequests || p.header.Get("Retry-After") == "" || !strings.Contains(p.body, `data-testid="error-sso-unavailable"`) {
		t.Fatalf("over the bound: %d", p.status)
	}
	if n := e.count(`SELECT count(*) FROM oidc_login_states`); n != server.MaxOIDCStartsPerIP {
		t.Fatalf("%d state rows, want %d: the refused start must store nothing", n, server.MaxOIDCStartsPerIP)
	}
	e.advance(11 * time.Minute)
	if p := r.start(e.browser(), ""); p.status != 200 {
		t.Fatalf("after the states expired: %d", p.status)
	}
}
