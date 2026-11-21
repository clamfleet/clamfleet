// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package extauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/testoidc"
	"github.com/clamfleet/clamfleet/internal/testtls"
)

const redirectURL = "https://127.0.0.1:1/login/oidc/callback"

type oidcRig struct {
	srv   *testoidc.Server
	pool  *x509.CertPool
	cfg   OIDCConfig
	clock time.Time
}

func newOIDCRig(t *testing.T) *oidcRig {
	t.Helper()
	b, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &oidcRig{clock: time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC)}
	r.srv, err = testoidc.Start(testoidc.Options{CertFile: b.Cert, KeyFile: b.Key, RedirectURIs: []string{redirectURL}, Now: func() time.Time { return r.clock }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.srv.Close)
	pem, _ := os.ReadFile(b.CA)
	r.pool = x509.NewCertPool()
	r.pool.AppendCertsFromPEM(pem)
	r.srv.AddUser("ann", map[string]any{"name": "Ann Example", "email": "Ann@Example.org", "email_verified": true, "groups": []string{"clamfleet-admins"}})
	r.srv.AddUser("bob", map[string]any{"groups": []string{"clamfleet-viewers"}, "email": "bob@example.org", "email_verified": false})
	r.srv.AddUser("carol", map[string]any{}) // no groups claim at all (what Keycloak sends for a user without groups)
	r.cfg = OIDCConfig{
		Issuer: r.srv.Issuer(), ClientID: testoidc.ClientID, ClientSecret: testoidc.ClientSecret, ClientAuth: "basic",
		RedirectURL: redirectURL, Scopes: []string{"openid", "email", "profile"}, RootCAs: r.pool, Timeout: 2 * time.Second,
		RoleClaim: "groups", AdminValues: []string{"clamfleet-admins"}, ViewerValues: []string{"clamfleet-viewers"},
		Now: func() time.Time { return r.clock },
	}
	return r
}

func (r *oidcRig) client(t *testing.T) *OIDCClient {
	t.Helper()
	c, err := NewOIDCClient(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var browser = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 5 * time.Second}

// signIn plays the browser: open the authorization URL, choose the user, follow the redirect, and hand the
// code to Exchange. The page is fetched over the fake's TLS with the rig's CA.
func (r *oidcRig) signIn(t *testing.T, c *OIDCClient, user string) (Identity, error) {
	t.Helper()
	req, err := c.Begin(context.Background())
	if err != nil {
		return Identity{}, err
	}
	code := r.pick(t, req, user)
	return c.Exchange(context.Background(), code, req.CodeVerifier, req.Nonce)
}

func (r *oidcRig) pick(t *testing.T, req AuthRequest, user string) string {
	t.Helper()
	hc := &http.Client{CheckRedirect: browser.CheckRedirect, Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsFor(r.pool)}}
	u, _ := url.Parse(req.URL)
	resp, err := hc.Get(u.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("authorization endpoint: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	q := u.Query()
	q.Set("user", user)
	resp, err = hc.Get(r.srv.Issuer() + "/authorize/pick?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("state") != req.State || loc.Query().Get("code") == "" {
		t.Fatalf("callback %s", resp.Header.Get("Location"))
	}
	return loc.Query().Get("code")
}

func TestOIDCFullFlow(t *testing.T) {
	r := newOIDCRig(t)
	c := r.client(t)
	id, err := r.signIn(t, c, "ann")
	if err != nil {
		t.Fatal(err)
	}
	if id.Source != "oidc" || id.ExternalID != r.srv.Issuer()+" ann" || id.Role != "admin" || id.Email != "ann@example.org" ||
		id.DisplayName != "Ann Example" || id.ExternalName != "ann" || id.DN != "" {
		t.Fatalf("%+v", id)
	}
	// What the provider saw: S256 with a challenge, the verifier at the token endpoint, basic client authentication.
	az := r.srv.Authorizes()
	if len(az) != 1 || az[0].Query.Get("code_challenge_method") != "S256" || az[0].Query.Get("code_challenge") == "" ||
		az[0].Query.Get("response_mode") != "" || az[0].Query.Get("redirect_uri") != redirectURL || !strings.Contains(az[0].Query.Get("scope"), "openid") ||
		az[0].Query.Get("state") == "" || az[0].Query.Get("nonce") == "" {
		t.Fatalf("%+v", az)
	}
	if tk := r.srv.Tokens(); len(tk) != 1 || !tk[0].HasVerifier || tk[0].AuthMethod != "basic" || tk[0].RedirectURI != redirectURL {
		t.Fatalf("%+v", tk)
	}
}

func TestOIDCClientAuthPost(t *testing.T) {
	r := newOIDCRig(t)
	r.cfg.ClientAuth = "post"
	if _, err := r.signIn(t, r.client(t), "ann"); err != nil {
		t.Fatal(err)
	}
	if tk := r.srv.Tokens(); len(tk) != 1 || tk[0].AuthMethod != "post" {
		t.Fatalf("%+v", tk)
	}
}

func TestOIDCEmailAndRoleRules(t *testing.T) {
	r := newOIDCRig(t)
	c := r.client(t)
	// An unverified email is not used.
	id, err := r.signIn(t, c, "bob")
	if err != nil || id.Email != "" || id.Role != "viewer" || id.ExternalName != "bob" {
		t.Fatalf("%+v %v", id, err)
	}
	// No groups claim at all: no role, which is a refusal and not an error.
	_, err = r.signIn(t, c, "carol")
	var rf *Refusal
	if !errors.As(err, &rf) || !rf.NoRole {
		t.Fatalf("%v", err)
	}
	// A nested claim path.
	r.cfg.RoleClaim = "realm_access.roles"
	r.srv.SetClaim("carol", "realm_access", map[string]any{"roles": []string{"clamfleet-viewers"}})
	if id, err := r.signIn(t, r.client(t), "carol"); err != nil || id.Role != "viewer" {
		t.Fatalf("%+v %v", id, err)
	}
	// Values are compared exactly.
	r.srv.SetClaim("carol", "realm_access", map[string]any{"roles": []string{"CLAMFLEET-VIEWERS"}})
	if _, err := r.signIn(t, r.client(t), "carol"); !isRefused(err, "no role") {
		t.Fatalf("%v", err)
	}
	// No preferred_username: the name falls back to the subject.
	r.cfg.RoleClaim = "groups"
	r.srv.AddUser("dave", map[string]any{"groups": []string{"clamfleet-admins"}, "preferred_username": ""})
	if id, err := r.signIn(t, r.client(t), "dave"); err != nil || id.ExternalName != "dave" {
		t.Fatalf("%+v %v", id, err)
	}
}

// Every scripted bad token is refused and no identity comes out.
func TestOIDCBadTokensFromTheProvider(t *testing.T) {
	for name, sc := range map[string]testoidc.Script{
		"wrong iss":     {Claims: func(c map[string]any) { c["iss"] = "https://evil.example" }},
		"wrong aud":     {Claims: func(c map[string]any) { c["aud"] = "other-client" }},
		"wrong azp":     {Claims: func(c map[string]any) { c["azp"] = "other-client" }},
		"azp, 2 auds":   {Claims: func(c map[string]any) { c["aud"] = []string{testoidc.ClientID, "x"}; c["azp"] = "x" }},
		"wrong nonce":   {Claims: func(c map[string]any) { c["nonce"] = "replayed" }},
		"expired":       {Claims: func(c map[string]any) { c["exp"] = int64(1) }},
		"alg none":      {Header: func(h map[string]any) { h["alg"] = "none" }},
		"a JWE":         {RawIDToken: "a.b.c.d.e"},
		"garbage token": {RawIDToken: "not-a-token"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newOIDCRig(t)
			c := r.client(t)
			r.srv.SetScript(sc)
			if id, err := r.signIn(t, c, "ann"); !errors.Is(err, ErrRefused) || id.ExternalID != "" {
				t.Fatalf("%+v %v", id, err)
			}
		})
	}
}

// The provider requires the verifier and checks S256: without it the exchange fails (a 4xx: a refusal).
func TestOIDCExchangeWithoutOrWithAWrongVerifierFails(t *testing.T) {
	r := newOIDCRig(t)
	c := r.client(t)
	for name, v := range map[string]string{"missing": "", "wrong": "not-the-verifier"} {
		req, err := c.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		code := r.pick(t, req, "ann")
		if _, err := c.Exchange(context.Background(), code, v, req.Nonce); !isRefused(err, "token endpoint refused") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestOIDCReplayedCodeIsRefused(t *testing.T) {
	r := newOIDCRig(t)
	c := r.client(t)
	req, _ := c.Begin(context.Background())
	code := r.pick(t, req, "ann")
	if _, err := c.Exchange(context.Background(), code, req.CodeVerifier, req.Nonce); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exchange(context.Background(), code, req.CodeVerifier, req.Nonce); !isRefused(err, "invalid_grant") {
		t.Fatalf("%v", err)
	}
}

func TestOIDCDiscoveryRules(t *testing.T) {
	for name, tc := range map[string]struct {
		sc   testoidc.Script
		want string
	}{
		"issuer differs":      {testoidc.Script{DiscoveryIssuer: "https://other.example"}, "issuer"},
		"257 KiB":             {testoidc.Script{DiscoveryPadBytes: 257 << 10}, "larger than"},
		"redirect":            {testoidc.Script{DiscoveryRedirectTo: "https://evil.example/x"}, "status 302"},
		"not json":            {testoidc.Script{DiscoveryContentType: "text/html"}, "application/json"},
		"plain http token ep": {testoidc.Script{TokenEndpoint: "http://idp.example/token"}, "token_endpoint"},
		"slow":                {testoidc.Script{DiscoveryDelay: 1500 * time.Millisecond}, "discovery request"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newOIDCRig(t)
			r.cfg.Timeout = 500 * time.Millisecond
			r.srv.SetScript(tc.sc)
			_, err := r.client(t).Begin(context.Background())
			if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v", err)
			}
		})
	}
	// Just under the limit is accepted.
	r := newOIDCRig(t)
	r.srv.SetScript(testoidc.Script{DiscoveryPadBytes: 200 << 10})
	if _, err := r.client(t).Begin(context.Background()); err != nil {
		t.Fatalf("a 200 KiB document: %v", err)
	}
}

// Discovery is lazy and cached for an hour, and fetched again after a failed exchange. A provider that is down
// at start only disables SSO until it comes back.
func TestOIDCDiscoveryIsLazyCachedAndRefreshedAfterAFailure(t *testing.T) {
	r := newOIDCRig(t)
	c := r.client(t)
	if r.srv.DiscoveryFetches() != 0 {
		t.Fatal("discovery was fetched at construction")
	}
	if _, err := c.Begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Begin(context.Background()); err != nil || r.srv.DiscoveryFetches() != 1 {
		t.Fatalf("%v, %d fetches", err, r.srv.DiscoveryFetches())
	}
	r.clock = r.clock.Add(59 * time.Minute)
	_, _ = c.Begin(context.Background())
	if r.srv.DiscoveryFetches() != 1 {
		t.Fatal("refetched inside the hour")
	}
	r.clock = r.clock.Add(2 * time.Minute)
	_, _ = c.Begin(context.Background())
	if r.srv.DiscoveryFetches() != 2 {
		t.Fatalf("%d fetches after the hour", r.srv.DiscoveryFetches())
	}
	// A failed exchange drops the cache.
	req, _ := c.Begin(context.Background())
	if _, err := c.Exchange(context.Background(), "bogus-code", req.CodeVerifier, req.Nonce); err == nil {
		t.Fatal("a bogus code was accepted")
	}
	before := r.srv.DiscoveryFetches()
	_, _ = c.Begin(context.Background())
	if r.srv.DiscoveryFetches() != before+1 {
		t.Fatal("the discovery document was not fetched again after a failed exchange")
	}
	// Down at first, then up.
	r2 := newOIDCRig(t)
	r2.srv.SetScript(testoidc.Script{DiscoveryRedirectTo: "https://x.example"})
	c2 := r2.client(t)
	if _, err := c2.Begin(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	r2.srv.SetScript(testoidc.Script{})
	if _, err := r2.signIn(t, c2, "ann"); err != nil {
		t.Fatalf("after the provider came back: %v", err)
	}
}

func TestOIDCTokenEndpointFaults(t *testing.T) {
	r := newOIDCRig(t)
	c := r.client(t)
	req, _ := c.Begin(context.Background())
	code := r.pick(t, req, "ann")
	r.srv.SetScript(testoidc.Script{TokenStatus: 500})
	if _, err := c.Exchange(context.Background(), code, req.CodeVerifier, req.Nonce); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a 500 from the token endpoint: %v", err)
	}
	r.srv.SetScript(testoidc.Script{TokenDelay: time.Second})
	r.cfg.Timeout = 300 * time.Millisecond
	c = r.client(t)
	req, _ = c.Begin(context.Background())
	if _, err := c.Exchange(context.Background(), r.pick(t, req, "ann"), req.CodeVerifier, req.Nonce); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a slow token endpoint: %v", err)
	}
}

// TLS verification is never skipped, on discovery or anywhere else.
func TestOIDCUntrustedCertificateIsUnavailable(t *testing.T) {
	r := newOIDCRig(t)
	r.cfg.RootCAs = x509.NewCertPool()
	if _, err := r.client(t).Begin(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}

func TestNewOIDCClientRefusesWhatConfigurationRefuses(t *testing.T) {
	r := newOIDCRig(t)
	for name, mut := range map[string]func(*OIDCConfig){
		"plain http issuer": func(c *OIDCConfig) { c.Issuer = "http://id.example" },
		"no secret":         func(c *OIDCConfig) { c.ClientSecret = "" },
		"bad client auth":   func(c *OIDCConfig) { c.ClientAuth = "jwt" },
		"no clock":          func(c *OIDCConfig) { c.Now = nil },
		"no role claim":     func(c *OIDCConfig) { c.RoleClaim = "" },
	} {
		c := r.cfg
		mut(&c)
		if _, err := NewOIDCClient(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	c := r.cfg
	c.Issuer = "http://127.0.0.1:9/realm"
	if _, err := NewOIDCClient(c); err != nil {
		t.Errorf("loopback http: %v", err)
	}
}

// Nothing secret appears in an error: the client secret, the code, the verifier.
func TestOIDCErrorsCarryNoSecrets(t *testing.T) {
	r := newOIDCRig(t)
	c := r.client(t)
	req, _ := c.Begin(context.Background())
	code := r.pick(t, req, "ann")
	_, err := c.Exchange(context.Background(), code, "wrong-verifier-value", req.Nonce)
	if err == nil {
		t.Fatal("accepted")
	}
	for _, s := range []string{testoidc.ClientSecret, code, "wrong-verifier-value", req.CodeVerifier} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("a secret is in %q", err)
		}
	}
}

func tlsFor(pool *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// http endpoints are allowed only when the issuer itself is http on loopback. Under an https issuer even a
// loopback http token endpoint is refused: the client secret and the code would travel in clear.
func TestOIDCPlainHTTPEndpointsOnlyUnderALoopbackHTTPIssuer(t *testing.T) {
	r := newOIDCRig(t)
	r.srv.SetScript(testoidc.Script{TokenEndpoint: "http://127.0.0.1:9/token"})
	if _, err := r.client(t).Begin(context.Background()); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "token_endpoint") {
		t.Fatalf("https issuer, loopback http token endpoint: %v", err)
	}
	// A plain-http loopback provider (tests, Keycloak in the e2e container) keeps working.
	srv, err := testoidc.Start(testoidc.Options{RedirectURIs: []string{redirectURL}, Now: func() time.Time { return r.clock }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	cfg := r.cfg
	cfg.Issuer = srv.Issuer()
	cfg.RootCAs = nil
	c, err := NewOIDCClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Begin(context.Background()); err != nil {
		t.Fatalf("http loopback issuer with http endpoints: %v", err)
	}
}
