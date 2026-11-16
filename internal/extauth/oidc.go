// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// oidc.go: the OpenID Connect authorization code flow with PKCE, on the standard library
// (decision 17; docs/plans/milestone-6.md 4.17).
//
// The client is deliberately small and strict:
//   - discovery is fetched lazily at the first sign-in (an identity provider that is down
//     when the server starts only disables SSO until it comes back), cached for an hour and
//     fetched again after a failed exchange; its "issuer" must equal the configured one
//     exactly and its endpoints must be https (http only to loopback, for tests);
//   - every request to the provider uses TLS 1.2 or later with verification on, follows NO
//     redirect, is bounded in time, and its answer is bounded in size (256 KiB for the
//     discovery document, 1 MiB for the token response) and must be JSON;
//   - PKCE with S256 is always used, with a verifier that never leaves this server except to
//     the token endpoint;
//   - the token response's ID token goes through ParseIDToken (idtoken.go).
//
// Nothing the provider returns (code, tokens, secrets) is stored or logged here: the caller
// keeps only the identity. Errors name the check or the HTTP status, never a token or the
// response body.
package extauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/clamfleet/clamfleet/internal/config"
	"github.com/clamfleet/clamfleet/internal/store"
)

// Bounds of what the provider may send us.
const (
	maxDiscoveryBytes = 256 << 10
	maxTokenBytes     = 1 << 20
	discoveryTTL      = time.Hour
	randomBytes       = 32
)

// OIDCConfig is everything OIDCClient needs, already resolved (secret file read, pool built).
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	ClientAuth   string // "basic" or "post"
	RedirectURL  string
	Scopes       []string
	RootCAs      *x509.CertPool
	Timeout      time.Duration

	RoleClaim                 string
	AdminValues, ViewerValues []string

	// Now is the injected clock (token times, the discovery cache).
	Now func() time.Time
}

// AuthRequest is the start of a sign-in: where to send the browser, and the three secrets of
// this sign-in the caller must keep until the callback (state, nonce, PKCE verifier).
type AuthRequest struct {
	URL          string
	State        string
	Nonce        string
	CodeVerifier string
}

type discovery struct {
	authURL, tokenURL string
	fetched           time.Time
}

// OIDCClient signs users in with one OpenID Connect provider.
type OIDCClient struct {
	cfg   OIDCConfig
	http  *http.Client
	roles RoleMap

	mu   sync.Mutex
	disc *discovery
}

// NewOIDCClient validates cfg and returns the client. It does no I/O (discovery is lazy).
func NewOIDCClient(cfg OIDCConfig) (*OIDCClient, error) {
	if err := checkEndpoint(cfg.Issuer); err != nil {
		return nil, fmt.Errorf("oidc: issuer: %w", err)
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" || cfg.RoleClaim == "" {
		return nil, errors.New("oidc: client id, client secret, redirect URL and role claim are required")
	}
	if cfg.ClientAuth != "basic" && cfg.ClientAuth != "post" {
		return nil, errors.New("oidc: client_auth must be basic or post")
	}
	if cfg.Timeout <= 0 || cfg.Now == nil {
		return nil, errors.New("oidc: a timeout and a clock are required")
	}
	c := &OIDCClient{cfg: cfg, roles: RoleMap{Admin: cfg.AdminValues, Viewer: cfg.ViewerValues}}
	c.http = &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			// No proxy from the environment: the provider is contacted directly, and a stray
			// HTTPS_PROXY must not route client secrets through something nobody configured.
			Proxy:           nil,
			TLSClientConfig: &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12},
			DialContext:     (&net.Dialer{Timeout: cfg.Timeout}).DialContext,
			// One request per client use: keeping connections would only keep a stale one.
			DisableKeepAlives: true,
		},
		// Rule: no redirect is followed, on any request (a redirect could carry the client secret
		// or the code to another host).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c, nil
}

// checkEndpoint: an absolute https URL, or http for a loopback host.
func checkEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("not an https URL")
	}
	if u.Scheme == "http" && !config.IsLoopbackHost(u.Hostname()) {
		return errors.New("plain http to a host that is not loopback")
	}
	return nil
}

// Begin starts a sign-in: it makes the state, nonce and PKCE verifier and returns the URL of the
// authorization endpoint. It needs the discovery document (fetched now if it is not cached).
func (c *OIDCClient) Begin(ctx context.Context) (AuthRequest, error) {
	d, err := c.discover(ctx)
	if err != nil {
		return AuthRequest{}, err
	}
	state, err := randomString()
	if err != nil {
		return AuthRequest{}, err
	}
	nonce, err := randomString()
	if err != nil {
		return AuthRequest{}, err
	}
	verifier, err := randomString()
	if err != nil {
		return AuthRequest{}, err
	}
	sum := sha256.Sum256([]byte(verifier))
	u, err := url.Parse(d.authURL)
	if err != nil {
		return AuthRequest{}, fmt.Errorf("%w: authorization endpoint", ErrUnavailable)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", c.cfg.RedirectURL)
	q.Set("scope", strings.Join(c.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	// No response_mode=form_post: a cross-site POST back would not carry the SameSite=Lax state
	// cookie and would fail the cross-origin check. The code comes back in the query of a GET.
	return AuthRequest{URL: u.String(), State: state, Nonce: nonce, CodeVerifier: verifier}, nil
}

func randomString() (string, error) {
	b := make([]byte, randomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidc: no randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Exchange trades the code for an ID token and returns the verified identity. nonce and
// verifier are the ones Begin made for this sign-in.
func (c *OIDCClient) Exchange(ctx context.Context, code, verifier, nonce string) (Identity, error) {
	d, err := c.discover(ctx)
	if err != nil {
		return Identity{}, err
	}
	raw, err := c.tokenRequest(ctx, d.tokenURL, code, verifier)
	if err != nil {
		c.forget() // fetch the discovery document again next time: an endpoint may have moved
		return Identity{}, err
	}
	claims, err := ParseIDToken(raw, IDTokenChecks{Issuer: c.cfg.Issuer, ClientID: c.cfg.ClientID, Nonce: nonce, Now: c.cfg.Now()})
	if err != nil {
		return Identity{}, err
	}

	id := Identity{}
	id.Source = store.AuthOIDC
	id.ExternalID = c.cfg.Issuer + " " + claims["sub"].(string)
	id.ExternalName = cleanText(str(claims["preferred_username"]), 128)
	id.DisplayName = cleanText(str(claims["name"]), 128)
	// Rule: the email is used only when the provider says it verified it (decision 19). An
	// unverified address could be anyone's, and it is what a collision check protects.
	if verified, _ := claims["email_verified"].(bool); verified {
		if e, err := store.NormalizeEmail(str(claims["email"])); err == nil {
			id.Email = e
		}
	}
	if id.ExternalName == "" {
		// Something readable for the account page and the audit actor.
		id.ExternalName = cleanText(str(claims["sub"]), 64)
	}
	// A user with no group has no `groups` claim at all with some providers (Keycloak): missing
	// is "no values", which is "no role", not an error.
	role, ok := c.roles.Resolve(claimValues(claims, c.cfg.RoleClaim))
	if !ok {
		return Identity{}, &Refusal{Reason: "oidc: no role", NoRole: true}
	}
	id.Role = role
	return id, nil
}

func str(v any) string { s, _ := v.(string); return s }

func (c *OIDCClient) forget() { c.mu.Lock(); c.disc = nil; c.mu.Unlock() }

// discover returns the cached discovery document, or fetches it.
func (c *OIDCClient) discover(ctx context.Context) (*discovery, error) {
	c.mu.Lock()
	d := c.disc
	c.mu.Unlock()
	if d != nil && c.cfg.Now().Sub(d.fetched) < discoveryTTL {
		return d, nil
	}
	body, err := c.get(ctx, strings.TrimRight(c.cfg.Issuer, "/")+"/.well-known/openid-configuration", maxDiscoveryBytes)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: discovery document is not JSON", ErrUnavailable)
	}
	// Rule: the issuer in the document must be the configured one, exactly. A mix-up between
	// providers (a document of another issuer served at this address) is the attack this stops.
	if doc.Issuer != c.cfg.Issuer {
		return nil, fmt.Errorf("%w: discovery issuer does not match auth.oidc.issuer", ErrUnavailable)
	}
	for name, ep := range map[string]string{"authorization_endpoint": doc.AuthorizationEndpoint, "token_endpoint": doc.TokenEndpoint} {
		if err := checkEndpoint(ep); err != nil {
			return nil, fmt.Errorf("%w: discovery %s: %v", ErrUnavailable, name, err)
		}
	}
	d = &discovery{authURL: doc.AuthorizationEndpoint, tokenURL: doc.TokenEndpoint, fetched: c.cfg.Now()}
	c.mu.Lock()
	c.disc = d
	c.mu.Unlock()
	return d, nil
}

// get fetches a JSON document: 200, a JSON content type, at most limit bytes, no redirect.
func (c *OIDCClient) get(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: discovery request: %v", ErrUnavailable, urlErrorText(err))
	}
	return readJSON(resp, limit, "discovery")
}

func readJSON(resp *http.Response, limit int64, what string) ([]byte, error) {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s answered status %d", ErrUnavailable, what, resp.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, fmt.Errorf("%w: %s is not application/json", ErrUnavailable, what)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrUnavailable, what, urlErrorText(err))
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrUnavailable, what, limit)
	}
	return b, nil
}

// urlErrorText drops the request URL from a transport error (a token endpoint URL can carry
// nothing secret here, but the habit keeps it that way).
func urlErrorText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

// tokenRequest posts the authorization code and returns the raw ID token.
func (c *OIDCClient) tokenRequest(ctx context.Context, tokenURL, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {c.cfg.RedirectURL}, "code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if c.cfg.ClientAuth == "basic" {
		// RFC 6749 section 2.3.1: the id and the secret are form-urlencoded before the Basic encoding.
		req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	} else {
		form.Set("client_id", c.cfg.ClientID)
		form.Set("client_secret", c.cfg.ClientSecret)
	}
	body := form.Encode()
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: token request: %v", ErrUnavailable, urlErrorText(err))
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		// The provider said no (a replayed or expired code, a wrong verifier): the user's sign-in
		// failed. Only the OAuth error code is kept, and only when it is a short token.
		defer resp.Body.Close()
		var e struct {
			Error string `json:"error"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = json.Unmarshal(b, &e)
		return "", refused(fmt.Sprintf("oidc: token endpoint refused the code (status %d, %s)", resp.StatusCode, oauthErrorToken(e.Error)))
	}
	b, err := readJSON(resp, maxTokenBytes, "token response")
	if err != nil {
		return "", err
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(b, &tr); err != nil || tr.IDToken == "" {
		return "", refused("oidc: token response has no id_token")
	}
	return tr.IDToken, nil
}

// oauthErrorToken keeps an OAuth error code (RFC 6749 section 5.2) only if it looks like one.
func oauthErrorToken(s string) string {
	if s == "" || len(s) > 40 {
		return "no error code"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r == '_') {
			return "no error code"
		}
	}
	return s
}
