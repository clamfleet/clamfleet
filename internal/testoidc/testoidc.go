// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package testoidc is an in-process OpenID Connect provider for tests and for the browser
// fixture ("6b, new"): discovery, an authorization
// endpoint that shows a page of users to choose from, and a token endpoint that checks
// PKCE and the client's credentials and answers with an ID token.
//
// It is as strict as a real provider where ClamFleet's security depends on it: the code is
// single use, bound to the redirect URI and to the PKCE challenge (S256 only: "plain" or a
// missing challenge is refused at the authorization endpoint, a missing or wrong verifier
// at the token endpoint), and the client must authenticate. It RECORDS what it was sent
// (the authorization query, whether the token request carried a verifier, how the client
// authenticated) so a test can assert on the wire, not on the outcome.
//
// And it can misbehave on command (Script): a wrong issuer, audience, authorized party or
// nonce, an expired token, alg "none", a JWE-shaped token, a discovery document that is
// too large, redirects, is not JSON, or answers late, a plain-http token endpoint, an
// error from the authorization endpoint.
//
// The ID token is signed with a throwaway value because ClamFleet does not verify the
// signature (OIDC Core section 3.1.3.7 rule 6; M6 decision 17): it takes the token straight
// from the token endpoint over a TLS connection it validated. A fake that signed properly
// would suggest a check that does not exist.
//
// Listens on 127.0.0.1 only. The issuer is spelled with the host name "localhost" so that
// a browser on https://127.0.0.1 sees a different SITE (SameSite is about sites, not ports).
package testoidc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ClientID and ClientSecret are what the fake's one registered client uses.
const (
	ClientID     = "clamfleet"
	ClientSecret = "testoidc-client-secret-0123456789"
)

// Options configure Start.
type Options struct {
	// CertFile and KeyFile make it an https server (internal/testtls); without them it is plain http.
	CertFile, KeyFile string
	// Now is the clock of the tokens' iat and exp; nil means time.Now.
	Now func() time.Time
	// RedirectURIs are the registered redirect URIs.
	RedirectURIs []string
}

// Script makes the next responses misbehave. The zero value is a well-behaved provider.
type Script struct {
	Claims func(claims map[string]any) // mutates the claims of every ID token
	Header func(header map[string]any) // mutates the JWS header
	// RawIDToken replaces the ID token string entirely (a 5-part JWE shape, garbage).
	RawIDToken string
	// TokenStatus, when non-zero, makes the token endpoint answer with that status and an OAuth error.
	TokenStatus    int
	TokenDelay     time.Duration
	DiscoveryDelay time.Duration
	// Discovery document faults.
	DiscoveryIssuer      string // the "issuer" member, when it should differ
	DiscoveryRedirectTo  string // answer 302 to this URL
	DiscoveryContentType string
	DiscoveryPadBytes    int    // add this many bytes of padding to the document
	TokenEndpoint        string // the "token_endpoint" member, when it should differ
	// AuthorizeError, when set, makes the authorization endpoint return the browser with
	// error=<value> instead of a code (a user who denied access).
	AuthorizeError string
}

// AuthorizeRecord is one authorization request as received.
type AuthorizeRecord struct {
	Query url.Values
}

// TokenRecord is one token request as received.
type TokenRecord struct {
	GrantType, RedirectURI, ClientID string
	HasVerifier                      bool
	Verifier                         string
	AuthMethod                       string // basic, post or none
	Code                             string
	// IDToken and AccessToken are what the fake answered with (empty when it refused), so a test can
	// look for them in logs.
	IDToken, AccessToken string
}

type code struct {
	user      string
	nonce     string
	challenge string
	redirect  string
}

// Server is a running fake provider.
type Server struct {
	l     net.Listener
	srv   *http.Server
	https bool
	now   func() time.Time

	mu         sync.Mutex
	users      map[string]map[string]any
	redirects  map[string]bool
	codes      map[string]*code
	script     Script
	authorizes []AuthorizeRecord
	tokens     []TokenRecord
	discovery  int
	closed     bool
}

// Start listens on 127.0.0.1 with a free port.
func Start(o Options) (*Server, error) {
	s := &Server{now: o.Now, users: map[string]map[string]any{}, redirects: map[string]bool{}, codes: map[string]*code{}}
	if s.now == nil {
		s.now = time.Now
	}
	for _, r := range o.RedirectURIs {
		s.redirects[r] = true
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	if o.CertFile != "" {
		c, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			l.Close()
			return nil, err
		}
		l = tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12})
		s.https = true
	}
	s.l = l
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discoveryDoc)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("GET /authorize/pick", s.pick)
	mux.HandleFunc("POST /token", s.token)
	// ErrorLog discarded: a browser that aborts a handshake (a certificate warning probe) must not print into the fixture's output.
	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = s.srv.Serve(l) }()
	return s, nil
}

// Issuer is scheme://localhost:port (the issuer string clients must configure).
func (s *Server) Issuer() string {
	_, port, _ := net.SplitHostPort(s.l.Addr().String())
	scheme := "http"
	if s.https {
		scheme = "https"
	}
	return scheme + "://localhost:" + port
}

// Close stops the server.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	_ = s.srv.Close()
}

// AllowRedirect registers a redirect URI.
func (s *Server) AllowRedirect(uri string) { s.mu.Lock(); s.redirects[uri] = true; s.mu.Unlock() }

// AddUser adds (or replaces) a user. key is what the user page shows and the default "sub" and
// "preferred_username"; claims are merged into the ID token (groups, email, email_verified, name ...).
func (s *Server) AddUser(key string, claims map[string]any) {
	c := map[string]any{"sub": key, "preferred_username": key}
	for k, v := range claims {
		c[k] = v
	}
	s.mu.Lock()
	s.users[key] = c
	s.mu.Unlock()
}

// SetClaim changes one claim of an existing user (a group change at the provider).
func (s *Server) SetClaim(key, claim string, v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.users[key]; u != nil {
		if v == nil {
			delete(u, claim)
		} else {
			u[claim] = v
		}
	}
}

// SetScript installs a script; SetScript(Script{}) restores good behaviour.
func (s *Server) SetScript(sc Script) { s.mu.Lock(); s.script = sc; s.mu.Unlock() }

// Authorizes, Tokens and DiscoveryFetches return what the server saw.
func (s *Server) Authorizes() []AuthorizeRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuthorizeRecord(nil), s.authorizes...)
}

// Tokens returns the recorded token requests.
func (s *Server) Tokens() []TokenRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]TokenRecord(nil), s.tokens...)
}

// DiscoveryFetches counts requests for the discovery document.
func (s *Server) DiscoveryFetches() int { s.mu.Lock(); defer s.mu.Unlock(); return s.discovery }

// Reset forgets the records (not the users or the script).
func (s *Server) Reset() {
	s.mu.Lock()
	s.authorizes, s.tokens, s.discovery = nil, nil, 0
	s.mu.Unlock()
}

func (s *Server) discoveryDoc(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.discovery++
	sc := s.script
	s.mu.Unlock()
	if sc.DiscoveryDelay > 0 {
		time.Sleep(sc.DiscoveryDelay)
	}
	if sc.DiscoveryRedirectTo != "" {
		http.Redirect(w, r, sc.DiscoveryRedirectTo, http.StatusFound)
		return
	}
	iss := s.Issuer()
	doc := map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/authorize",
		"token_endpoint":                        iss + "/token",
		"jwks_uri":                              iss + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	}
	if sc.DiscoveryIssuer != "" {
		doc["issuer"] = sc.DiscoveryIssuer
	}
	if sc.TokenEndpoint != "" {
		doc["token_endpoint"] = sc.TokenEndpoint
	}
	if sc.DiscoveryPadBytes > 0 {
		doc["padding"] = strings.Repeat("x", sc.DiscoveryPadBytes)
	}
	ct := "application/json"
	if sc.DiscoveryContentType != "" {
		ct = sc.DiscoveryContentType
	}
	w.Header().Set("Content-Type", ct)
	_ = json.NewEncoder(w).Encode(doc)
}

var pickPage = template.Must(template.New("pick").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Test identity provider</title></head>
<body><h1 data-testid="idp-page">Test identity provider</h1>
<p>Choose who signs in:</p>
<ul>{{range .Users}}<li><a data-testid="idp-user-{{.Key}}" href="{{.Href}}">{{.Key}}</a></li>{{end}}</ul>
</body></html>
`))

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	s.authorizes = append(s.authorizes, AuthorizeRecord{Query: q})
	ok := s.redirects[q.Get("redirect_uri")]
	sc := s.script
	keys := make([]string, 0, len(s.users))
	for k := range s.users {
		keys = append(keys, k)
	}
	s.mu.Unlock()
	// A real provider shows an error page, never a redirect, for a bad client or redirect URI.
	switch {
	case q.Get("client_id") != ClientID:
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	case !ok:
		http.Error(w, "redirect_uri is not registered", http.StatusBadRequest)
		return
	}
	back := func(vals url.Values) {
		u, _ := url.Parse(q.Get("redirect_uri"))
		qq := u.Query()
		for k, v := range vals {
			qq[k] = v
		}
		if st := q.Get("state"); st != "" {
			qq.Set("state", st)
		}
		u.RawQuery = qq.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	switch {
	case q.Get("response_type") != "code":
		back(url.Values{"error": {"unsupported_response_type"}})
		return
	case q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		back(url.Values{"error": {"invalid_request"}, "error_description": {"PKCE with S256 is required"}})
		return
	case !hasScope(q.Get("scope"), "openid"):
		back(url.Values{"error": {"invalid_scope"}})
		return
	case sc.AuthorizeError != "":
		back(url.Values{"error": {sc.AuthorizeError}, "error_description": {"the user denied access"}})
		return
	}
	sort.Strings(keys)
	type row struct{ Key, Href string }
	var rows []row
	for _, k := range keys {
		pq := url.Values{}
		for kk, vv := range q {
			pq[kk] = vv
		}
		pq.Set("user", k)
		rows = append(rows, row{k, "/authorize/pick?" + pq.Encode()})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pickPage.Execute(w, map[string]any{"Users": rows})
}

func hasScope(list, want string) bool {
	for _, f := range strings.Fields(list) {
		if f == want {
			return true
		}
	}
	return false
}

// pick is the click on a user: it issues a code and returns the browser to the redirect URI.
func (s *Server) pick(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	_, known := s.users[q.Get("user")]
	ok := s.redirects[q.Get("redirect_uri")] && q.Get("client_id") == ClientID && q.Get("code_challenge_method") == "S256" && q.Get("code_challenge") != ""
	var c string
	if known && ok {
		c = randToken()
		s.codes[c] = &code{user: q.Get("user"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	}
	s.mu.Unlock()
	if c == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	u, _ := url.Parse(q.Get("redirect_uri"))
	qq := u.Query()
	qq.Set("code", c)
	if st := q.Get("state"); st != "" {
		qq.Set("state", st)
	}
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func oauthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	rec := TokenRecord{GrantType: r.PostForm.Get("grant_type"), RedirectURI: r.PostForm.Get("redirect_uri"), Code: r.PostForm.Get("code"),
		Verifier: r.PostForm.Get("code_verifier"), HasVerifier: r.PostForm.Get("code_verifier") != "", AuthMethod: "none"}
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		rec.AuthMethod = "basic"
		id, _ = url.QueryUnescape(u)
		secret, _ = url.QueryUnescape(p)
	} else if secret != "" {
		rec.AuthMethod = "post"
	}
	rec.ClientID = id
	s.mu.Lock()
	s.tokens = append(s.tokens, rec)
	slot := len(s.tokens) - 1
	sc := s.script
	s.mu.Unlock()
	if sc.TokenDelay > 0 {
		time.Sleep(sc.TokenDelay)
	}
	if sc.TokenStatus != 0 {
		oauthError(w, sc.TokenStatus, "server_error")
		return
	}
	if id != ClientID || secret != ClientSecret {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if rec.GrantType != "authorization_code" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	s.mu.Lock()
	c := s.codes[rec.Code]
	if c != nil {
		// Single use: the code is burnt whether or not the rest checks out (RFC 6749 section 4.1.2).
		delete(s.codes, rec.Code)
	}
	user := map[string]any(nil)
	if c != nil {
		user = map[string]any{}
		for k, v := range s.users[c.user] {
			user[k] = v
		}
	}
	s.mu.Unlock()
	if c == nil || user == nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(rec.Verifier))
	if !rec.HasVerifier || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge || rec.RedirectURI != c.redirect {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	now := s.now()
	claims := map[string]any{
		"iss": s.Issuer(), "aud": ClientID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": c.nonce,
	}
	for k, v := range user {
		claims[k] = v
	}
	if sc.Claims != nil {
		sc.Claims(claims)
	}
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "test"}
	if sc.Header != nil {
		sc.Header(header)
	}
	idToken := sc.RawIDToken
	if idToken == "" {
		idToken = compact(header, claims)
	}
	access := randToken()
	s.mu.Lock()
	s.tokens[slot].IDToken, s.tokens[slot].AccessToken = idToken, access
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": access, "token_type": "Bearer", "expires_in": 300, "id_token": idToken,
	})
}

// compact builds a JWS compact serialization with a throwaway signature (see the package comment).
func compact(header, claims map[string]any) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	sig := make([]byte, 32)
	_, _ = rand.Read(sig)
	return enc(header) + "." + enc(claims) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// String describes the server for failure messages.
func (s *Server) String() string { return fmt.Sprintf("testoidc %s", s.Issuer()) }
