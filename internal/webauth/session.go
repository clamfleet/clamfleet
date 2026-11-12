// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// session.go: the session token and cookie, the principal, the CSRF token and
// the redirect-target sanitiser.
//
// A session token is "cfs_" + base64url (no padding) of 32 random bytes. The
// prefix marks it as a console credential; it can never be mistaken for, or
// accepted as, an agent token ("cfa_", internal/agentauth). The database
// keeps only the SHA-256 of the token, the same pattern as agent tokens: a
// leaked database (or backup) holds no usable cookie.
package webauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	// TokenPrefix starts every session token.
	TokenPrefix = "cfs_"
	secretBytes = 32
	tokenLen    = len(TokenPrefix) + 43

	// CookieNameSecure carries the __Host- prefix: the browser then refuses to
	// set or send it unless it is Secure, has Path=/ and no Domain, which stops
	// a sibling subdomain from planting a cookie over it.
	CookieNameSecure = "__Host-clamfleet_session"
	// CookieNamePlain is used only with auth.cookie_secure: false (plain-HTTP
	// development); a __Host- cookie cannot be set over HTTP.
	CookieNamePlain = "clamfleet_session"
)

var enc = base64.RawURLEncoding.Strict()

// ErrMalformedToken: not a well-formed session token. Never contains the input.
var ErrMalformedToken = errors.New("malformed session token")

// NewToken returns a fresh session token and its storage hash.
func NewToken() (token string, hash []byte, err error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("generate session token: %w", err)
	}
	token = TokenPrefix + enc.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken is the storage hash of a token: SHA-256 of the whole string.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// ParseToken checks the format only, so garbage never reaches the database.
func ParseToken(token string) error {
	if len(token) != tokenLen || token[:len(TokenPrefix)] != TokenPrefix {
		return ErrMalformedToken
	}
	if b, err := enc.DecodeString(token[len(TokenPrefix):]); err != nil || len(b) != secretBytes {
		return ErrMalformedToken
	}
	return nil
}

// CookieName returns the session cookie's name for the given mode.
func CookieName(secure bool) string {
	if secure {
		return CookieNameSecure
	}
	return CookieNamePlain
}

// NewCookie builds the session cookie: HttpOnly (no script can read it),
// Secure (unless development mode), SameSite=Lax (not sent on cross-site
// POSTs; CSRF layer 1 of 3, see Manager.CSRF), Path=/ and no Domain (host
// only). No Max-Age: it is a browser-session cookie and expiry is enforced on
// the server, where it cannot be extended by editing a cookie.
func NewCookie(token string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name: CookieName(secure), Value: token, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	}
}

// ClearCookie tells the browser to drop the session cookie.
func ClearCookie(secure bool) *http.Cookie {
	c := NewCookie("", secure)
	c.MaxAge = -1
	return c
}

// Principal is the signed-in user behind a request. It is a different type
// from agentauth.Identity on purpose: the type system keeps a session away from
// the agent API and an agent token away from the UI.
type Principal struct {
	SessionID  int64
	UserID     int64
	Email      string
	Name       string
	Role       string
	MustChange bool // the password must be changed before anything else
	TokenHash  []byte
	csrf       []byte
}

// IsAdmin reports whether the user has the admin role.
func (p Principal) IsAdmin() bool { return p.Role == "admin" }

// CSRFToken returns a token for forms and the X-CSRF-Token header. Each call
// returns a different string for the same secret: it is XORed with a fresh
// random mask, so a compression side channel (BREACH) that sees many
// responses learns nothing stable about it.
func (p Principal) CSRFToken() string { return maskToken(p.csrf) }

type principalKey struct{}

// FromContext returns the principal the middleware stored.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// WithPrincipal stores p in ctx (the middleware does this; tests may too).
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func maskToken(secret []byte) string {
	mask := make([]byte, len(secret))
	if _, err := rand.Read(mask); err != nil {
		// No randomness, no safe token. A panic here is caught by net/http as a
		// failed request; it never yields a predictable token.
		panic("webauth: crypto/rand failed: " + err.Error())
	}
	out := make([]byte, 0, 2*len(secret))
	out = append(out, mask...)
	for i, b := range secret {
		out = append(out, b^mask[i])
	}
	return enc.EncodeToString(out)
}

// tokenMatches reports whether presented is a (masked) form of secret, in
// constant time.
func tokenMatches(secret []byte, presented string) bool {
	if len(secret) == 0 || len(presented) > 4*len(secret) {
		return false
	}
	raw, err := enc.DecodeString(presented)
	if err != nil || len(raw) != 2*len(secret) {
		return false
	}
	n := len(secret)
	got := make([]byte, n)
	for i := 0; i < n; i++ {
		got[i] = raw[i] ^ raw[n+i]
	}
	return subtle.ConstantTimeCompare(got, secret) == 1
}

// SanitizeNext validates the post-login redirect target: only a local path.
// Anything else ("//evil.example", "/\evil", "https://x", "javascript:",
// control characters) becomes "/", so the login form is not an open redirect.
func SanitizeNext(next string) string {
	if next == "" || len(next) > 2048 || next[0] != '/' || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	for _, r := range next {
		if r < ' ' || r == 0x7f || r == '\\' {
			return "/"
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || !strings.HasPrefix(u.Path, "/") {
		return "/"
	}
	// Never bounce back to the login page itself (a loop) or to an action URL.
	if u.Path == "/login" || u.Path == "/logout" {
		return "/"
	}
	return next
}
