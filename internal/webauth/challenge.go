// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// challenge.go: the login challenge token and its cookie.
//
// A user with TOTP who gives the right password gets a challenge, not a
// session. It is a row in its own table, found by its own cookie
// (__Host-clamfleet_login) and its own token prefix ("cfp_"), so a pending login
// cannot be used as a session by type (ParseToken refuses the prefix), by table
// (SessionByTokenHash never reads challenges) or by cookie name.
//
// Rejected: a "stage" column on user_sessions. One forgotten WHERE stage='full'
// would turn a pending login into a session.
package webauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

const (
	// ChallengePrefix starts every login challenge token.
	ChallengePrefix = "cfp_"
	challengeLen    = len(ChallengePrefix) + 43

	// ChallengeCookieNameSecure and ChallengeCookieNamePlain mirror the session cookie's pair.
	ChallengeCookieNameSecure = "__Host-clamfleet_login"
	ChallengeCookieNamePlain  = "clamfleet_login"

	// ChallengeTTL is how long the second factor may take after the password.
	ChallengeTTL = 5 * time.Minute
)

// NewChallengeToken returns a fresh challenge token and its storage hash.
func NewChallengeToken() (token string, hash []byte, err error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("generate challenge token: %w", err)
	}
	token = ChallengePrefix + base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// ParseChallengeToken checks the format only, so garbage never reaches the database.
func ParseChallengeToken(token string) error {
	if len(token) != challengeLen || token[:len(ChallengePrefix)] != ChallengePrefix {
		return ErrMalformedToken
	}
	if b, err := enc.DecodeString(token[len(ChallengePrefix):]); err != nil || len(b) != secretBytes {
		return ErrMalformedToken
	}
	return nil
}

// ChallengeCookieName returns the challenge cookie's name for the given mode.
func ChallengeCookieName(secure bool) string {
	if secure {
		return ChallengeCookieNameSecure
	}
	return ChallengeCookieNamePlain
}

// NewChallengeCookie has the flags of the session cookie (HttpOnly, Secure
// unless development mode, SameSite=Lax, Path=/, no Domain, no Max-Age: the
// server enforces the 5-minute lifetime).
func NewChallengeCookie(token string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name: ChallengeCookieName(secure), Value: token, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	}
}

// ClearChallengeCookie tells the browser to drop the challenge cookie.
func ClearChallengeCookie(secure bool) *http.Cookie {
	c := NewChallengeCookie("", secure)
	c.MaxAge = -1
	return c
}

// ChallengeTokenFromRequest returns the well-formed challenge token of the
// request, or "".
func ChallengeTokenFromRequest(r *http.Request, secure bool) string {
	c, err := r.Cookie(ChallengeCookieName(secure))
	if err != nil || ParseChallengeToken(c.Value) != nil {
		return ""
	}
	return c.Value
}
