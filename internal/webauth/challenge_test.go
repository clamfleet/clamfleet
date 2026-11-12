// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package webauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChallengeTokenFormat(t *testing.T) {
	tok, hash, err := NewChallengeToken()
	if err != nil || !strings.HasPrefix(tok, "cfp_") || len(hash) != 32 {
		t.Fatalf("%q %v", tok, err)
	}
	if err := ParseChallengeToken(tok); err != nil {
		t.Fatal(err)
	}
	if string(HashToken(tok)) != string(hash) {
		t.Fatal("the storage hash is not the hash of the token")
	}
	for _, bad := range []string{"", "cfp_", tok[:len(tok)-1], tok + "x", "cfs_" + tok[4:], strings.Replace(tok, "cfp_", "xxx_", 1), "cfp_" + strings.Repeat("!", 43)} {
		if ParseChallengeToken(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Rule: a challenge is never a session, and a session token is never a challenge:
// the two token kinds refuse each other's prefix.
func TestChallengeAndSessionTokensDoNotCross(t *testing.T) {
	ch, _, _ := NewChallengeToken()
	if ParseToken(ch) == nil {
		t.Fatal("ParseToken accepted a login challenge token: a pending login could be used as a session")
	}
	sess, _, _ := NewToken()
	if ParseChallengeToken(sess) == nil {
		t.Fatal("ParseChallengeToken accepted a session token")
	}
}

func TestChallengeCookieFlags(t *testing.T) {
	c := NewChallengeCookie("cfp_x", true)
	if c.Name != "__Host-clamfleet_login" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" || c.MaxAge != 0 || !c.Expires.IsZero() {
		t.Fatalf("%+v", c)
	}
	p := NewChallengeCookie("cfp_x", false)
	if p.Name != "clamfleet_login" || p.Secure || !p.HttpOnly {
		t.Fatalf("plain mode: %+v", p)
	}
	if cl := ClearChallengeCookie(true); cl.MaxAge != -1 || cl.Value != "" || cl.Name != c.Name {
		t.Fatalf("%+v", cl)
	}
}

// Only the challenge cookie's own name carries a challenge, and only if well-formed.
func TestChallengeTokenFromRequest(t *testing.T) {
	tok, _, _ := NewChallengeToken()
	get := func(name, value string) string {
		r := httptest.NewRequest("GET", "/login/totp", nil)
		r.AddCookie(&http.Cookie{Name: name, Value: value})
		return ChallengeTokenFromRequest(r, true)
	}
	if get("__Host-clamfleet_login", tok) != tok {
		t.Error("the challenge cookie was not read")
	}
	if get("__Host-clamfleet_session", tok) != "" {
		t.Error("a challenge token in the SESSION cookie was read as a challenge")
	}
	if get("__Host-clamfleet_login", "garbage") != "" {
		t.Error("a malformed token was returned")
	}
}
