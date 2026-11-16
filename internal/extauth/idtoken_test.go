// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package extauth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var now0 = time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC)

const (
	issuer   = "https://id.example/realms/main"
	clientID = "clamfleet"
	nonce0   = "nonce-0123456789"
)

func jws(header, claims map[string]any) string {
	e := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	return e(header) + "." + e(claims) + ".c2ln"
}

func goodClaims() map[string]any {
	return map[string]any{"iss": issuer, "aud": clientID, "sub": "user-1", "nonce": nonce0,
		"iat": now0.Add(-time.Minute).Unix(), "exp": now0.Add(4 * time.Minute).Unix()}
}

func checks() IDTokenChecks {
	return IDTokenChecks{Issuer: issuer, ClientID: clientID, Nonce: nonce0, Now: now0}
}

// Every check of the ID token is a row that fails when the check is removed. The signature is not one of
// them: it is not verified by design (decision 17), which the package comment explains.
func TestParseIDToken(t *testing.T) {
	hdr := map[string]any{"alg": "RS256"}
	for _, c := range []struct {
		name string
		mut  func(m map[string]any)
		want string // "" = accepted; else the reason must contain this
	}{
		{"good", func(m map[string]any) {}, ""},
		{"aud as an array with us in it", func(m map[string]any) { m["aud"] = []any{clientID} }, ""},
		{"several audiences with a good azp", func(m map[string]any) { m["aud"] = []any{"other", clientID}; m["azp"] = clientID }, ""},
		{"single audience with a good azp", func(m map[string]any) { m["azp"] = clientID }, ""},
		{"exp a little in the past (clock skew)", func(m map[string]any) { m["exp"] = now0.Add(-30 * time.Second).Unix() }, ""},
		{"iat a little in the future (clock skew)", func(m map[string]any) { m["iat"] = now0.Add(30 * time.Second).Unix() }, ""},
		{"float timestamps", func(m map[string]any) { m["exp"] = float64(now0.Add(time.Hour).Unix()) }, ""},

		{"wrong iss", func(m map[string]any) { m["iss"] = "https://evil.example" }, "iss"},
		{"iss with a trailing slash", func(m map[string]any) { m["iss"] = issuer + "/" }, "iss"},
		{"no iss", func(m map[string]any) { delete(m, "iss") }, "iss"},
		{"wrong aud", func(m map[string]any) { m["aud"] = "someone-else" }, "aud"},
		{"aud array without us", func(m map[string]any) { m["aud"] = []any{"a", "b"} }, "aud"},
		{"aud of a bad type", func(m map[string]any) { m["aud"] = 7 }, "aud"},
		{"no aud", func(m map[string]any) { delete(m, "aud") }, "aud"},
		{"several audiences and no azp", func(m map[string]any) { m["aud"] = []any{clientID, "other"} }, "azp"},
		{"several audiences and a wrong azp", func(m map[string]any) { m["aud"] = []any{clientID, "other"}; m["azp"] = "other" }, "azp"},
		{"single audience and a wrong azp", func(m map[string]any) { m["azp"] = "other" }, "azp"},
		{"expired", func(m map[string]any) { m["exp"] = now0.Add(-2 * time.Minute).Unix() }, "expired"},
		{"no exp", func(m map[string]any) { delete(m, "exp") }, "expired"},
		{"exp as a string", func(m map[string]any) { m["exp"] = "9999999999" }, "expired"},
		{"iat too old", func(m map[string]any) { m["iat"] = now0.Add(-11 * time.Minute).Unix() }, "iat"},
		{"iat in the future", func(m map[string]any) { m["iat"] = now0.Add(2 * time.Minute).Unix() }, "iat"},
		{"no iat", func(m map[string]any) { delete(m, "iat") }, "iat"},
		{"nbf in the future", func(m map[string]any) { m["nbf"] = now0.Add(5 * time.Minute).Unix() }, "not valid yet"},
		{"wrong nonce", func(m map[string]any) { m["nonce"] = "another-nonce" }, "nonce"},
		{"no nonce", func(m map[string]any) { delete(m, "nonce") }, "nonce"},
		{"no sub", func(m map[string]any) { delete(m, "sub") }, "sub"},
		{"empty sub", func(m map[string]any) { m["sub"] = "" }, "sub"},
		{"sub too long", func(m map[string]any) { m["sub"] = strings.Repeat("a", 256) }, "sub"},
		{"sub of a bad type", func(m map[string]any) { m["sub"] = 42 }, "sub"},
	} {
		m := goodClaims()
		c.mut(m)
		got, err := ParseIDToken(jws(hdr, m), checks())
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.want == "" && got["sub"] != "user-1":
			t.Errorf("%s: claims %v", c.name, got)
		case c.want != "" && !isRefused(err, c.want):
			t.Errorf("%s: %v, want a refusal mentioning %q", c.name, err, c.want)
		}
	}
}

func TestParseIDTokenRefusesBadShapes(t *testing.T) {
	good := jws(map[string]any{"alg": "RS256"}, goodClaims())
	for name, tc := range map[string]struct{ tok, want string }{
		"alg none":        {jws(map[string]any{"alg": "none"}, goodClaims()), "alg is none"},
		"alg None":        {jws(map[string]any{"alg": "None"}, goodClaims()), "alg is none"},
		"no alg":          {jws(map[string]any{"typ": "JWT"}, goodClaims()), "alg"},
		"a JWE":           {"a.b.c.d.e", "JWE"},
		"two parts":       {"a.b", "compact JWS"},
		"four parts":      {"a.b.c.d", "compact JWS"},
		"empty":           {"", "compact JWS"},
		"header garbage":  {"!!." + strings.Split(good, ".")[1] + ".c", "header"},
		"payload garbage": {strings.Split(good, ".")[0] + ".!!.c", "payload"},
		"payload array":   {strings.Split(good, ".")[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("[1]")) + ".c", "payload"},
		"too large":       {good + strings.Repeat("a", 64<<10), "too large"},
	} {
		if _, err := ParseIDToken(tc.tok, checks()); !isRefused(err, tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The nonce check must not pass when the stored nonce is empty.
	c := checks()
	c.Nonce = ""
	m := goodClaims()
	m["nonce"] = ""
	if _, err := ParseIDToken(jws(map[string]any{"alg": "RS256"}, m), c); err == nil {
		t.Error("an empty nonce matched an empty nonce")
	}
}

func TestClaimValues(t *testing.T) {
	claims := map[string]any{
		"groups":       []any{"a", "b", 7, "c"},
		"single":       "one",
		"realm_access": map[string]any{"roles": []any{"r1", "r2"}},
		"a.b":          []any{"dotted"},
		"number":       5,
	}
	for path, want := range map[string]string{
		"groups": "a,b,c", "single": "one", "realm_access.roles": "r1,r2", "a.b": "dotted", "number": "", "missing": "", "realm_access.nope": "", "groups.x": "",
	} {
		if got := strings.Join(claimValues(claims, path), ","); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
}

func TestCleanText(t *testing.T) {
	if got := cleanText("  Ann\x00 \n Ex\x7fample  ", 128); got != "Ann  Example" {
		t.Errorf("%q", got)
	}
	if got := cleanText(strings.Repeat("é", 200), 10); len([]rune(got)) != 10 {
		t.Errorf("%d runes", len([]rune(got)))
	}
}
