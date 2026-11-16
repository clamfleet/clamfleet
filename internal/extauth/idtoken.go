// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// idtoken.go: the checks on an OpenID Connect ID token (docs/plans/milestone-6.md 4.17).
//
// THE SIGNATURE IS NOT VERIFIED, on purpose (M6 decision 17; OIDC Core 1.0 section 3.1.3.7
// rule 6): the token reaches us straight from the provider's token endpoint over a TLS
// connection WE validated, in answer to a code only this server holds the verifier for, and
// that is what the specification allows in place of checking the signature. There is no JOSE
// parsing for an attacker to aim at: the token is split, base64url-decoded and read as JSON,
// nothing else. What this file WOULD get wrong if the token came any other way (a front
// channel, a token handed over by the browser, back-channel logout tokens) is exactly why
// those are out of scope: any of them needs signature verification, and then a JOSE library.
//
// Everything else is checked, and each check is a test (idtoken_test.go).
package extauth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"
)

// Bounds and tolerances of the ID token checks.
const (
	maxIDTokenBytes = 64 << 10
	maxSubBytes     = 255
	// clockSkew is how far the provider's clock may be ahead or behind ours.
	clockSkew = 60 * time.Second
	// maxIssuedAge is how old a token may be when we receive it (it was issued a moment ago).
	maxIssuedAge = 10 * time.Minute
)

// IDTokenChecks says what the token must match.
type IDTokenChecks struct {
	Issuer, ClientID string
	Nonce            string // the nonce stored with the sign-in
	Now              time.Time
}

// ParseIDToken decodes a compact JWS ID token and checks its claims. It returns the claims.
// Every failure is a *Refusal with a reason that names the check, never the token.
func ParseIDToken(raw string, c IDTokenChecks) (map[string]any, error) {
	if len(raw) > maxIDTokenBytes {
		return nil, refused("oidc: id token too large")
	}
	parts := strings.Split(raw, ".")
	switch len(parts) {
	case 3:
	case 5:
		return nil, refused("oidc: encrypted id token (JWE) is not supported")
	default:
		return nil, refused("oidc: id token is not a compact JWS")
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := decodePart(parts[0], &header); err != nil {
		return nil, refused("oidc: id token header")
	}
	// Rule: alg "none" is refused. The signature is not verified (see above), but a token that
	// says it is unsigned is not what a provider sends from its token endpoint.
	if header.Alg == "" || strings.EqualFold(header.Alg, "none") {
		return nil, refused("oidc: id token alg is none")
	}
	claims := map[string]any{}
	dec := json.NewDecoder(strings.NewReader(mustDecode(parts[1])))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil || claims == nil {
		return nil, refused("oidc: id token payload")
	}

	if iss, _ := claims["iss"].(string); iss != c.Issuer {
		return nil, refused("oidc: id token iss does not match the issuer")
	}
	auds, ok := audiences(claims["aud"])
	if !ok || !contains(auds, c.ClientID) {
		return nil, refused("oidc: id token aud does not contain the client id")
	}
	// azp: required with several audiences, and when present it must be us even with one.
	azp, hasAzp := claims["azp"]
	if len(auds) > 1 && !hasAzp {
		return nil, refused("oidc: id token has several audiences and no azp")
	}
	if hasAzp {
		if s, _ := azp.(string); s != c.ClientID {
			return nil, refused("oidc: id token azp is not the client id")
		}
	}
	exp, ok := number(claims["exp"])
	if !ok || !time.Unix(exp, 0).After(c.Now.Add(-clockSkew)) {
		return nil, refused("oidc: id token is expired")
	}
	iat, ok := number(claims["iat"])
	if !ok || time.Unix(iat, 0).Before(c.Now.Add(-maxIssuedAge)) || time.Unix(iat, 0).After(c.Now.Add(clockSkew)) {
		return nil, refused("oidc: id token iat is out of range")
	}
	if v, present := claims["nbf"]; present {
		nbf, ok := number(v)
		if !ok || time.Unix(nbf, 0).After(c.Now.Add(clockSkew)) {
			return nil, refused("oidc: id token is not valid yet")
		}
	}
	// Constant time: the nonce is a secret of this sign-in.
	if n, _ := claims["nonce"].(string); c.Nonce == "" || subtle.ConstantTimeCompare([]byte(n), []byte(c.Nonce)) != 1 {
		return nil, refused("oidc: id token nonce does not match")
	}
	if sub, _ := claims["sub"].(string); sub == "" || len(sub) > maxSubBytes || !utf8.ValidString(sub) {
		return nil, refused("oidc: id token sub is missing or invalid")
	}
	return claims, nil
}

func decodePart(s string, into any) error {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

// mustDecode returns the decoded part, or "" (which then fails to parse as JSON).
func mustDecode(s string) string {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return ""
	}
	return string(b)
}

// audiences reads "aud": a string, or an array of strings.
func audiences(v any) ([]string, bool) {
	switch a := v.(type) {
	case string:
		return []string{a}, true
	case []any:
		out := make([]string, 0, len(a))
		for _, x := range a {
			s, ok := x.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, len(out) > 0
	}
	return nil, false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// number reads a JSON number (NumericDate) as whole seconds.
func number(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	if i, err := n.Int64(); err == nil {
		return i, true
	}
	f, err := n.Float64()
	if err != nil || f < 0 || f > 1e12 {
		return 0, false
	}
	return int64(f), true
}

// claimValues walks a dotted path ("groups", "realm_access.roles") into the claims and returns
// the strings found there: a string is one value, an array contributes its string members, and
// anything else is nothing. The whole path is tried as one key first, because a claim name may
// itself contain dots ("https://example.org/roles" is a common one; so is "a.b").
func claimValues(claims map[string]any, path string) []string {
	var cur any = claims
	if v, ok := claims[path]; ok {
		cur = v
	} else {
		for _, seg := range strings.Split(path, ".") {
			m, ok := cur.(map[string]any)
			if !ok {
				return nil
			}
			if cur, ok = m[seg]; !ok {
				return nil
			}
		}
	}
	switch v := cur.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// cleanText keeps a provider-supplied name displayable: no control characters, at most n runes.
func cleanText(s string, n int) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if r < ' ' || r == 0x7f || r == utf8.RuneError {
			continue
		}
		if count++; count > n {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
