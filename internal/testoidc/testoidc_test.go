// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package testoidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const redirect = "http://127.0.0.1:1/login/oidc/callback"

var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 5 * time.Second}

func start(t *testing.T) *Server {
	t.Helper()
	s, err := Start(Options{RedirectURIs: []string{redirect}, Now: func() time.Time { return time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.AddUser("ann", map[string]any{"groups": []string{"admins"}, "email": "ann@example.org", "email_verified": true})
	return s
}

func challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func authQuery(verifier, method string) url.Values {
	return url.Values{"response_type": {"code"}, "client_id": {ClientID}, "redirect_uri": {redirect}, "scope": {"openid email"},
		"state": {"st"}, "nonce": {"nn"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {method}}
}

// issueCode drives authorize and pick, returning the code the browser would carry back.
func issueCode(t *testing.T, s *Server, q url.Values) string {
	t.Helper()
	q.Set("user", "ann")
	resp, err := noFollow.Get(s.Issuer() + "/authorize/pick?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || loc.Query().Get("state") != "st" || loc.Query().Get("code") == "" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	return loc.Query().Get("code")
}

func exchange(t *testing.T, s *Server, code, verifier string, basic bool) (int, map[string]any) {
	t.Helper()
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}}
	if verifier != "" {
		f.Set("code_verifier", verifier)
	}
	req, _ := http.NewRequest("POST", s.Issuer()+"/token", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth(ClientID, ClientSecret)
	} else {
		f.Set("client_id", ClientID)
		f.Set("client_secret", ClientSecret)
		req, _ = http.NewRequest("POST", s.Issuer()+"/token", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func claimsOf(t *testing.T, tok any) map[string]any {
	t.Helper()
	parts := strings.Split(tok.(string), ".")
	if len(parts) != 3 {
		t.Fatalf("%d parts", len(parts))
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFakeHappyPathAndSingleUseCode(t *testing.T) {
	s := start(t)
	code := issueCode(t, s, authQuery("v-123", "S256"))
	st, body := exchange(t, s, code, "v-123", true)
	if st != 200 {
		t.Fatalf("%d %v", st, body)
	}
	c := claimsOf(t, body["id_token"])
	if c["iss"] != s.Issuer() || c["aud"] != ClientID || c["nonce"] != "nn" || c["sub"] != "ann" || c["email_verified"] != true || c["exp"].(float64) != float64(time.Date(2031, 3, 4, 12, 5, 0, 0, time.UTC).Unix()) {
		t.Fatalf("%v", c)
	}
	if st, _ := exchange(t, s, code, "v-123", true); st != 400 {
		t.Fatalf("a code works twice: %d", st)
	}
	if tk := s.Tokens(); len(tk) != 2 || tk[0].AuthMethod != "basic" || !tk[0].HasVerifier {
		t.Fatalf("%+v", tk)
	}
}

func TestFakeEnforcesPKCEAndClientAuthentication(t *testing.T) {
	s := start(t)
	// Verifier missing, wrong: refused, and the code is burnt either way.
	for name, v := range map[string]string{"missing": "", "wrong": "other"} {
		code := issueCode(t, s, authQuery("v-123", "S256"))
		if st, _ := exchange(t, s, code, v, true); st != 400 {
			t.Errorf("%s verifier: %d", name, st)
		}
		if st, _ := exchange(t, s, code, "v-123", true); st != 400 {
			t.Errorf("%s: the code survived a failed exchange", name)
		}
	}
	// plain or no challenge: refused at the authorization endpoint.
	for _, m := range []string{"plain", ""} {
		q := authQuery("v", m)
		resp, _ := noFollow.Get(s.Issuer() + "/authorize?" + q.Encode())
		resp.Body.Close()
		if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=invalid_request") {
			t.Errorf("method %q: %d %s", m, resp.StatusCode, loc)
		}
	}
	// Unregistered redirect URI: an error page, never a redirect.
	q := authQuery("v", "S256")
	q.Set("redirect_uri", "https://evil.example/cb")
	resp, _ := noFollow.Get(s.Issuer() + "/authorize?" + q.Encode())
	resp.Body.Close()
	if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
		t.Fatalf("%d", resp.StatusCode)
	}
	// Client authentication: a bad secret is refused; post works as well as basic.
	code := issueCode(t, s, authQuery("v-123", "S256"))
	if st, _ := exchange(t, s, code, "v-123", false); st != 200 {
		t.Fatalf("client_secret_post: %d", st)
	}
	req, _ := http.NewRequest("POST", s.Issuer()+"/token", strings.NewReader("grant_type=authorization_code&code=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(ClientID, "wrong")
	r2, _ := noFollow.Do(req)
	r2.Body.Close()
	if r2.StatusCode != 401 {
		t.Fatalf("bad secret: %d", r2.StatusCode)
	}
}

func TestFakeScriptsMisbehaviour(t *testing.T) {
	s := start(t)
	s.SetScript(Script{Claims: func(c map[string]any) { c["iss"] = "https://evil.example" }})
	_, body := exchange(t, s, issueCode(t, s, authQuery("v", "S256")), "v", true)
	if claimsOf(t, body["id_token"])["iss"] != "https://evil.example" {
		t.Fatal("the script did not apply")
	}
	s.SetScript(Script{RawIDToken: "a.b.c.d.e"})
	_, body = exchange(t, s, issueCode(t, s, authQuery("v", "S256")), "v", true)
	if body["id_token"] != "a.b.c.d.e" {
		t.Fatal("raw token")
	}
	s.SetScript(Script{DiscoveryIssuer: "https://other.example"})
	resp, _ := noFollow.Get(s.Issuer() + "/.well-known/openid-configuration")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), `"issuer":"https://other.example"`) || s.DiscoveryFetches() != 1 {
		t.Fatalf("%s", b)
	}
	s.SetScript(Script{AuthorizeError: "access_denied"})
	resp, _ = noFollow.Get(s.Issuer() + "/authorize?" + authQuery("v", "S256").Encode())
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Location"), "error=access_denied") || !strings.Contains(resp.Header.Get("Location"), "state=st") {
		t.Fatal(resp.Header.Get("Location"))
	}
}
