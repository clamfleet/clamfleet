// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Command idpdriver signs in to a ClamFleet console like a browser would, for the identity-provider
// interoperability test (make e2e-idp, e2e/idp_e2e_test.go). The test runs it INSIDE the clamfleet-idp
// container, next to the real server, OpenLDAP and Keycloak, so nothing is exposed: the console, the
// directory and the provider all listen on 127.0.0.1 there.
//
//	idpdriver ldap --url https://127.0.0.1:8443 --ca ca.pem --user alice --password PW
//	idpdriver oidc --url https://127.0.0.1:8443 --ca ca.pem --user alice --password PW
//
// ldap posts the console's login form with the user name. oidc posts the SSO form, follows the link
// to Keycloak, submits Keycloak's login form (an HTML form: the action is parsed out of the page and
// its &amp; unescaped), and returns to the console's callback with the console's cookie jar, which
// holds the state cookie. Both then read what the console shows a signed-in user and print one JSON
// object. A cookie jar per site, because the console and Keycloak are both on 127.0.0.1 and a jar
// ignores ports.
//
// It is a test tool: it reads the real clock, trusts the CA it is given, and prints no password.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Result is what the driver prints.
type Result struct {
	// Status is the status of the last response of the sign-in (after the redirects it follows).
	Status int `json:"status"`
	// SignedIn is true when the console then showed a signed-in page.
	SignedIn bool `json:"signed_in"`
	// CurrentUser is the console's header text ("alice@example.test (admin)"), "" when not signed in.
	CurrentUser string `json:"current_user"`
	// AccountSource is the account page's source label ("LDAP"), "" when not signed in.
	AccountSource string `json:"account_source"`
	// AdminPage is the status of GET /admin/hosts (200 for an admin, 403 for a viewer, 303 when not signed in).
	AdminPage int `json:"admin_page"`
	// TestIDs are the data-testid values of the page the sign-in ended on (error-no-role, login-form ...).
	TestIDs []string `json:"test_ids"`
	// ErrorText is the console's inline error text (the generic failure), "" if none.
	ErrorText string `json:"error_text"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "idpdriver:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 || (args[0] != "ldap" && args[0] != "oidc") {
		return errors.New("usage: idpdriver ldap|oidc --url URL --ca FILE --user NAME --password PW")
	}
	mode := args[0]
	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	base := fs.String("url", "", "console URL")
	caFile := fs.String("ca", "", "CA certificate (PEM) of the console")
	user := fs.String("user", "", "user name")
	pw := fs.String("password", "", "password")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *base == "" || *caFile == "" || *user == "" {
		return errors.New("--url, --ca and --user are required")
	}
	pem, err := os.ReadFile(*caFile)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return errors.New("--ca holds no certificate")
	}
	console := newClient(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	var res Result
	switch mode {
	case "ldap":
		res, err = ldapSignIn(console, *base, *user, *pw)
	case "oidc":
		res, err = oidcSignIn(console, newClient(nil), *base, *user, *pw)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(res)
}

// newClient returns a client with its own cookie jar that follows no redirect by itself.
func newClient(tc *tls.Config) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar, Timeout: 30 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: tc},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func do(c *http.Client, method, u string, form url.Values, hdr map[string]string) (*http.Response, string, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, "", err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp, string(b), err
}

// sameOrigin is what a browser sends with a form post from the console's own page.
var sameOrigin = map[string]string{"Sec-Fetch-Site": "same-origin"}

// follow follows 3xx answers on the console (same host), up to 5, and returns the last response and body.
func follow(c *http.Client, base string, resp *http.Response, body string) (*http.Response, string, error) {
	for i := 0; i < 5 && resp.StatusCode >= 300 && resp.StatusCode < 400; i++ {
		loc, err := resp.Location()
		if err != nil {
			return resp, body, err
		}
		if !strings.HasPrefix(loc.String(), base) {
			return resp, body, fmt.Errorf("the console redirected to another host: %s", loc.Host)
		}
		if resp, body, err = do(c, "GET", loc.String(), nil, nil); err != nil {
			return resp, body, err
		}
	}
	return resp, body, nil
}

func ldapSignIn(c *http.Client, base, user, pw string) (Result, error) {
	if _, _, err := do(c, "GET", base+"/login", nil, nil); err != nil {
		return Result{}, err
	}
	resp, body, err := do(c, "POST", base+"/login", url.Values{"email": {user}, "password": {pw}}, sameOrigin)
	if err != nil {
		return Result{}, err
	}
	if resp, body, err = follow(c, base, resp, body); err != nil {
		return Result{}, err
	}
	return describe(c, base, resp, body)
}

var formActionRE = regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)
var continueRE = regexp.MustCompile(`<a href="([^"]+)" data-testid="sso-continue"`)

func oidcSignIn(c, idp *http.Client, base, user, pw string) (Result, error) {
	// 1. The SSO form: a page whose link goes to Keycloak.
	resp, body, err := do(c, "POST", base+"/login/oidc", url.Values{}, sameOrigin)
	if err != nil {
		return Result{}, err
	}
	m := continueRE.FindStringSubmatch(body)
	if resp.StatusCode != 200 || m == nil {
		return Result{}, fmt.Errorf("the SSO start answered %d without a link to the provider", resp.StatusCode)
	}
	authURL := html.UnescapeString(m[1])

	// 2. Keycloak: open the page (it may redirect inside its own site), then submit its login form.
	idp.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(r.URL.String(), base+"/") {
			return http.ErrUseLastResponse // the way back to the console is the console's to follow
		}
		return nil
	}
	resp, body, err = do(idp, "GET", authURL, nil, nil)
	if err != nil {
		return Result{}, err
	}
	fm := formActionRE.FindStringSubmatch(body)
	if resp.StatusCode != 200 || fm == nil {
		return Result{}, fmt.Errorf("no Keycloak login form (status %d)", resp.StatusCode)
	}
	action := html.UnescapeString(fm[1]) // the action carries &amp; in the page
	resp, _, err = do(idp, "POST", action, url.Values{"username": {user}, "password": {pw}, "credentialId": {""}}, nil)
	if err != nil {
		return Result{}, err
	}
	if resp.StatusCode == 200 {
		// Keycloak showed its form again: the credentials were wrong.
		return Result{Status: 200, TestIDs: []string{"keycloak-login-failed"}}, nil
	}
	back, err := resp.Location()
	if err != nil || !strings.HasPrefix(back.String(), base+"/login/oidc/callback") {
		return Result{}, fmt.Errorf("the provider did not return to the console callback (status %d)", resp.StatusCode)
	}

	// 3. The callback, with the console's cookie jar (the state cookie).
	resp, body, err = do(c, "GET", back.String(), nil, nil)
	if err != nil {
		return Result{}, err
	}
	if resp, body, err = follow(c, base, resp, body); err != nil {
		return Result{}, err
	}
	return describe(c, base, resp, body)
}

var testIDRE = regexp.MustCompile(`data-testid="([a-z0-9-]+)"`)
var currentUserRE = regexp.MustCompile(`data-testid="current-user">([^<]*)<`)
var sourceRE = regexp.MustCompile(`data-testid="account-source">([^<]*)<`)
var errorRE = regexp.MustCompile(`data-testid="error" role="alert">([^<]*)<`)

// describe reads what the console shows after the sign-in attempt.
func describe(c *http.Client, base string, resp *http.Response, body string) (Result, error) {
	r := Result{Status: resp.StatusCode}
	for _, m := range testIDRE.FindAllStringSubmatch(body, -1) {
		r.TestIDs = append(r.TestIDs, m[1])
	}
	if m := errorRE.FindStringSubmatch(body); m != nil {
		r.ErrorText = html.UnescapeString(m[1])
	}
	if m := currentUserRE.FindStringSubmatch(body); m != nil {
		r.SignedIn, r.CurrentUser = true, html.UnescapeString(strings.TrimSpace(m[1]))
		_, acc, err := do(c, "GET", base+"/account", nil, nil)
		if err != nil {
			return r, err
		}
		if m := sourceRE.FindStringSubmatch(acc); m != nil {
			r.AccountSource = html.UnescapeString(m[1])
		}
	}
	ar, _, err := do(c, "GET", base+"/admin/hosts", nil, nil)
	if err != nil {
		return r, err
	}
	r.AdminPage = ar.StatusCode
	return r, nil
}
