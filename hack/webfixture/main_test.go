// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *safeBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// The fixture is what the browser tests stand on, so it is tested like the
// product: start it, sign in with what fixture.json says, read the states the
// notes promise, stop it and check nothing is left behind.
func TestFixtureStartsSeedsAndCleansUp(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "clamfleet-server")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/clamfleet-server").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr safeBuf
	done := make(chan error, 1)
	jsonPath := filepath.Join(t.TempDir(), "copy.json")
	go func() { done <- run(ctx, []string{"--server-bin", bin, "--json-out", jsonPath}, &stdout, &stderr) }()

	var url0 string
	for deadline := time.Now().Add(60 * time.Second); url0 == "" && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		select {
		case err := <-done:
			t.Fatalf("fixture exited early: %v\n%s", err, stderr.String())
		default:
		}
		if line := stdout.String(); strings.HasPrefix(line, "READY ") && strings.HasSuffix(line, "\n") {
			url0 = strings.TrimSpace(strings.TrimPrefix(line, "READY "))
		}
	}
	if !strings.HasPrefix(url0, "https://127.0.0.1:") {
		t.Fatalf("no READY line on loopback: %q", stdout.String())
	}
	var fx Fixture
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(fx.TmpDir, "fixture.json")); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("fixture.json must be mode 0600: %v", fi)
	}

	client, err := httpClient(fx.CACert)
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	do := func(method, path string, form url.Values) (int, string) {
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, _ := http.NewRequest(method, fx.URL+path, body)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	login := func(l Login) int {
		code, _ := do("POST", "/login", url.Values{"email": {l.Email}, "password": {l.Password}})
		return code
	}

	if login(fx.Viewer) != 303 {
		t.Fatal("viewer cannot sign in")
	}
	code, page := do("GET", "/", nil)
	if code != 200 {
		t.Fatalf("fleet: %d", code)
	}
	for name, h := range fx.Hosts {
		want := `data-testid="fleet-state-` + name + `">` + h.State + `<`
		if !strings.Contains(page, want) {
			t.Errorf("host %s: the fleet page does not show %s as promised in fixture.json", name, h.State)
		}
	}
	// Hostile agent text is inert.
	if strings.Contains(page, "<script>alert") || strings.Contains(page, "<img src=x") {
		t.Error("xss01 text reached the page unescaped")
	}
	if code, _ := do("GET", "/admin/hosts", nil); code != 403 {
		t.Errorf("viewer on /admin/hosts: %d", code)
	}

	// A fresh jar: the admin, who may open the hosts page.
	jar2, _ := cookiejar.New(nil)
	client.Jar = jar2
	if login(fx.Admin) != 303 {
		t.Fatal("admin cannot sign in")
	}
	if code, _ := do("GET", "/admin/hosts", nil); code != 200 {
		t.Errorf("admin on /admin/hosts: %d", code)
	}
	// The one-time-password user is sent to the password change.
	jar3, _ := cookiejar.New(nil)
	client.Jar = jar3
	req, _ := http.NewRequest("POST", fx.URL+"/login", strings.NewReader(url.Values{"email": {fx.MustChange.Email}, "password": {fx.MustChange.Password}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/account" {
		t.Errorf("must-change login: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Stop: the process ends, the temp directory is gone, the port is closed.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("fixture did not stop")
	}
	if _, err := os.Stat(fx.TmpDir); !os.IsNotExist(err) {
		t.Errorf("temp dir %s was not removed", fx.TmpDir)
	}
	if _, err := client.Get(fx.URL + "/healthz"); err == nil {
		t.Error("the server still answers after the fixture stopped")
	}
}

// startFixture runs the fixture with extra flags and returns what fixture.json says
// and a client with a fresh cookie jar that does not follow redirects. The fixture
// is stopped and its temp directory checked gone at test end.
func startFixture(t *testing.T, bin string, extra ...string) (Fixture, func() *http.Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr safeBuf
	done := make(chan error, 1)
	jsonPath := filepath.Join(t.TempDir(), "copy.json")
	go func() {
		done <- run(ctx, append([]string{"--server-bin", bin, "--json-out", jsonPath}, extra...), &stdout, &stderr)
	}()
	ready := false
	for deadline := time.Now().Add(60 * time.Second); !ready && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		select {
		case err := <-done:
			t.Fatalf("fixture exited early: %v\n%s", err, stderr.String())
		default:
		}
		ready = strings.HasPrefix(stdout.String(), "READY ") && strings.HasSuffix(stdout.String(), "\n")
	}
	if !ready {
		cancel()
		t.Fatalf("fixture did not become ready:\n%s", stderr.String())
	}
	var fx Fixture
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("fixture did not stop")
		}
		if _, err := os.Stat(fx.TmpDir); !os.IsNotExist(err) {
			t.Errorf("temp dir %s was not removed", fx.TmpDir)
		}
	})
	return fx, func() *http.Client {
		c, err := httpClient(fx.CACert)
		if err != nil {
			t.Fatal(err)
		}
		jar, _ := cookiejar.New(nil)
		c.Jar = jar
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return c
	}
}

func buildServer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "clamfleet-server")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/clamfleet-server").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func post(t *testing.T, c *http.Client, base, path string, form url.Values) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header.Get("Location")
}

// rfc6238 is a second implementation of the code a browser test makes from
// fixture.json: HMAC-SHA1, 6 digits, 30 s.
func rfc6238(t *testing.T, secretB32 string, step int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	s := m.Sum(nil)
	off := s[19] & 0x0f
	n := (uint32(s[off])&0x7f)<<24 | uint32(s[off+1])<<16 | uint32(s[off+2])<<8 | uint32(s[off+3])
	return fmt.Sprintf("%06d", n%1_000_000)
}

// The seeded users for the two-factor browser tests: `enrol` signs in with the
// password alone, `totp` goes through the code step with the secret and the
// recovery codes that fixture.json promises, and there is no `forced` user unless asked.
func TestFixtureSeedsTOTPUsers(t *testing.T) {
	fx, newClient := startFixture(t, buildServer(t))
	if fx.TOTPRequired || fx.Forced != nil {
		t.Fatalf("totp_required=%v forced=%v without --totp-required", fx.TOTPRequired, fx.Forced)
	}
	if fi, err := os.Stat(filepath.Join(fx.TmpDir, "secret.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the key file made by `key generate`: %v %v", fi, err)
	}
	if len(fx.TOTP.RecoveryCodes) != 10 || len(fx.TOTP.SecretBase32) != 32 {
		t.Fatalf("totp seed: %+v", fx.TOTP)
	}

	// enrol: no second factor yet.
	c := newClient()
	if code, loc := post(t, c, fx.URL, "/login", url.Values{"email": {fx.Enrol.Email}, "password": {fx.Enrol.Password}}); code != 303 || loc != "/" {
		t.Fatalf("enrol login: %d %q", code, loc)
	}

	// totp: password, then a code made from the secret in fixture.json.
	c = newClient()
	if code, loc := post(t, c, fx.URL, "/login", url.Values{"email": {fx.TOTP.Email}, "password": {fx.TOTP.Password}}); code != 303 || loc != "/login/totp" {
		t.Fatalf("totp password step: %d %q", code, loc)
	}
	step := time.Now().Unix() / 30
	if code, loc := post(t, c, fx.URL, "/login/totp", url.Values{"code": {rfc6238(t, fx.TOTP.SecretBase32, step)}}); code != 303 || loc != "/" {
		t.Fatalf("totp code step: %d %q", code, loc)
	}

	// A recovery code works in a new browser; the same code does not work twice.
	for i, want := range []int{303, 200} {
		c = newClient()
		post(t, c, fx.URL, "/login", url.Values{"email": {fx.TOTP.Email}, "password": {fx.TOTP.Password}})
		code, _ := post(t, c, fx.URL, "/login/totp", url.Values{"code": {fx.TOTP.RecoveryCodes[0]}})
		if code != want {
			t.Fatalf("recovery code, use %d: %d, want %d", i+1, code, want)
		}
	}
}

func TestFixtureTOTPRequiredSeedsForcedUser(t *testing.T) {
	fx, newClient := startFixture(t, buildServer(t), "--totp-required")
	if !fx.TOTPRequired || fx.Forced == nil || fx.Forced.Email != "forced@fixture.example" {
		t.Fatalf("totp_required=%v forced=%v", fx.TOTPRequired, fx.Forced)
	}
	c := newClient()
	if code, loc := post(t, c, fx.URL, "/login", url.Values{"email": {fx.Forced.Email}, "password": {fx.Forced.Password}}); code != 303 {
		t.Fatalf("forced login: %d %q", code, loc)
	}
	resp, err := c.Get(fx.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/account/totp" {
		t.Fatalf("GET / as the forced user: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// The user with an authenticator is not gated.
	c = newClient()
	post(t, c, fx.URL, "/login", url.Values{"email": {fx.TOTP.Email}, "password": {fx.TOTP.Password}})
	if code, loc := post(t, c, fx.URL, "/login/totp", url.Values{"code": {rfc6238(t, fx.TOTP.SecretBase32, time.Now().Unix()/30)}}); code != 303 || loc != "/" {
		t.Fatalf("totp user under totp_required: %d %q", code, loc)
	}
	resp, err = c.Get(fx.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET / as an enrolled user: %d", resp.StatusCode)
	}
}
