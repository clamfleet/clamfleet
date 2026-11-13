// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/alert"
	"github.com/clamfleet/clamfleet/internal/proto"
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

// The Alerts pages need a receiver the server can reach and a way to read what
// arrived: the fixture promises both (docs/testing.md). This walks the whole
// promise with the real server: the seeded target is listed, a clamd-down report
// of the promised host reaches the receiver as one signed state_change, and the
// console's test send reaches it as a "test" payload.
func TestFixtureAlertsReceiverAndSeededTarget(t *testing.T) {
	fx, newClient := startFixture(t, buildServer(t))
	a := fx.Alerts
	if a.SeededTarget != "seeded-hook" || a.Host != "alerts01" || !strings.HasPrefix(a.ReceiverURL, "http://127.0.0.1:") ||
		!strings.HasPrefix(a.SigningKey, "whsec_") || a.HookURL != a.ReceiverURL+"/hook/seeded" {
		t.Fatalf("%+v", a)
	}
	type rec struct {
		Path   string              `json:"path"`
		Header map[string][]string `json:"header"`
		Body   string              `json:"body"`
	}
	requests := func() []rec {
		resp, err := http.Get(a.RequestsURL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out []rec
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if n := len(requests()); n != 0 {
		t.Fatalf("the receiver holds %d requests before anything was sent: the seeding must not alert", n)
	}

	c := newClient()
	if code, _ := post(t, c, fx.URL, "/login", url.Values{"email": {fx.Admin.Email}, "password": {fx.Admin.Password}}); code != 303 {
		t.Fatal("admin cannot sign in")
	}
	get := func(path string) (int, string) {
		resp, err := c.Get(fx.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	code, page := get("/admin/alerts")
	if code != 200 || !strings.Contains(page, `data-testid="alert-row-seeded-hook"`) || !strings.Contains(page, `data-testid="alert-unencrypted-seeded-hook"`) ||
		strings.Contains(page, "/hook/seeded") || strings.Contains(page, a.SigningKey) {
		t.Fatalf("Alerts page: %d (the URL path and the key must not be shown)\n%s", code, page)
	}
	if strings.Contains(page, "alert-banner-no-public-url") {
		t.Error("public_url is set in the fixture config: no banner")
	}
	if !strings.Contains(page, "alert-banner-email-off") {
		t.Error("email is off in the fixture: the banner must show")
	}

	// A clamd-down report of alerts01: one signed CRIT alert within the dispatcher's tick.
	// A report's timestamp has one-second resolution and a repeated (host, ts) is a duplicate that
	// changes nothing: the seeding report of alerts01 may be in this very second.
	time.Sleep(1100 * time.Millisecond)
	rep := baseReport("alerts01", time.Now().UTC(), "alerts")
	msg := "ping: timeout"
	rep.Clamd = proto.Clamd{Up: false, Error: &msg}
	client, err := httpClient(fx.CACert)
	if err != nil {
		t.Fatal(err)
	}
	if err := postReport(context.Background(), client, fx.URL, fx.Hosts["alerts01"].Token, rep); err != nil {
		t.Fatal(err)
	}
	var got []rec
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if got = requests(); len(got) >= 1 {
			break
		}
	}
	if len(got) != 1 || got[0].Path != "/hook/seeded" {
		log, _ := os.ReadFile(fx.ServerLog)
		t.Fatalf("the receiver got %d requests: %+v\nserver log:\n%s", len(got), got, log)
	}
	var p struct {
		Kind, Host, To string
		URL            *string
	}
	if err := json.Unmarshal([]byte(got[0].Body), &p); err != nil || p.Kind != "state_change" || p.Host != "alerts01" || p.To != "CRIT" || p.URL == nil || *p.URL != fx.URL+"/hosts/alerts01" {
		t.Fatalf("%+v %v\n%s", p, err, got[0].Body)
	}
	key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(a.SigningKey, "whsec_"))
	ts, _ := strconv.ParseInt(got[0].Header["Webhook-Timestamp"][0], 10, 64)
	if !alert.VerifySignature(key, got[0].Header["Webhook-Id"][0], ts, []byte(got[0].Body), got[0].Header["Webhook-Signature"][0]) {
		t.Fatalf("the signature does not verify with the key in fixture.json: %v", got[0].Header)
	}

	// Test send from the console (htmx): the fragment says delivered and the receiver records kind "test".
	_, home := get("/admin/alerts")
	m := regexp.MustCompile(`<meta name="csrf-token" content="([^"]+)">`).FindStringSubmatch(home)
	if m == nil {
		t.Fatal("no csrf token")
	}
	req, _ := http.NewRequest("POST", fx.URL+"/admin/alerts/seeded-hook/test", nil)
	req.Header.Set("HX-Request", "true")
	req.Header.Set("X-CSRF-Token", html.UnescapeString(m[1]))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "Delivered: HTTP 204") {
		t.Fatalf("test send: %d %s", resp.StatusCode, body)
	}
	if n := len(requests()); n != 2 {
		t.Fatalf("%d requests after the test send, want 2", n)
	}

	// The receiver's controls: scripted status and clearing.
	if resp, err := http.Post(a.StatusURL+"?code=503", "", nil); err != nil || resp.StatusCode != 204 {
		t.Fatalf("%v %v", resp, err)
	}
	if resp, err := http.Post(a.ReceiverURL+"/anything", "application/json", strings.NewReader("{}")); err != nil || resp.StatusCode != 503 {
		t.Fatalf("scripted status: %v %v", resp, err)
	}
	if resp, err := http.Post(a.StatusURL+"?code=0", "", nil); err != nil || resp.StatusCode != 204 {
		t.Fatal(err)
	}
	if resp, err := http.Post(a.StatusURL+"?code=99", "", nil); err != nil || resp.StatusCode != 400 {
		t.Fatalf("a bad code must be refused: %v %v", resp, err)
	}
	reqDel, _ := http.NewRequest("DELETE", a.RequestsURL, nil)
	if resp, err := http.DefaultClient.Do(reqDel); err != nil || resp.StatusCode != 204 {
		t.Fatalf("%v %v", resp, err)
	}
	if n := len(requests()); n != 0 {
		t.Fatalf("%d requests after DELETE", n)
	}
}

// The events fixture promises: ids per host, an open count, some acknowledged events,
// and hostile names that render inert. The page is read as the admin and as the viewer.
func TestFixtureSeedsDetections(t *testing.T) {
	fx, newClient := startFixture(t, buildServer(t))
	ev := fx.Events
	if ev.OpenCount != 9 || len(ev.AckedIDs) != 2 || ev.AckedBy != fx.Admin.Email {
		t.Fatalf("%+v", ev)
	}
	for host, want := range map[string]int{"crit01": 2, "xss01": 5, "warn01": 1, "alerts01": 1, "ok01": 2} {
		if got := len(ev.IDsByHost[host]); got != want {
			t.Errorf("%s: %d event ids, want %d (a merged duplicate counts once)", host, got, want)
		}
	}
	c := newClient()
	if code, _ := post(t, c, fx.URL, "/login", url.Values{"email": {fx.Admin.Email}, "password": {fx.Admin.Password}}); code != 303 {
		t.Fatal("admin cannot sign in")
	}
	get := func(path string) string {
		resp, err := c.Get(fx.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	page := get("/events?ack=all")
	for _, want := range []string{
		`data-testid="nav-events-count">9<`, "Acknowledged by " + fx.Admin.Email, "&times;2", "received 3h later, spooled",
		`\u{202E}</span>`, `\u{2028}</span>`, `byte 0xFF, not valid UTF-8`, `back\slash.txt`, `literal\u{202E}name`,
		`&lt;img src=x onerror=alert(1)&gt;`, `&lt;b&gt;Win.Test.XSS&lt;/b&gt;`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the events page lacks %q", want)
		}
	}
	for _, bad := range []string{"\u202e", "\u2028", "<img src=x", "<b>Win"} {
		if strings.Contains(page, bad) {
			t.Errorf("the raw %q reached the page", bad)
		}
	}
	if open := get("/events"); strings.Contains(open, "Acknowledged by") || strings.Count(open, `data-testid="event-row-`) != 9 {
		t.Errorf("the default (open) filter shows %d rows, want 9 (9 open; the x2 merge is one row)", strings.Count(open, `data-testid="event-row-`))
	}
}
