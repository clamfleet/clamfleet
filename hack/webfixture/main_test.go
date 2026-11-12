// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"bytes"
	"context"
	"encoding/json"
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
