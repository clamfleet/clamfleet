// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// The strongest test that needs no container: the real agent binary talks to
// the real server binary over loopback TLS. Nothing is injected between them,
// so a route that is not mounted, a middleware that is missing or a token that
// is mishandled on either side turns it red.
package main

import (
	"bufio"
	"bytes"
	ctls "crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/testtls"
	"github.com/clamfleet/clamfleet/internal/version"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// liveServer is a running `clamfleet-server serve` child process.
type liveServer struct {
	addr   string
	env    []string
	stderr *syncBuf
}

// startServe runs `serve` on 127.0.0.1:0 with the test certificate and waits
// for its "listening" log line, which carries the real port.
func startServe(t *testing.T, tls testtls.Bundle, db string, extraEnv ...string) *liveServer {
	t.Helper()
	env := append(cliEnv(db,
		"CLAMFLEET_SERVER_TLS_CERT="+tls.Cert, "CLAMFLEET_SERVER_TLS_KEY="+tls.Key), extraEnv...)
	// cliEnv sets empty TLS_CERT/KEY first; the later entries win in the child's environment.
	cmd := exec.Command(serverBin, "serve")
	cmd.Env = env
	stderr := &syncBuf{}
	pipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Error("serve did not stop on SIGTERM")
		}
	})
	addrCh := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(pipe)
		for sc.Scan() {
			line := sc.Text()
			stderr.Write([]byte(line + "\n"))
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == "listening" {
				if a, ok := m["addr"].(string); ok {
					select {
					case addrCh <- a:
					default:
					}
				}
			}
		}
	}()
	select {
	case a := <-addrCh:
		return &liveServer{addr: a, env: env, stderr: stderr}
	case <-time.After(20 * time.Second):
		t.Fatalf("server did not start:\n%s", stderr.String())
		return nil
	}
}

// agentSetup writes an agent config, a token file and fake systemctl/journalctl
// (the M1 pattern) and returns a function that runs the real agent binary.
type agentSetup struct {
	t       *testing.T
	dir     string
	cfgPath string
	tokPath string
	baseEnv []string
}

func newAgent(t *testing.T, serverAddr, caFile, yamlExtra string) *agentSetup {
	t.Helper()
	dir := t.TempDir()
	fake := filepath.Join(dir, "bin")
	if err := os.Mkdir(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, body := range map[string]string{
		"systemctl":  "#!/bin/sh\nprintf 'LoadState=loaded\\nActiveState=active\\n'\n",
		"journalctl": "#!/bin/sh\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(fake, n), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	conf := filepath.Join(dir, "clamd.conf")
	if err := os.WriteFile(conf, []byte("LocalSocket "+filepath.Join(dir, "no-such-socket")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &agentSetup{t: t, dir: dir, cfgPath: filepath.Join(dir, "agent.yaml"), tokPath: filepath.Join(dir, "token"),
		// A clean environment; SSL_CERT_FILE is how the agent trusts the private test CA.
		baseEnv: []string{"PATH=" + fake, "SSL_CERT_FILE=" + caFile}}
	yml := "server: https://" + serverAddr + "\ntoken_file: " + a.tokPath + "\ntags: [e2e, two]\nclamd_conf: " + conf +
		"\ndb_dir: " + dir + "\nfreshclam_log: " + dir + "/none.log\nscan: {summary: " + dir + "/none.json}\n" + yamlExtra
	if err := os.WriteFile(a.cfgPath, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	return a
}

func (a *agentSetup) token(tok string) {
	a.t.Helper()
	if err := os.WriteFile(a.tokPath, []byte(tok+"\n"), 0o600); err != nil {
		a.t.Fatal(err)
	}
}

func (a *agentSetup) runOnce() result {
	a.t.Helper()
	cmd := exec.Command(agentBin, "run", "--once", "--config", a.cfgPath)
	cmd.Env = a.baseEnv
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		a.t.Fatal(err)
	}
	return result{so.String(), se.String(), code}
}

type shown struct {
	ReportedName string          `json:"reported_name"`
	AgentVersion string          `json:"agent_version"`
	ReportCount  int             `json:"report_count"`
	FirstSeen    *string         `json:"first_seen"`
	LastReport   json.RawMessage `json:"last_report"`
	Tags         []string        `json:"tags"`
}

func hostShow(t *testing.T, env []string, name string) shown {
	t.Helper()
	r := runServer(t, env, "host", "show", name, "--json")
	var s shown
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &s) != nil {
		t.Fatalf("host show: %+v", r)
	}
	return s
}

func TestAgentRunOnceStoresReportThroughServer(t *testing.T) {
	tls, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(t.TempDir(), "cf.db")
	srv := startServe(t, tls, db)

	// The admin CLI runs as a second process on the same SQLite file while the
	// server is up.
	reg := runServer(t, srv.env, "host", "add", "web01")
	if reg.code != 0 {
		t.Fatalf("host add: %+v", reg)
	}
	good := strings.TrimSpace(reg.stdout)

	ag := newAgent(t, srv.addr, tls.CA, "")
	ag.token(good)
	res := ag.runOnce()
	if res.code != 0 {
		t.Fatalf("agent run --once: exit %d\n%s", res.code, res.stderr)
	}
	s := hostShow(t, srv.env, "web01")
	if string(s.LastReport) == "null" || s.AgentVersion != version.Version || s.ReportCount != 1 || s.FirstSeen == nil {
		t.Fatalf("the report did not arrive through the server: %+v", s)
	}
	if s.ReportedName == "" || len(s.Tags) != 2 {
		t.Fatalf("%+v", s)
	}

	// A wrong token: exit 1, "unauthorized" on stderr, no new report.
	bad := strings.Replace(good, good[4:6], "AA", 1)
	if bad == good {
		bad = strings.Replace(good, good[4:6], "BB", 1)
	}
	ag.token(bad)
	res = ag.runOnce()
	if res.code != 1 || !strings.Contains(res.stderr, "unauthorized") {
		t.Fatalf("wrong token: exit %d\n%s", res.code, res.stderr)
	}
	if n := hostShow(t, srv.env, "web01").ReportCount; n != 1 {
		t.Fatalf("%d reports after a rejected one, want 1", n)
	}

	// After a rotation the old token (still in the agent's file) is refused and
	// the new one works, without restarting anything.
	rot := runServer(t, srv.env, "host", "rotate-token", "web01")
	fresh := strings.TrimSpace(rot.stdout)
	ag.token(good)
	if res := ag.runOnce(); res.code != 1 || !strings.Contains(res.stderr, "unauthorized") {
		t.Fatalf("old token after rotation: exit %d\n%s", res.code, res.stderr)
	}
	ag.token(fresh)
	if res := ag.runOnce(); res.code != 0 {
		t.Fatalf("new token: exit %d\n%s", res.code, res.stderr)
	}
	// ts has one-second resolution: two reports in the same second are one (natural-key dedup).
	if n := hostShow(t, srv.env, "web01").ReportCount; n < 1 || n > 2 {
		t.Fatalf("%d reports", n)
	}

	// No token appears in anything either process wrote to stderr.
	for _, tok := range []string{good, bad, fresh} {
		for _, stream := range []string{srv.stderr.String(), reg.stderr, rot.stderr, res.stderr} {
			if strings.Contains(stream, tok) || strings.Contains(stream, tok[4:]) {
				t.Fatalf("a token appears in a log:\n%s", stream)
			}
		}
	}
	if !strings.Contains(srv.stderr.String(), `"client_ip":"127.0.0.1"`) {
		t.Fatalf("the server did not log the client IP:\n%s", srv.stderr.String())
	}
}

// Decision 11, end to end with both real binaries: with tls.client_ca set the
// agent needs its certificate, and the token is needed as well.
func TestAgentRunOnceThroughMTLS(t *testing.T) {
	tls, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(t.TempDir(), "cf.db")
	srv := startServe(t, tls, db, "CLAMFLEET_SERVER_TLS_CLIENT_CA="+tls.CA)
	reg := runServer(t, srv.env, "host", "add", "web01")
	tok := strings.TrimSpace(reg.stdout)

	// No client certificate configured: the handshake fails, nothing is stored.
	ag := newAgent(t, srv.addr, tls.CA, "")
	ag.token(tok)
	if res := ag.runOnce(); res.code != 1 || !strings.Contains(res.stderr, `"class":"network"`) {
		t.Fatalf("agent without a certificate: exit %d\n%s", res.code, res.stderr)
	}
	if n := hostShow(t, srv.env, "web01").ReportCount; n != 0 {
		t.Fatalf("%d reports through a failed handshake", n)
	}

	// Certificate and token: accepted.
	ag = newAgent(t, srv.addr, tls.CA, "tls: {client_cert: "+tls.ClientCert+", client_key: "+tls.ClientKey+"}\n")
	ag.token(tok)
	if res := ag.runOnce(); res.code != 0 {
		t.Fatalf("agent with certificate and token: exit %d\n%s", res.code, res.stderr)
	}
	if n := hostShow(t, srv.env, "web01").ReportCount; n != 1 {
		t.Fatalf("%d reports, want 1", n)
	}

	// Certificate but a wrong token: the certificate alone is not enough.
	other := runServer(t, srv.env, "host", "rotate-token", "web01")
	if other.code != 0 {
		t.Fatal(other)
	}
	if res := ag.runOnce(); res.code != 1 || !strings.Contains(res.stderr, "unauthorized") {
		t.Fatalf("valid certificate, stale token: exit %d\n%s", res.code, res.stderr)
	}
}

// The config key must reach the handler of the real binary: a main() that
// drops trusted_proxies (or never passes it on) logs the proxy's address.
func TestServeAppliesTrustedProxies(t *testing.T) {
	tls, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, proxies, want string
	}{
		{"trusted peer", "10.9.9.9,127.0.0.1", "203.0.113.7"},
		{"peer not trusted", "10.9.9.9", "127.0.0.1"},
	} {
		srv := startServe(t, tls, filepath.Join(t.TempDir(), "cf.db"), "CLAMFLEET_SERVER_TRUSTED_PROXIES="+tc.proxies)
		ca, _ := os.ReadFile(tls.CA)
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(ca)
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &ctls.Config{RootCAs: pool}}, Timeout: 10 * time.Second}
		req, _ := http.NewRequest("POST", "https://"+srv.addr+"/v1/report", nil)
		req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.7")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		deadline := time.Now().Add(5 * time.Second)
		for !strings.Contains(srv.stderr.String(), `"client_ip":"`+tc.want+`"`) && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if !strings.Contains(srv.stderr.String(), `"client_ip":"`+tc.want+`"`) {
			t.Errorf("%s: want client_ip %s in the request log:\n%s", tc.name, tc.want, srv.stderr.String())
		}
	}
}
