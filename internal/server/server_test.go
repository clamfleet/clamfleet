// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/agentauth"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
	"github.com/clamfleet/clamfleet/internal/testtls"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

var fixedNow = time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC)

type running struct {
	addr  string
	logs  *syncBuf
	token string
	st    *sqlite.Store
	tls   testtls.Bundle
	done  chan error
	stop  context.CancelFunc
}

// start runs the real listener (ServeListener) with a real store and a
// registered host. mut adjusts the config before it starts.
func start(t *testing.T, mut func(c *Config, b testtls.Bundle)) *running {
	t.Helper()
	dir := t.TempDir()
	b, err := testtls.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st, err := sqlite.Open(ctx, filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	tok, hash, _ := agentauth.Generate()
	if _, err := st.CreateHost(ctx, "app01", hash, fixedNow, store.Audit{Kind: store.ActorCLI, Actor: "t"}); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Listen: "127.0.0.1:0", TLS: TLS{Cert: b.Cert, Key: b.Key}, DBPath: filepath.Join(dir, "s.db")}
	if mut != nil {
		mut(&cfg, b)
	}
	logs := &syncBuf{}
	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ln, err := Listen(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sctx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	h := NewHandler(Deps{Store: st, Now: func() time.Time { return fixedNow }, Log: log})
	go func() { done <- ServeListener(sctx, ln, cfg, h, log) }()
	r := &running{addr: ln.Addr().String(), logs: logs, token: tok, st: st, tls: b, done: done, stop: stop}
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("server did not shut down")
		}
		st.Close()
	})
	return r
}

func clientFor(t *testing.T, b testtls.Bundle, clientCert, clientKey string, mod func(*tls.Config)) *http.Client {
	t.Helper()
	ca, err := os.ReadFile(b.CA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	cfg := &tls.Config{RootCAs: pool}
	if clientCert != "" {
		c, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	if mod != nil {
		mod(cfg)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
}

func post(c *http.Client, url, token string) (int, error) {
	req, _ := http.NewRequest("POST", url, strings.NewReader(`{"schema":1,"host":"app01","ts":"2026-11-12T10:00:00Z","tags":[]}`))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func TestServeTLSMinimumAndListenLine(t *testing.T) {
	r := start(t, nil)
	// The listen line carries the actual address (the config said port 0) in a parseable form.
	// The server logs from its own goroutine: wait for the line.
	var found bool
	for deadline := time.Now().Add(5 * time.Second); !found && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, l := range strings.Split(r.logs.String(), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "listening" {
				found = m["addr"] == r.addr && m["tls"] == true && m["mtls"] == false
			}
		}
	}
	if !found {
		t.Fatalf("no parseable listening line with addr %s:\n%s", r.addr, r.logs.String())
	}
	if !strings.HasPrefix(r.addr, "127.0.0.1:") || strings.HasSuffix(r.addr, ":0") {
		t.Fatalf("addr %q", r.addr)
	}

	ok := clientFor(t, r.tls, "", "", nil)
	if code, err := post(ok, "https://"+r.addr+"/v1/report", r.token); err != nil || code != 202 {
		t.Fatalf("TLS 1.2+ client: %d %v", code, err)
	}
	old := clientFor(t, r.tls, "", "", func(c *tls.Config) { c.MinVersion, c.MaxVersion = tls.VersionTLS10, tls.VersionTLS11 })
	if _, err := post(old, "https://"+r.addr+"/healthz", ""); err == nil {
		t.Fatal("a TLS 1.1-only client completed a handshake")
	}
	// Plain HTTP against a TLS listener gets no application answer.
	plain := &http.Client{Timeout: 5 * time.Second}
	if resp, err := plain.Get("http://" + r.addr + "/healthz"); err == nil && resp.StatusCode < 400 {
		t.Fatalf("plaintext request succeeded against TLS: %d", resp.StatusCode)
	}
}

func TestServePlaintextOnLoopback(t *testing.T) {
	r := start(t, func(c *Config, _ testtls.Bundle) { c.TLS = TLS{} })
	resp, err := http.Get("http://" + r.addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func mtls(c *Config, b testtls.Bundle) { c.TLS.ClientCA = b.CA }

// M2 decision 11: with tls.client_ca set, a client without a valid certificate
// cannot even finish the handshake.
func TestMTLSHandshakeWithoutClientCertFails(t *testing.T) {
	r := start(t, mtls)
	noCert := clientFor(t, r.tls, "", "", nil)
	// Even a correct token is useless: the connection never reaches a handler.
	if code, err := post(noCert, "https://"+r.addr+"/v1/report", r.token); err == nil {
		t.Fatalf("request without a client certificate succeeded with %d", code)
	}
	rc, rk, err := testtls.Rogue(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rogue := clientFor(t, r.tls, rc, rk, nil)
	if code, err := post(rogue, "https://"+r.addr+"/v1/report", r.token); err == nil {
		t.Fatalf("request with a certificate from another CA succeeded with %d", code)
	}
	if n, _ := r.st.HostByName(context.Background(), "app01"); n.ReportCount != 0 {
		t.Fatalf("%d reports stored through failed handshakes", n.ReportCount)
	}
}

// ...but a valid client certificate is not enough: the token is still required.
func TestMTLSValidCertStillNeedsToken(t *testing.T) {
	r := start(t, mtls)
	c := clientFor(t, r.tls, r.tls.ClientCert, r.tls.ClientKey, nil)
	url := "https://" + r.addr + "/v1/report"
	bad, _, _ := agentauth.Generate()
	for name, tok := range map[string]string{"no token": "", "unknown token": bad} {
		if code, err := post(c, url, tok); err != nil || code != 401 {
			t.Errorf("valid cert + %s: %d %v, want 401", name, code, err)
		}
	}
	if code, err := post(c, url, r.token); err != nil || code != 202 {
		t.Fatalf("valid cert + good token: %d %v, want 202", code, err)
	}
	d, _ := r.st.HostByName(context.Background(), "app01")
	if d.ReportCount != 1 {
		t.Fatalf("%d reports, want exactly the one authenticated", d.ReportCount)
	}
}

// mTLS is off by default: the token alone is enough and no certificate is asked for.
func TestNoMTLSByDefault(t *testing.T) {
	r := start(t, nil)
	c := clientFor(t, r.tls, "", "", nil)
	if code, err := post(c, "https://"+r.addr+"/v1/report", r.token); err != nil || code != 202 {
		t.Fatalf("%d %v", code, err)
	}
}

func TestTLSConfigErrors(t *testing.T) {
	dir := t.TempDir()
	b, _ := testtls.New(dir)
	empty := filepath.Join(dir, "empty.pem")
	os.WriteFile(empty, []byte("not a pem"), 0o600)
	for name, c := range map[string]Config{
		"missing cert":      {TLS: TLS{Cert: filepath.Join(dir, "nope"), Key: b.Key}},
		"client_ca no PEM":  {TLS: TLS{Cert: b.Cert, Key: b.Key, ClientCA: empty}},
		"client_ca missing": {TLS: TLS{Cert: b.Cert, Key: b.Key, ClientCA: filepath.Join(dir, "nope")}},
	} {
		if _, err := newTLSReloader(c); err == nil {
			t.Errorf("%s: expected an error at start", name)
		}
	}
	if rl, err := newTLSReloader(Config{}); rl != nil || err != nil {
		t.Fatalf("TLS off: %v %v", rl, err)
	}
	rl, _ := newTLSReloader(Config{TLS: TLS{Cert: b.Cert, Key: b.Key, ClientCA: b.CA}})
	tc, err := rl.config().GetConfigForClient(nil) // what a handshake actually uses
	if err != nil || tc.MinVersion != tls.VersionTLS12 || tc.ClientAuth != tls.RequireAndVerifyClientCert || tc.ClientCAs == nil {
		t.Fatalf("%+v %v", tc, err)
	}
}

func TestShutdownIsClean(t *testing.T) {
	r := start(t, nil)
	r.stop()
	select {
	case err := <-r.done:
		r.done <- nil // the cleanup waits on the same channel
		if err != nil {
			t.Fatalf("clean shutdown returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no shutdown")
	}
}
