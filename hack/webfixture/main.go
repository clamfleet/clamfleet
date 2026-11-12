// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Command webfixture starts a throwaway ClamFleet server on 127.0.0.1 with
// seeded users and hosts, for the browser end-to-end tests (Playwright) and for
// poking at the console by hand. Read docs/testing.md ("Browser fixture").
//
// What it does, in order:
//  1. makes a private temp directory and throwaway TLS files (internal/testtls),
//     so the browser sees the production cookie settings (Secure, __Host-);
//  2. writes a server.yaml (loopback, direct TLS, 1 s health evaluation) and
//     runs `clamfleet-server migrate`;
//  3. creates an admin, a viewer and a user with a one-time password straight in
//     the store (the CLI always forces a password change; the fixture wants
//     ready-to-use logins), and registers hosts with `clamfleet-server host add`;
//  4. starts `clamfleet-server serve` as a child process;
//  5. posts one report per host through the real HTTP API, so every host is in a
//     known state;
//  6. writes <tmp>/fixture.json (URL, CA, logins, host tokens), prints one line
//     "READY <url>" on stdout, and waits for SIGINT or SIGTERM;
//  7. stops the server and deletes the temp directory (unless --keep).
//
// Nothing listens beyond 127.0.0.1 and nothing outlives the process. The
// passwords and tokens are random per run and only in fixture.json (mode 0600).
//
// This is a test tool, not production code: it reads the real clock to stamp
// the reports it sends, which is what a real agent does.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
	"github.com/clamfleet/clamfleet/internal/testtls"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

// Login is one seeded account.
type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Host is one seeded host.
type Host struct {
	Token string `json:"token"`
	// State is what the host shows right after start-up. stale01 turns STALE
	// about 35 s later (its report interval is 10 s, the shortest the server accepts).
	State string `json:"initial_state"`
	// Note says how the host got into that state.
	Note string `json:"note"`
}

// Fixture is the content of fixture.json.
type Fixture struct {
	URL        string          `json:"url"`
	CACert     string          `json:"ca_cert"`
	TmpDir     string          `json:"tmp_dir"`
	DB         string          `json:"db_path"`
	ServerLog  string          `json:"server_log"`
	Admin      Login           `json:"admin"`
	Viewer     Login           `json:"viewer"`
	MustChange Login           `json:"must_change"`
	Hosts      map[string]Host `json:"hosts"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "webfixture:", err)
		stop()
		os.Exit(1)
	}
}

// run seeds and serves until ctx ends. stdout gets the READY line only.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("webfixture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	serverBin := fs.String("server-bin", "bin/clamfleet-server", "the clamfleet-server binary (make build)")
	port := fs.Int("port", 0, "TCP port on 127.0.0.1 (0 picks a free one)")
	jsonOut := fs.String("json-out", "", "also copy fixture.json to this path (default: only <tmp>/fixture.json)")
	keep := fs.Bool("keep", false, "keep the temp directory on exit")
	evalEvery := fs.Duration("eval-interval", time.Second, "health.eval_interval of the server")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bin, err := filepath.Abs(*serverBin)
	if err != nil {
		return err
	}
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("server binary %s not found: run `make build` first", bin)
	}

	tmp, err := os.MkdirTemp("", "clamfleet-web-")
	if err != nil {
		return err
	}
	if !*keep {
		defer os.RemoveAll(tmp)
	}
	if err := os.Chmod(tmp, 0o700); err != nil {
		return err
	}
	tlsb, err := testtls.New(tmp)
	if err != nil {
		return err
	}
	if *port == 0 {
		// Bind and release: a small race, acceptable for a test tool on loopback.
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		*port = l.Addr().(*net.TCPAddr).Port
		l.Close()
	}
	cfg := filepath.Join(tmp, "server.yaml")
	db := filepath.Join(tmp, "clamfleet.db")
	yaml := fmt.Sprintf("listen: 127.0.0.1:%d\ntls:\n  cert: %s\n  key: %s\ndb_path: %s\nhealth:\n  eval_interval: %s\n",
		*port, tlsb.Cert, tlsb.Key, db, *evalEvery)
	if err := os.WriteFile(cfg, []byte(yaml), 0o600); err != nil {
		return err
	}
	// A clean environment: the developer's own CLAMFLEET_SERVER_* must not leak in.
	env := []string{"PATH=" + os.Getenv("PATH"), "CLAMFLEET_SERVER_CONFIG=" + cfg}
	cli := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = env
		var so, se bytes.Buffer
		cmd.Stdout, cmd.Stderr = &so, &se
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("clamfleet-server %s: %w\n%s", strings.Join(args, " "), err, se.String())
		}
		return strings.TrimSpace(so.String()), nil
	}
	if _, err := cli("migrate"); err != nil {
		return err
	}

	fx := &Fixture{
		URL: fmt.Sprintf("https://127.0.0.1:%d", *port), CACert: tlsb.CA, TmpDir: tmp, DB: db,
		ServerLog: filepath.Join(tmp, "server.log"), Hosts: map[string]Host{},
	}
	if err := seedUsers(ctx, db, fx); err != nil {
		return err
	}
	seeds := hostSeeds()
	for _, h := range seeds {
		tok, err := cli("host", "add", h.name)
		if err != nil {
			return err
		}
		fx.Hosts[h.name] = Host{Token: tok, State: h.state, Note: h.note}
	}

	logf, err := os.OpenFile(fx.ServerLog, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	srv := exec.Command(bin, "serve", "--config", cfg)
	srv.Env = env
	srv.Stdout, srv.Stderr = logf, logf
	if err := srv.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- srv.Wait() }()
	defer func() {
		_ = srv.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			_ = srv.Process.Kill()
			<-exited
		}
	}()

	client, err := httpClient(tlsb.CA)
	if err != nil {
		return err
	}
	if err := waitHealthy(ctx, client, fx.URL, exited); err != nil {
		return fmt.Errorf("server did not become healthy (see %s): %w", fx.ServerLog, err)
	}
	now := time.Now().UTC()
	for _, h := range seeds {
		if h.report == nil {
			continue
		}
		if err := postReport(ctx, client, fx.URL, fx.Hosts[h.name].Token, h.report(h.name, now)); err != nil {
			return fmt.Errorf("seed report of %s: %w", h.name, err)
		}
	}

	raw, _ := json.MarshalIndent(fx, "", "  ")
	for _, p := range []string{filepath.Join(tmp, "fixture.json"), *jsonOut} {
		if p == "" {
			continue
		}
		if err := os.WriteFile(p, append(raw, '\n'), 0o600); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "READY %s\n", fx.URL)

	select {
	case <-ctx.Done():
		return nil
	case err := <-exited:
		exited <- err // the deferred stop reads it again
		return fmt.Errorf("server exited: %v (see %s)", err, fx.ServerLog)
	}
}

// seedUsers creates the logins directly in the store: the CLI forces a
// password change at first login, which is right for operators and wrong for a
// browser test that wants to sign in and look at the fleet.
func seedUsers(ctx context.Context, db string, fx *Fixture) error {
	st, err := sqlite.Open(ctx, db)
	if err != nil {
		return err
	}
	defer st.Close()
	h := webauth.NewHasher()
	mk := func(email, role string, mustChange bool) (Login, error) {
		pw, err := webauth.GeneratePassword()
		if err != nil {
			return Login{}, err
		}
		hash, err := h.Hash(ctx, pw)
		if err != nil {
			return Login{}, err
		}
		_, err = st.CreateUser(ctx, store.NewUser{Email: email, Role: role, PasswordHash: hash, MustChange: mustChange},
			time.Now(), store.Audit{Kind: store.ActorCLI, Actor: "webfixture"})
		return Login{email, pw}, err
	}
	if fx.Admin, err = mk("admin@fixture.example", store.RoleAdmin, false); err != nil {
		return err
	}
	if fx.Viewer, err = mk("viewer@fixture.example", store.RoleViewer, false); err != nil {
		return err
	}
	fx.MustChange, err = mk("newbie@fixture.example", store.RoleViewer, true)
	return err
}

type hostSeed struct {
	name, state, note string
	report            func(name string, now time.Time) proto.Report // nil: never reports (pending)
}

// baseReport is a healthy host: fresh signatures, every service active.
func baseReport(name string, now time.Time, tags ...string) proto.Report {
	ver, built := "1.4.3", now.Add(-time.Hour)
	interval := 300
	last := now.Add(-5 * time.Minute)
	src := proto.SourceJournal
	return proto.Report{
		Schema: proto.SchemaVersion, Host: name, AgentVersion: "0.1.0", Tags: tags, IntervalSeconds: &interval, TS: now,
		OS:    proto.OS{ID: "debian", Version: "13"},
		Clamd: proto.Clamd{Up: true, Version: &ver},
		Sigs: proto.Sigs{
			Daily:    &proto.SigDB{Version: 28181, Built: built, Sigs: 355854},
			Main:     &proto.SigDB{Version: 63, Built: built.Add(-24 * 30 * time.Hour), Sigs: 3287027},
			Bytecode: &proto.SigDB{Version: 339, Built: built.Add(-24 * 30 * time.Hour), Sigs: 80},
		},
		Freshclam: proto.Freshclam{LastOK: &last, Source: &src},
		Services:  proto.Services{Clamd: "active", Freshclam: "active", Clamonacc: "inactive"},
	}
}

func hostSeeds() []hostSeed {
	return []hostSeed{
		{"ok01", "OK", "healthy", func(n string, now time.Time) proto.Report { return baseReport(n, now, "prod", "web") }},
		{"warn01", "WARN", "freshclam service inactive (rule freshclam_inactive)", func(n string, now time.Time) proto.Report {
			r := baseReport(n, now, "prod", "db")
			r.Services.Freshclam = "inactive"
			return r
		}},
		{"crit01", "CRIT", "clamd down with error \"ping: timeout\" (rule clamd_down)", func(n string, now time.Time) proto.Report {
			r := baseReport(n, now, "staging")
			msg := "ping: timeout"
			r.Clamd = proto.Clamd{Up: false, Error: &msg}
			return r
		}},
		{"stale01", "OK", "reports once with a 10 s interval, then never again: STALE after about 35 s", func(n string, now time.Time) proto.Report {
			r := baseReport(n, now, "lab")
			ten := 10
			r.IntervalSeconds = &ten
			return r
		}},
		{"pending01", "pending", "registered, never reported (becomes STALE after 15 min)", nil},
		{"xss01", "WARN", "hostile agent text in tags, host name and freshclam error: must render inert", func(n string, now time.Time) proto.Report {
			r := baseReport(n, now, "<b>bold</b>", `"><img src=x onerror=alert(1)>`)
			r.Host = `"><img src=x onerror=alert(2)>`
			at, ok, msg := now.Add(-time.Minute), now.Add(-time.Hour), `<script>alert(3)</script>`
			r.Freshclam.LastError, r.Freshclam.LastOK, r.Freshclam.LastErrorMsg = &at, &ok, &msg
			return r
		}},
	}
}

func httpClient(caPath string) (*http.Client, error) {
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("test CA is not valid PEM")
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}, nil
}

func waitHealthy(ctx context.Context, c *http.Client, base string, exited <-chan error) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
		if resp, err := c.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case err := <-exited:
			return fmt.Errorf("server exited: %v", err)
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("timeout")
		}
	}
}

func postReport(ctx context.Context, c *http.Client, base, token string, r proto.Report) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/report", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
