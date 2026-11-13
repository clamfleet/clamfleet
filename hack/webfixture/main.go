// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Command webfixture starts a throwaway ClamFleet server on 127.0.0.1 with
// seeded users and hosts, for the browser end-to-end tests (Playwright) and for
// poking at the console by hand. Read docs/testing.md ("Browser fixture").
//
// What it does, in order:
//  1. makes a private temp directory and throwaway TLS files (internal/testtls),
//     so the browser sees the production cookie settings (Secure, __Host-);
//  2. writes a server.yaml (loopback, direct TLS, 1 s health evaluation, a
//     secret_key_file in the temp directory), runs `clamfleet-server migrate` and
//     creates the key file with the real `clamfleet-server key generate`;
//  3. creates an admin, a viewer and a user with a one-time password straight in
//     the store (the CLI always forces a password change; the fixture wants
//     ready-to-use logins), and registers hosts with `clamfleet-server host add`.
//     It also seeds the two-factor users: `enrol` (no TOTP yet), `totp` (TOTP
//     enabled, with its base32 secret and recovery codes written to fixture.json)
//     and, with --totp-required, `forced` (no TOTP, in a console that requires it);
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
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/secrets"
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

// TOTPLogin is a seeded account with an authenticator. The secret is random per
// run and only in fixture.json (mode 0600): a browser test makes its codes from
// it (RFC 6238: HMAC-SHA1, 6 digits, 30 s, against the real clock, because the
// server under test runs on the real clock too).
type TOTPLogin struct {
	Email         string   `json:"email"`
	Password      string   `json:"password"`
	SecretBase32  string   `json:"secret_base32"`
	RecoveryCodes []string `json:"recovery_codes"` // 10, display form (abcd-efgh-ijkl-mnop)
}

// AlertsFixture describes what the Alerts pages can be driven with: a webhook
// receiver on loopback that records requests, and one seeded target. The server
// runs with alert.cooldown 0s, alert.webhook.allow_loopback true and public_url
// set to the fixture URL.
type AlertsFixture struct {
	// ReceiverURL is the receiver's base (http://127.0.0.1:PORT, plaintext on
	// purpose: the Alerts page then shows its "unencrypted" warning).
	ReceiverURL string `json:"receiver_url"`
	// RequestsURL: GET returns the recorded requests as JSON, DELETE clears them.
	RequestsURL string `json:"requests_url"`
	// StatusURL: POST ?code=500 scripts the receiver's answer, ?code=0 resets it.
	StatusURL string `json:"status_url"`
	// SeededTarget is the name of a webhook target the fixture created (through
	// the real CLI) for HookURL, signed with SigningKey. It only takes the hosts
	// tagged "alerts", so no other seeded host's transitions reach the receiver.
	SeededTarget string `json:"seeded_target"`
	HookURL      string `json:"hook_url"`
	SigningKey   string `json:"signing_key"`
	// Host is the seeded host that matches the target: post a report with
	// clamd.up=false and its token and the receiver gets one state_change to
	// CRIT within about 5 s.
	Host string `json:"host"`
}

// EventsFixture describes the seeded detections (the events page and acknowledgement).
// They are posted through the real /v1/event with the hosts' tokens; some are then
// acknowledged by the fixture admin, straight in the store (before any browser test
// starts), so the Acknowledged filter and "Acknowledged by" have content.
type EventsFixture struct {
	// OpenCount is how many are unacknowledged (the nav badge at the start).
	OpenCount int `json:"open_count"`
	// IDsByHost lists the event ids of each host, oldest first.
	IDsByHost map[string][]int64 `json:"ids_by_host"`
	// AckedIDs were acknowledged by AckedBy (the admin's email).
	AckedIDs []int64 `json:"acked_ids"`
	AckedBy  string  `json:"acked_by"`
}

// Fixture is the content of fixture.json.
type Fixture struct {
	URL        string `json:"url"`
	CACert     string `json:"ca_cert"`
	TmpDir     string `json:"tmp_dir"`
	DB         string `json:"db_path"`
	ServerLog  string `json:"server_log"`
	Admin      Login  `json:"admin"`
	Viewer     Login  `json:"viewer"`
	MustChange Login  `json:"must_change"`
	// Enrol has a password and no authenticator yet: the enrolment flow signs in as it.
	Enrol Login `json:"enrol"`
	// TOTP has an authenticator and recovery codes.
	TOTP TOTPLogin `json:"totp"`
	// TOTPRequired is true when started with --totp-required; Forced (then set) has no
	// authenticator, so signing in lands on the enrolment page.
	TOTPRequired bool            `json:"totp_required"`
	Forced       *Login          `json:"forced,omitempty"`
	Hosts        map[string]Host `json:"hosts"`
	Alerts       AlertsFixture   `json:"alerts"`
	Events       EventsFixture   `json:"events"`
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
	totpRequired := fs.Bool("totp-required", false, "set auth.local.totp_required and seed the 'forced' user")
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
	keyFile := filepath.Join(tmp, "secret.key") // inside the private temp dir, never the developer's /etc key
	// alert.cooldown 0s: no holds, so a spec sees every transition at once (the
	// cooldown is proven with an injected clock in the unit tests). Loopback is allowed because the
	// receiver below is on loopback; public_url makes the alert links point at this fixture.
	yaml := fmt.Sprintf("listen: 127.0.0.1:%d\ntls:\n  cert: %s\n  key: %s\ndb_path: %s\nsecret_key_file: %s\nhealth:\n  eval_interval: %s\n"+
		"public_url: https://127.0.0.1:%d\nalert:\n  cooldown: 0s\n  webhook:\n    allow_loopback: true\n",
		*port, tlsb.Cert, tlsb.Key, db, keyFile, *evalEvery, *port)
	if *totpRequired {
		yaml += "auth:\n  local:\n    totp_required: true\n"
	}
	if err := os.WriteFile(cfg, []byte(yaml), 0o600); err != nil {
		return err
	}
	// A clean environment: the developer's own CLAMFLEET_SERVER_* must not leak in.
	env := []string{"PATH=" + os.Getenv("PATH"), "CLAMFLEET_SERVER_CONFIG=" + cfg}
	cliIn := func(stdin string, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = env
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		var so, se bytes.Buffer
		cmd.Stdout, cmd.Stderr = &so, &se
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("clamfleet-server %s: %w\n%s", strings.Join(args, " "), err, se.String())
		}
		return strings.TrimSpace(so.String()), nil
	}
	cli := func(args ...string) (string, error) { return cliIn("", args...) }
	rcv, err := startReceiver()
	if err != nil {
		return err
	}
	defer rcv.Close()
	if _, err := cli("migrate"); err != nil {
		return err
	}
	// The real command creates the key file, so the fixture exercises the install path too.
	if _, err := cli("key", "generate"); err != nil {
		return err
	}

	fx := &Fixture{
		URL: fmt.Sprintf("https://127.0.0.1:%d", *port), CACert: tlsb.CA, TmpDir: tmp, DB: db,
		ServerLog: filepath.Join(tmp, "server.log"), Hosts: map[string]Host{},
	}
	fx.TOTPRequired = *totpRequired
	if err := seedUsers(ctx, db, keyFile, fx); err != nil {
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

	// Detections next, before the alert target exists, and the dispatcher is given
	// time to plan them (with no target they match none), so no seeded detection is
	// ever delivered to the seeded target later.
	if err := seedEvents(ctx, client, fx, now); err != nil {
		return fmt.Errorf("seed events: %w", err)
	}

	// The seeded alert target, created after the reports so it never sees the
	// seeding transitions (and it takes only hosts tagged "alerts" anyway). The URL goes in through
	// stdin and the printed signing key is the only thing on stdout: the documented CLI flow.
	hook := rcv.URL() + "/hook/seeded"
	key, err := cliIn(hook+"\n", "alert", "add-webhook", "seeded-hook", "--url-stdin", "--tags", "alerts")
	if err != nil {
		return err
	}
	fx.Alerts = AlertsFixture{ReceiverURL: rcv.URL(), RequestsURL: rcv.URL() + "/__requests", StatusURL: rcv.URL() + "/__status",
		SeededTarget: "seeded-hook", HookURL: hook, SigningKey: key, Host: "alerts01"}

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
func seedUsers(ctx context.Context, db, keyFile string, fx *Fixture) error {
	st, err := sqlite.Open(ctx, db)
	if err != nil {
		return err
	}
	defer st.Close()
	ring, err := secrets.LoadFile(keyFile)
	if err != nil {
		return err
	}
	h := webauth.NewHasher()
	audit := store.Audit{Kind: store.ActorCLI, Actor: "webfixture"}
	mkUser := func(email, role string, mustChange bool) (store.User, string, error) {
		pw, err := webauth.GeneratePassword()
		if err != nil {
			return store.User{}, "", err
		}
		hash, err := h.Hash(ctx, pw)
		if err != nil {
			return store.User{}, "", err
		}
		u, err := st.CreateUser(ctx, store.NewUser{Email: email, Role: role, PasswordHash: hash, MustChange: mustChange}, time.Now(), audit)
		return u, pw, err
	}
	mk := func(email, role string, mustChange bool) (Login, error) {
		_, pw, err := mkUser(email, role, mustChange)
		return Login{email, pw}, err
	}
	if fx.Admin, err = mk("admin@fixture.example", store.RoleAdmin, false); err != nil {
		return err
	}
	if fx.Viewer, err = mk("viewer@fixture.example", store.RoleViewer, false); err != nil {
		return err
	}
	if fx.MustChange, err = mk("newbie@fixture.example", store.RoleViewer, true); err != nil {
		return err
	}
	if fx.Enrol, err = mk("enrol@fixture.example", store.RoleViewer, false); err != nil {
		return err
	}
	if fx.TOTPRequired {
		forced, err := mk("forced@fixture.example", store.RoleViewer, false)
		if err != nil {
			return err
		}
		fx.Forced = &forced
	}

	// The user with an authenticator: the same calls the console's enrolment makes,
	// so what the fixture seeds is what a real enrolment leaves behind.
	u, pw, err := mkUser("totp@fixture.example", store.RoleViewer, false)
	if err != nil {
		return err
	}
	secret, err := webauth.GenerateTOTPSecret()
	if err != nil {
		return err
	}
	sealed, err := ring.Seal(secrets.PurposeTOTP, secret, uint64(u.ID))
	if err != nil {
		return err
	}
	codes, err := webauth.GenerateRecoveryCodes(webauth.RecoveryCodeCount)
	if err != nil {
		return err
	}
	var hashes [][]byte
	for _, c := range codes {
		n, _ := webauth.NormalizeRecoveryCode(c)
		hashes = append(hashes, webauth.HashRecoveryCode(n))
	}
	now := time.Now()
	// The last accepted step is 10 steps back, so the code of the current step is
	// still fresh for the first sign-in of a test.
	err = st.EnableTOTP(ctx, store.EnableTOTP{
		UserID: u.ID, ExpectedVersion: u.AuthVersion, Sealed: sealed, Step: webauth.TOTPStep(now) - 10, RecoveryHashes: hashes,
	}, now, audit)
	if err != nil {
		return err
	}
	fx.TOTP = TOTPLogin{Email: u.Email, Password: pw, SecretBase32: webauth.EncodeTOTPSecret(secret), RecoveryCodes: codes}
	return nil
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
		{"alerts01", "OK", "healthy, tag \"alerts\": the only host the seeded alert target takes (Alerts pages)", func(n string, now time.Time) proto.Report { return baseReport(n, now, "alerts") }},
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

// Characters the Go source spells with escapes the reader can see.
const (
	rloChar = "\u202e" // RIGHT-TO-LEFT OVERRIDE
	lsChar  = "\u2028" // LINE SEPARATOR
	bs1     = "\\"     // one backslash
	bs2     = "\\\\"   // two: how the agent encodes one backslash in a file name
)

// seedEvent is one detection to post.
type seedEvent struct {
	host      string
	n         int // the agent event id is n in hex; two events with the same key but different n merge (x2)
	ago       time.Duration
	path, sig string
	ackedBy   bool
}

// eventSeeds are the detections of the fixture. Paths are in the AGENT'S ENCODING
// (docs/api.md): a backslash is doubled, a non-UTF-8 byte is \xNN.
func eventSeeds() []seedEvent {
	const eicar = "Win.Test.EICAR_HDB-1"
	return []seedEvent{
		{host: "crit01", n: 1, ago: 2 * time.Minute, path: "/srv/eicar/a.com", sig: eicar},
		{host: "crit01", n: 2, ago: time.Minute, path: "/srv/eicar/b.com", sig: eicar},
		// Hostile names: markup, a real right-to-left override, the text of an escape, a
		// real U+2028, a real backslash in a file name, and a byte that is not UTF-8.
		{host: "xss01", n: 3, ago: 4 * time.Minute, path: "/srv/<img src=x onerror=alert(1)>/" + rloChar + "txt.exe", sig: "<b>Win.Test.XSS</b>"},
		{host: "xss01", n: 4, ago: 3 * time.Minute, path: "/srv/literal" + bs2 + "u{202E}name", sig: "Win.Test.Literal"},
		{host: "xss01", n: 5, ago: 150 * time.Second, path: "/srv/line" + lsChar + "break", sig: "Win.Test.LineSep"},
		{host: "xss01", n: 6, ago: 140 * time.Second, path: "/srv/back" + bs2 + "slash.txt", sig: "Win.Test.Backslash"},
		{host: "xss01", n: 7, ago: 130 * time.Second, path: "/srv/raw" + bs1 + "xffbyte", sig: "Win.Test.RawByte"},
		// One detection reported twice with two ids and the same key: shown once, x2.
		{host: "warn01", n: 8, ago: 5 * time.Minute, path: "/srv/dup/file.bin", sig: "Eicar-Test"},
		{host: "warn01", n: 9, ago: 5 * time.Minute, path: "/srv/dup/file.bin", sig: "Eicar-Test"},
		{host: "alerts01", n: 10, ago: 30 * time.Second, path: "/srv/alerts/eicar.com", sig: eicar},
		// History: detected 3 h before it arrived (it waited in an agent's spool), then acknowledged.
		{host: "ok01", n: 11, ago: 3 * time.Hour, path: "/srv/old/one.bin", sig: eicar, ackedBy: true},
		{host: "ok01", n: 12, ago: 3*time.Hour + time.Minute, path: "/srv/old/two.bin", sig: eicar, ackedBy: true},
	}
}

// seedEvents posts the detections, waits until the dispatcher has planned them,
// acknowledges the ones marked, and records the ids in fx.Events.
func seedEvents(ctx context.Context, c *http.Client, fx *Fixture, now time.Time) error {
	seeds := eventSeeds()
	for _, e := range seeds {
		id := fmt.Sprintf("%032x", e.n)
		ev := proto.Event{Schema: proto.SchemaVersion, ID: &id, Host: e.host, TS: proto.UTC(now.Add(-e.ago)), Path: e.path, Signature: e.sig, Source: "clamd"}
		if err := postJSON(ctx, c, fx.URL+"/v1/event", fx.Hosts[e.host].Token, ev); err != nil {
			return fmt.Errorf("%s: %w", e.host, err)
		}
	}
	st, err := sqlite.Open(ctx, fx.DB)
	if err != nil {
		return err
	}
	defer st.Close()
	// Flagged events are planned by the dispatcher (it is woken by each new event);
	// with no alert target they are unrouted and the flags clear.
	deadline := time.Now().Add(20 * time.Second)
	for {
		work, err := st.HasAlertWork(ctx, time.Now(), 0)
		if err != nil {
			return err
		}
		if !work {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("the dispatcher did not plan the seeded detections within 20 s")
		}
		time.Sleep(100 * time.Millisecond)
	}
	rows, err := st.ListEvents(ctx, store.EventFilter{Ack: store.AckAll, Limit: store.MaxEventPage})
	if err != nil {
		return err
	}
	byPath := map[string]store.EventRow{}
	for _, r := range rows {
		byPath[r.Host+"\x00"+r.Path] = r
	}
	fx.Events = EventsFixture{IDsByHost: map[string][]int64{}, AckedBy: fx.Admin.Email}
	audit := store.Audit{Kind: store.ActorUser, Actor: fx.Admin.Email}
	seen := map[int64]bool{}
	for _, e := range seeds {
		r, ok := byPath[e.host+"\x00"+e.path]
		if !ok {
			return fmt.Errorf("seeded event %d of %s was not stored", e.n, e.host)
		}
		if seen[r.ID] {
			continue // the merged duplicate
		}
		seen[r.ID] = true
		fx.Events.IDsByHost[e.host] = append(fx.Events.IDsByHost[e.host], r.ID)
		if e.ackedBy {
			if _, _, err := st.AckEvent(ctx, r.ID, time.Now(), audit); err != nil {
				return err
			}
			fx.Events.AckedIDs = append(fx.Events.AckedIDs, r.ID)
		}
	}
	for host := range fx.Events.IDsByHost {
		ids := fx.Events.IDsByHost[host]
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	}
	open, err := st.CountOpenEvents(ctx)
	if err != nil {
		return err
	}
	fx.Events.OpenCount = int(open)
	return nil
}

// postJSON posts v with a bearer token and expects 202.
func postJSON(ctx context.Context, c *http.Client, url, token string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
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
