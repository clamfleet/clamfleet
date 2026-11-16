// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// The detection path with both real binaries and nothing injected between them
// (milestone 5, section 6.4): `clamfleet-agent event` writes the spool, the
// agent service sends it, the server stores it, wakes the dispatcher, and a
// webhook receiver gets the alert. No clamd is involved: the event command is
// run with exactly the environment clamd gives VirusEvent.
//
// Every limit here is the product's own (the 30 s acceptance, the 10 s event-lane
// timeout), measured with the real clock, so the margins are generous but the
// failures they catch are not: a stuck lane, a missing wake, a dead receiver that
// starves a CRIT.
package main

import (
	"bufio"
	ctls "crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/alert"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/testtls"
)

// serveProc is a `serve` child process that a test can stop and start again on
// the same port and database.
type serveProc struct {
	t      *testing.T
	cmd    *exec.Cmd
	stderr *syncBuf
	env    []string
	done   chan struct{}
	addr   string
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// startServeAt runs `serve` listening on addr (a fixed port, so it can be restarted).
func startServeAt(t *testing.T, tls testtls.Bundle, db, addr string, extra ...string) *serveProc {
	t.Helper()
	env := append(cliEnv(db, "CLAMFLEET_SERVER_TLS_CERT="+tls.Cert, "CLAMFLEET_SERVER_TLS_KEY="+tls.Key,
		"CLAMFLEET_SERVER_LISTEN="+addr, "CLAMFLEET_SERVER_ALERT_WEBHOOK_ALLOW_LOOPBACK=true"), extra...)
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
	p := &serveProc{t: t, cmd: cmd, stderr: stderr, env: env, done: make(chan struct{}), addr: addr}
	listening := make(chan struct{}, 1)
	go func() {
		sc := bufio.NewScanner(pipe)
		for sc.Scan() {
			line := sc.Text()
			stderr.Write([]byte(line + "\n"))
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == "listening" {
				select {
				case listening <- struct{}{}:
				default:
				}
			}
		}
		cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(p.Stop)
	select {
	case <-listening:
	case <-time.After(20 * time.Second):
		t.Fatalf("server did not start:\n%s", stderr.String())
	}
	return p
}

// Stop ends the server with SIGTERM and waits (idempotent).
func (p *serveProc) Stop() {
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(15 * time.Second):
		p.cmd.Process.Kill()
		<-p.done
	}
}

// receiver is a webhook endpoint on loopback that records every request with
// the time it arrived. With hang set it holds each request until released (a
// dead receiver: the server's own 10 s deadline ends the attempt).
type receiver struct {
	srv  *http.Server
	url  string
	mu   sync.Mutex
	hits []recvHit
	hang chan struct{} // nil: answer at once
	live int
	peak int
}

type recvHit struct {
	at   time.Time
	body string
}

func newReceiver(t *testing.T, hang bool) *receiver {
	t.Helper()
	r := &receiver{}
	if hang {
		r.hang = make(chan struct{})
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.url = "http://" + ln.Addr().String() + "/hook"
	r.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.hits = append(r.hits, recvHit{time.Now(), string(b)})
		r.live++
		r.peak = max(r.peak, r.live)
		r.mu.Unlock()
		defer func() { r.mu.Lock(); r.live--; r.mu.Unlock() }()
		if r.hang != nil {
			select {
			case <-r.hang:
			case <-req.Context().Done():
				return
			}
		}
		w.WriteHeader(204)
	})}
	go r.srv.Serve(ln)
	t.Cleanup(func() {
		if r.hang != nil {
			close(r.hang)
		}
		r.srv.Close()
	})
	return r
}

func (r *receiver) detections() []alert.DetectionPayload {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []alert.DetectionPayload
	for _, h := range r.hits {
		var p alert.DetectionPayload
		if json.Unmarshal([]byte(h.body), &p) == nil && p.Kind == alert.KindDetection {
			out = append(out, p)
		}
	}
	return out
}

// waitFor returns the detection for path and when it reached the receiver, or fails after d.
func (r *receiver) waitFor(t *testing.T, path string, d time.Duration) (alert.DetectionPayload, time.Time) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		r.mu.Lock()
		for _, h := range r.hits {
			var p alert.DetectionPayload
			if json.Unmarshal([]byte(h.body), &p) == nil && p.Kind == alert.KindDetection && p.Path == path {
				r.mu.Unlock()
				return p, h.at
			}
		}
		r.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("no detection for %s within %v (receiver holds %d requests)", path, d, len(r.detections()))
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// agentService is `clamfleet-agent run` as a background process.
type agentService struct {
	cmd    *exec.Cmd
	stderr *syncBuf
	done   chan struct{}
}

func (a *agentSetup) spoolDir() string { return filepath.Join(a.dir, "spool") }

// startRun runs the agent service against the setup's config.
func (a *agentSetup) startRun(t *testing.T) *agentService {
	t.Helper()
	cmd := exec.Command(agentBin, "run", "--config", a.cfgPath)
	cmd.Env = a.baseEnv
	s := &agentService{cmd: cmd, stderr: &syncBuf{}, done: make(chan struct{})}
	cmd.Stderr = s.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { cmd.Wait(); close(s.done) }()
	t.Cleanup(s.Stop)
	// The service creates the spool layout at start: the event command (which
	// never creates anything) must not run before it has.
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(filepath.Join(a.spoolDir(), "usage")); err == nil {
			break
		}
		select {
		case <-s.done:
			t.Fatalf("the agent service exited at start:\n%s", s.stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent service did not create the spool:\n%s", s.stderr.String())
		}
	}
	return s
}

func (s *agentService) Stop() {
	select {
	case <-s.done:
		return
	default:
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.done:
	case <-time.After(15 * time.Second):
		s.cmd.Process.Kill()
		<-s.done
	}
}

// event runs `clamfleet-agent event` with exactly what clamd gives VirusEvent:
// PATH and the two variables.
func (a *agentSetup) event(t *testing.T, filename, signature string) (res result, took time.Duration) {
	t.Helper()
	cmd := exec.Command(agentBin, "event", "--config", a.cfgPath)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "CLAM_VIRUSEVENT_FILENAME=" + filename, "CLAM_VIRUSEVENT_VIRUSNAME=" + signature}
	var so, se syncBuf
	cmd.Stdout, cmd.Stderr = &so, &se
	start := time.Now()
	err := cmd.Run()
	took = time.Since(start)
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{so.String(), se.String(), code}, took
}

func (a *agentSetup) spoolCount(t *testing.T, sub string) int {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(a.spoolDir(), sub))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), ".tmp-") {
			n++
		}
	}
	return n
}

func (a *agentSetup) waitSpoolEmpty(t *testing.T, sub string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for a.spoolCount(t, sub) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("spool/%s still holds %d items after %v", sub, a.spoolCount(t, sub), d)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// detectionRig is a server with a burst-0 webhook target, one host and an agent
// with a spool, ready to run.
type detectionRig struct {
	t     *testing.T
	tls   testtls.Bundle
	db    string
	addr  string
	srv   *serveProc
	rcv   *receiver
	agent *agentSetup
	key   string
}

func newDetectionRig(t *testing.T, serverExtra []string, agentExtra string) *detectionRig {
	t.Helper()
	tls, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, _ := newDB(t)
	keyPath := writeKeyFile(t, 0o600, newKey(t))
	rcv := newReceiver(t, false)
	// burst 0: every detection alone, so a test measures transport, not summaries.
	seedWebhookTarget(t, db, "ops", rcv.url, loadRing(t, keyPath), func(n *store.NewAlertTarget) { n.DetectionBurst = 0; n.SendStateChanges = false })
	addr := freeAddr(t)
	extra := append([]string{"CLAMFLEET_SERVER_SECRET_KEY_FILE=" + keyPath, "CLAMFLEET_SERVER_PUBLIC_URL=https://cf.example"}, serverExtra...)
	srv := startServeAt(t, tls, db, addr, extra...)
	reg := runServer(t, srv.env, "host", "add", "web01")
	if reg.code != 0 {
		t.Fatal(reg)
	}
	r := &detectionRig{t: t, tls: tls, db: db, addr: addr, srv: srv, rcv: rcv, key: keyPath}
	ag := newAgent(t, addr, tls.CA, "")
	spool := ag.spoolDir()
	if err := os.Mkdir(spool, 0o750); err != nil {
		t.Fatal(err)
	}
	// Rewrite the config with the spool (and any extra keys): newAgent wrote it without.
	raw, _ := os.ReadFile(ag.cfgPath)
	if err := os.WriteFile(ag.cfgPath, append(raw, []byte("spool: {dir: "+spool+", max_mb: 50}\n"+agentExtra)...), 0o600); err != nil {
		t.Fatal(err)
	}
	ag.token(strings.TrimSpace(reg.stdout))
	r.agent = ag
	return r
}

// The alert arrives within 10 s of the event command, and the spool is empty
// afterwards. With the dispatcher not woken it could take up to the 5 s tick on
// top of the agent's 1 s poll; the real path is well inside the limit.
func TestDetectionThroughSpool(t *testing.T) {
	rig := newDetectionRig(t, nil, "")
	rig.agent.startRun(t)
	res, took := rig.agent.event(t, "/srv/e2e/eicar.com", "Win.Test.EICAR_HDB-1")
	if res.code != 0 || res.stderr != "" {
		t.Fatalf("event: %+v", res)
	}
	if took > 2*time.Second {
		t.Fatalf("the event command took %v: clamd waits for it", took)
	}
	start := time.Now()
	p, _ := rig.rcv.waitFor(t, "/srv/e2e/eicar.com", 10*time.Second)
	t.Logf("event command %v; alert %v after it", took, time.Since(start))
	if p.Host != "web01" || p.Signature != "Win.Test.EICAR_HDB-1" || p.Source != "clamd" {
		t.Fatalf("%+v", p)
	}
	rig.agent.waitSpoolEmpty(t, "events", 5*time.Second)
}

// The server is down when the detection happens: it waits in the spool and is
// delivered once after the restart, with ts before the restart and received_at after it.
func TestEventSurvivesServerDowntime(t *testing.T) {
	rig := newDetectionRig(t, nil, "")
	rig.agent.startRun(t)
	// A first detection proves the path, then the server goes away.
	rig.agent.event(t, "/srv/first", "Sig")
	rig.rcv.waitFor(t, "/srv/first", 15*time.Second)
	rig.srv.Stop()

	if res, _ := rig.agent.event(t, "/srv/while/down", "Win.Test.EICAR_HDB-1"); res.code != 0 {
		t.Fatalf("event with the server down: %+v", res)
	}
	time.Sleep(3 * time.Second)
	if n := rig.agent.spoolCount(t, "events"); n != 1 {
		t.Fatalf("%d items in the spool while the server is down, want 1", n)
	}
	restart := time.Now()
	srv := startServeAt(t, rig.tls, rig.db, rig.addr, "CLAMFLEET_SERVER_SECRET_KEY_FILE="+rig.key, "CLAMFLEET_SERVER_PUBLIC_URL=https://cf.example")
	_ = srv
	p, _ := rig.rcv.waitFor(t, "/srv/while/down", 30*time.Second)
	ts, _ := time.Parse(time.RFC3339, p.TS)
	recv, _ := time.Parse(time.RFC3339, p.ReceivedAt)
	if !ts.Before(restart) || recv.Before(restart.Truncate(time.Second)) {
		t.Fatalf("ts %v received_at %v restart %v: the detection time is before the restart, the arrival after it", ts, recv, restart)
	}
	rig.agent.waitSpoolEmpty(t, "events", 5*time.Second)
	time.Sleep(2 * time.Second)
	n := 0
	for _, d := range rig.rcv.detections() {
		if d.Path == "/srv/while/down" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d alerts for the detection, want exactly 1", n)
	}
}

// proxy is a TLS front for the real server that holds every /v1/report request
// for hold: a report ingest that is slow for any reason.
func startHoldingProxy(t *testing.T, tls testtls.Bundle, backend string, hold time.Duration) string {
	t.Helper()
	ca, _ := os.ReadFile(tls.CA)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	target, _ := url.Parse("https://" + backend)
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = &http.Transport{TLSClientConfig: &ctls.Config{RootCAs: pool}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/report" {
			select {
			case <-time.After(hold):
			case <-r.Context().Done():
				return
			}
		}
		rp.ServeHTTP(w, r)
	})
	cert, err := ctls.LoadX509KeyPair(tls.Cert, tls.Key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ctls.Listen("tcp", "127.0.0.1:0", &ctls.Config{Certificates: []ctls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// A report request is held for 20 s by a slow proxy; a detection during that time
// is still delivered inside 10 s, because the event lane has its own request.
// With one lane the event would wait behind the stuck report.
func TestFreshEventDuringSlowIngest(t *testing.T) {
	rig := newDetectionRig(t, nil, "")
	proxy := startHoldingProxy(t, rig.tls, rig.addr, 20*time.Second)
	raw, _ := os.ReadFile(rig.agent.cfgPath)
	cfg := strings.Replace(string(raw), "server: https://"+rig.addr, "server: https://"+proxy, 1)
	if cfg == string(raw) {
		t.Fatal("server line not found in the agent config")
	}
	if err := os.WriteFile(rig.agent.cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.agent.startRun(t)
	time.Sleep(1500 * time.Millisecond) // the first report is now stuck in the proxy
	if res, _ := rig.agent.event(t, "/srv/during/slow", "Sig"); res.code != 0 {
		t.Fatalf("%+v", res)
	}
	start := time.Now()
	rig.rcv.waitFor(t, "/srv/during/slow", 10*time.Second)
	t.Logf("alert %v after the event, with a report held for 20 s", time.Since(start))
}

// 300 detections wait in the spool during an outage. After the restart a fresh
// one overtakes them (M5 decision 14): its alert arrives within 30 s, and all 300
// arrive eventually.
func TestFreshEventDuringBacklog(t *testing.T) {
	rig := newDetectionRig(t, nil, "")
	rig.srv.Stop()
	rig.agent.startRun(t)
	for i := 0; i < 300; i++ {
		if res, _ := rig.agent.event(t, fmt.Sprintf("/srv/backlog/%03d", i), "Win.Test.EICAR_HDB-1"); res.code != 0 {
			t.Fatalf("event %d: %+v", i, res)
		}
	}
	if n := rig.agent.spoolCount(t, "events"); n != 300 {
		t.Fatalf("%d items spooled, want 300", n)
	}
	// "Fresh" means younger than a minute, so the backlog must be older: the spooled
	// items are renamed as if they had been written an hour ago (the name carries the
	// spool time; the id inside must still match it, and does).
	evDir := filepath.Join(rig.agent.spoolDir(), "events")
	ents, err := os.ReadDir(evDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		var nanos int64
		var id string
		if _, err := fmt.Sscanf(e.Name(), "%020d-%32s.json", &nanos, &id); err != nil {
			t.Fatalf("unexpected spool name %q: %v", e.Name(), err)
		}
		old := fmt.Sprintf("%020d-%s.json", nanos-int64(time.Hour), strings.TrimSuffix(id, ".json"))
		if err := os.Rename(filepath.Join(evDir, e.Name()), filepath.Join(evDir, old)); err != nil {
			t.Fatal(err)
		}
	}
	startServeAt(t, rig.tls, rig.db, rig.addr, "CLAMFLEET_SERVER_SECRET_KEY_FILE="+rig.key, "CLAMFLEET_SERVER_PUBLIC_URL=https://cf.example")
	if res, _ := rig.agent.event(t, "/srv/fresh/one", "Win.Test.EICAR_HDB-1"); res.code != 0 {
		t.Fatalf("%+v", res)
	}
	start := time.Now()
	_, at := rig.rcv.waitFor(t, "/srv/fresh/one", 30*time.Second)
	t.Logf("fresh detection alerted %v after its event, behind a 300-event backlog", time.Since(start))
	// It overtook the backlog: strict oldest-first would deliver it last, after all
	// 300 (which can still fit inside 30 s on a fast machine, so the time alone
	// proves nothing).
	rig.rcv.mu.Lock()
	before := 0
	for _, h := range rig.rcv.hits {
		if h.at.Before(at) {
			before++
		}
	}
	rig.rcv.mu.Unlock()
	if before > 100 {
		t.Fatalf("%d of the 300 backlog alerts arrived before the fresh one: it waited behind the backlog", before)
	}
	deadline := time.Now().Add(120 * time.Second)
	for len(rig.rcv.detections()) < 301 {
		if time.Now().After(deadline) {
			t.Fatalf("%d of 301 detections arrived", len(rig.rcv.detections()))
		}
		time.Sleep(200 * time.Millisecond)
	}
	rig.agent.waitSpoolEmpty(t, "events", 10*time.Second)
}

// A second target whose receiver hangs holds detection sends in flight to its own
// deadline. A fresh detection for the healthy target still alerts within 30 s:
// the dead target is capped at 2 sends and one worker is reserved.
func TestDetectionWithBusyWorkers(t *testing.T) {
	rig := newDetectionRig(t, nil, "")
	dead := newReceiver(t, true)
	seedWebhookTarget(t, rig.db, "dead", dead.url, loadRing(t, rig.key), func(n *store.NewAlertTarget) { n.DetectionBurst = 0; n.SendStateChanges = false })
	// The server read its targets at each pass, so the new one is seen. 10 hosts
	// post one detection each straight to /v1/event.
	ca, _ := os.ReadFile(rig.tls.CA)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &ctls.Config{RootCAs: pool}}}
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("busy%02d", i)
		reg := runServer(t, rig.srv.env, "host", "add", name)
		body := fmt.Sprintf(`{"schema":1,"id":"%032x","host":%q,"ts":%q,"path":"/srv/busy/%d","signature":"S","source":"clamd"}`, i+1, name, time.Now().UTC().Format(time.RFC3339), i)
		req, _ := http.NewRequest("POST", "https://"+rig.addr+"/v1/event", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(reg.stdout))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil || resp.StatusCode != 202 {
			t.Fatalf("post %d: %v %v", i, resp, err)
		}
		resp.Body.Close()
	}
	// Wait until the dead receiver really holds requests.
	deadline := time.Now().Add(10 * time.Second)
	for {
		dead.mu.Lock()
		live := dead.live
		dead.mu.Unlock()
		if live >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the dead receiver was never tried")
		}
		time.Sleep(50 * time.Millisecond)
	}
	rig.agent.startRun(t)
	if res, _ := rig.agent.event(t, "/srv/fresh/healthy", "Sig"); res.code != 0 {
		t.Fatalf("%+v", res)
	}
	start := time.Now()
	rig.rcv.waitFor(t, "/srv/fresh/healthy", 30*time.Second)
	t.Logf("healthy target alerted %v after the event while the other target hung", time.Since(start))
	dead.mu.Lock()
	peak := dead.peak
	dead.mu.Unlock()
	if peak > alert.MaxDetectionsPerTarget {
		t.Fatalf("%d sends in flight to one target, cap %d", peak, alert.MaxDetectionsPerTarget)
	}
}

// The agent is silent for longer than the STALE window while the server runs;
// it comes back with a backlog of heartbeats. The STALE recovery happens on the
// newest one, and the replayed ones cause no further transition.
func TestReplayAfterLongOutage(t *testing.T) {
	rig := newDetectionRig(t, []string{"CLAMFLEET_SERVER_HEALTH_EVAL_INTERVAL=1s"}, "interval: 10s\n")
	// A live report first (and so a first state).
	if res := rig.agent.runOnce(); res.code != 0 {
		t.Fatalf("run --once: %+v", res)
	}
	// The agent now "cannot reach" the server: the service points at a closed port
	// and spools a heartbeat every 10 s.
	raw, _ := os.ReadFile(rig.agent.cfgPath)
	good := string(raw)
	if err := os.WriteFile(rig.agent.cfgPath, []byte(strings.Replace(good, "server: https://"+rig.addr, "server: https://127.0.0.1:1", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := rig.agent.startRun(t)
	type change struct {
		From *string `json:"from_state"`
		To   string  `json:"to_state"`
	}
	changes := func() (n int, last string) {
		r := runServer(t, rig.srv.env, "host", "show", "web01", "--json")
		var s struct {
			StateChanges []change `json:"state_changes"`
			ReportCount  int      `json:"report_count"`
		}
		if r.code != 0 || json.Unmarshal([]byte(r.stdout), &s) != nil {
			t.Fatalf("host show: %+v", r)
		}
		if len(s.StateChanges) > 0 {
			last = s.StateChanges[0].To // newest first
		}
		return len(s.StateChanges), last
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		if _, last := changes(); last == "STALE" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the host never became STALE")
		}
		time.Sleep(time.Second)
	}
	spooled := rig.agent.spoolCount(t, "reports")
	if spooled < 3 {
		t.Fatalf("%d heartbeats in the spool, want at least 3", spooled)
	}
	svc.Stop()
	before, _ := changes() // none to X, X to STALE
	if err := os.WriteFile(rig.agent.cfgPath, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.agent.startRun(t)
	rig.agent.waitSpoolEmpty(t, "reports", 30*time.Second)
	time.Sleep(3 * time.Second) // evaluator ticks during and after the replay
	after, last := changes()
	if after != before+1 || last == "STALE" {
		t.Fatalf("%d transitions before the replay, %d after (last %s): exactly one, the recovery on the newest report", before, after, last)
	}
}
