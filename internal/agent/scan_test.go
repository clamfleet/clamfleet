// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// ---- the stream parser, on recorded clamdscan output (testdata/clamdscan) ----

func TestParseScanStreamOnRecordedOutput(t *testing.T) {
	for _, c := range []struct {
		name                   string
		ok, infected, errs     int64
		sumInfected, sumErrors int64
	}{
		{"clean", 1, 0, 0, 0, -1},
		{"infected", 0, 1, 0, 1, -1},
		{"error", 0, 0, 1, 0, 1},
		{"several", 1, 1, 1, 1, 1},
		{"down", 0, 0, 0, 0, 1}, // no per-file line: only the summary knows
	} {
		got, err := ParseScanStream(bytes.NewReader(fixture(t, "clamdscan/"+c.name+".out")))
		if err != nil {
			t.Fatal(err)
		}
		want := ScanCounts{OK: c.ok, Infected: c.infected, Errors: c.errs, SummaryInfected: c.sumInfected, SummaryErrors: c.sumErrors}
		if got != want {
			t.Errorf("%s: %+v, want %+v", c.name, got, want)
		}
	}
}

// The parser never returns a path, in a value or an error.
func TestParseScanStreamKeepsNoPath(t *testing.T) {
	in := "/srv/MARKER-PATH/a: Eicar-Signature FOUND\n/srv/MARKER-PATH/b: Permission denied. ERROR\n"
	c, err := ParseScanStream(strings.NewReader(in))
	if err != nil || fmt.Sprintf("%+v %v", c, err) != fmt.Sprintf("%+v %v", ScanCounts{Infected: 1, Errors: 1, SummaryInfected: -1, SummaryErrors: -1}, nil) {
		t.Fatalf("%+v %v", c, err)
	}
	if strings.Contains(fmt.Sprint(c), "MARKER") {
		t.Fatal("a path is in the counts")
	}
}

// A line without a trailing newline at EOF still counts; a CRLF is trimmed.
func TestParseScanStreamEdges(t *testing.T) {
	c, _ := ParseScanStream(strings.NewReader("/a: OK\r\n/b: Sig FOUND"))
	if c.OK != 1 || c.Infected != 1 {
		t.Fatalf("%+v", c)
	}
}

// A 100 KB line is counted once, as an error, and the next line is still read.
func TestParseScanStreamOverlongLine(t *testing.T) {
	in := "/" + strings.Repeat("x", 100<<10) + ": Sig FOUND\n/ok: OK\n"
	c, err := ParseScanStream(strings.NewReader(in))
	if err != nil || c.Errors != 1 || c.Infected != 0 || c.OK != 1 {
		t.Fatalf("%+v %v", c, err)
	}
}

// lineSource synthesises n bytes of per-file lines without storing them.
type lineSource struct {
	left int64
	pos  int
	line []byte
}

func (l *lineSource) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && l.left > 0 {
		c := copy(p[n:], l.line[l.pos:])
		n += c
		l.pos = (l.pos + c) % len(l.line)
		l.left -= int64(c)
	}
	return n, nil
}

// Rule: memory is constant whatever the number of files. 2 GB of OK lines are
// counted while the heap is sampled, and the allocation count of a smaller
// stream does not depend on its size. Mutation: collect the lines.
func TestParseScanStreamIsBoundedOn2GB(t *testing.T) {
	const size = 2 << 30
	line := []byte("/srv/data/some/deeper/directory/file-0123456789.bin: OK\n")
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak {
					peak = m.HeapAlloc
				}
			}
		}
	}()
	c, err := ParseScanStream(&lineSource{left: size, line: line})
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(size / len(line)); c.OK < want-1 || c.OK > want+1 {
		t.Fatalf("counted %d lines, want about %d", c.OK, want)
	}
	if grown := int64(peak) - int64(base.HeapAlloc); grown > 16<<20 {
		t.Fatalf("the heap grew by %d MB while parsing 2 GB", grown>>20)
	}
	small := testing.AllocsPerRun(3, func() { ParseScanStream(&lineSource{left: 1 << 20, line: line}) })
	big := testing.AllocsPerRun(3, func() { ParseScanStream(&lineSource{left: 8 << 20, line: line}) })
	if big > small+2 {
		t.Fatalf("allocations grow with the stream: %v for 1 MB, %v for 8 MB", small, big)
	}
}

func TestStderrClassNeverQuotes(t *testing.T) {
	for in, want := range map[string]string{
		string(fixture(t, "clamdscan/down.err")):            "clamd not reachable",
		"ERROR: Can't parse the config file /x/y":           "config file problem",
		"/srv/MARKER-PATH: Permission denied":               "permission denied",
		"something nobody has seen /srv/MARKER-PATH before": "unclassified",
		"  \n": "",
	} {
		got := stderrClass([]byte(in))
		if got != want || strings.Contains(got, "MARKER") {
			t.Errorf("%q: class %q, want %q", in, got, want)
		}
	}
}

// ---- the whole scan, with a fake clamdscan and a fake systemctl --------------

type scanEnv struct {
	t       *testing.T
	dir     string
	cfg     Config
	argsOut string
	logs    *syncWriter
	clk     time.Time
	state   string // the clamd unit's ActiveState
}

type syncWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}
func (w *syncWriter) String() string { w.mu.Lock(); defer w.mu.Unlock(); return w.b.String() }

func newScanEnv(t *testing.T) *scanEnv {
	t.Helper()
	dir := shortTempDir(t)
	e := &scanEnv{t: t, dir: dir, logs: &syncWriter{}, clk: time.Date(2031, 3, 4, 2, 0, 0, 0, time.UTC), state: "active"}
	e.cfg = DefaultConfig()
	e.cfg.ClamdConf = filepath.Join(dir, "clamd.conf")
	e.cfg.Scan.Paths = []string{"/srv/data"}
	e.cfg.Scan.Summary = filepath.Join(dir, "last_scan.json")
	e.argsOut = filepath.Join(dir, "args")
	return e
}

// fake writes a clamdscan stand-in: it records its arguments, replays a fixture
// (stdout, stderr, exit status) or runs the given extra shell.
func (e *scanEnv) fake(body string) string {
	p := filepath.Join(e.dir, "clamdscan")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + e.argsOut + "\n" + body + "\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *scanEnv) replay(name string) string {
	d, _ := filepath.Abs(filepath.Join("testdata", "clamdscan"))
	return fmt.Sprintf("cat %s/%s.out\ncat %s/%s.err >&2\nexit $(cat %s/%s.exit)", d, name, d, name, d, name)
}

func (e *scanEnv) scanner(bin string) *Scanner {
	return &Scanner{
		Cfg: e.cfg, Bin: bin, Now: func() time.Time { return e.clk },
		Log: slog.New(slog.NewJSONHandler(e.logs, nil)),
		Exec: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "systemctl" {
				e.t.Errorf("unexpected command %s", name)
			}
			return []byte("LoadState=loaded\nActiveState=" + e.state + "\n"), nil
		},
	}
}

func (e *scanEnv) summary() (proto.LastScan, bool) {
	b, err := os.ReadFile(e.cfg.Scan.Summary)
	if err != nil {
		return proto.LastScan{}, false
	}
	var s proto.LastScan
	if err := json.Unmarshal(b, &s); err != nil {
		e.t.Fatal(err)
	}
	return s, true
}

func TestScanExitCodesAndSummary(t *testing.T) {
	for _, c := range []struct {
		fixture        string
		exit           int
		infected, errs int64
	}{
		{"clean", 0, 0, 0}, {"infected", 1, 1, 0}, {"error", 2, 0, 1}, {"several", 1, 1, 1}, {"down", 2, 0, 1},
	} {
		e := newScanEnv(t)
		sc := e.scanner(e.fake(e.replay(c.fixture)))
		code, err := sc.Run(context.Background())
		if err != nil || code != c.exit {
			t.Fatalf("%s: code %d err %v, want %d", c.fixture, code, err, c.exit)
		}
		s, ok := e.summary()
		if !ok || s.Exit != c.exit || s.Infected != c.infected || s.Errors != c.errs || s.Scanned != 0 || !s.Started.Equal(e.clk) || !s.Finished.Equal(e.clk) {
			t.Errorf("%s: summary %+v (present %v)", c.fixture, s, ok)
		}
		if fi, err := os.Stat(e.cfg.Scan.Summary); err != nil || fi.Mode().Perm() != 0o640 {
			t.Errorf("%s: summary mode %v %v", c.fixture, fi, err)
		}
		// The agent's own reader accepts what the scan wrote.
		if ls, p := readLastScan(e.cfg.Scan.Summary); p != nil || ls == nil || ls.Exit != c.exit {
			t.Errorf("%s: readLastScan %+v %v", c.fixture, ls, p)
		}
	}
}

// Rule: a clamdscan killed by a signal (ExitCode -1) or exiting with a code that is not 0, 1 or 2
// is an error, never a success. Mutation: pass the raw exit code through.
func TestScanSignalOrOddExitIsAnError(t *testing.T) {
	for name, body := range map[string]string{
		"killed by a signal": "printf '/a: OK\\n'\nkill -9 $$",
		"exit 127":           "exit 127",
		"exit 3":             "exit 3",
	} {
		e := newScanEnv(t)
		code, err := e.scanner(e.fake(body)).Run(context.Background())
		if code != ScanError || err != nil {
			t.Errorf("%s: code %d err %v, want 2 and no error", name, code, err)
		}
		s, ok := e.summary()
		if !ok || s.Exit != ScanError {
			t.Errorf("%s: summary %+v (present %v), want exit 2", name, s, ok)
		}
	}
}

// The command line is exactly what the plan says: the agent's clamd.conf, --multiscan,
// the configured paths, and no --fdpass.
func TestScanCommandLine(t *testing.T) {
	e := newScanEnv(t)
	e.cfg.Scan.Paths = []string{"/srv/a", "/srv/b"}
	if _, err := e.scanner(e.fake(e.replay("clean"))).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(e.argsOut)
	want := "--config-file=" + e.cfg.ClamdConf + "\n--multiscan\n--\n/srv/a\n/srv/b\n"
	if string(b) != want {
		t.Fatalf("args %q, want %q", b, want)
	}
}

// Rule: with the clamd unit inactive, the scan writes nothing, exits 2, never runs
// clamdscan and never touches the socket (socket activation would start clamd).
// Mutation: scanning anyway.
func TestScanNeverTouchesClamdWhileTheUnitIsInactive(t *testing.T) {
	e := newScanEnv(t)
	e.state = "inactive"
	clamd := startFakeClamd(t, map[string]reply{})
	e.cfg.ClamdConf = filepath.Join(e.dir, "clamd.conf")
	os.WriteFile(e.cfg.ClamdConf, []byte("LocalSocket "+clamd.Path+"\n"), 0o644)
	ran := filepath.Join(e.dir, "ran")
	// A real clamdscan would connect; this stand-in does, to prove the test could see it.
	sc := e.scanner(e.fake("touch " + ran + "\n"))
	code, err := sc.Run(context.Background())
	if code != 2 || !errors.Is(err, ErrScanClamdInactive) {
		t.Fatalf("code %d err %v", code, err)
	}
	if _, ok := e.summary(); ok {
		t.Fatal("a summary was written for a scan that never ran")
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("clamdscan was run while the clamd unit was inactive")
	}
	if n := clamd.conns.Load(); n != 0 {
		t.Fatalf("%d connections to the clamd socket", n)
	}
}

func TestScanRefusals(t *testing.T) {
	e := newScanEnv(t)
	e.cfg.Scan.Paths = nil
	if code, err := e.scanner(e.fake("exit 0")).Run(context.Background()); code != 2 || err == nil || !strings.Contains(err.Error(), "scan.paths") {
		t.Fatalf("%d %v", code, err)
	}
	e = newScanEnv(t)
	sc := e.scanner(filepath.Join(e.dir, "no-such-clamdscan"))
	if code, err := sc.Run(context.Background()); code != 2 || err == nil {
		t.Fatalf("a missing clamdscan: %d %v", code, err)
	}
	if _, ok := e.summary(); ok {
		t.Fatal("a summary for a scan that could not start")
	}
	// No clamd unit configured: not systemd-managed, so no unit check at all.
	e = newScanEnv(t)
	e.cfg.Units.Clamd = ""
	sc = e.scanner(e.fake(e.replay("clean")))
	sc.Exec = func(context.Context, string, ...string) ([]byte, error) {
		t.Error("systemctl asked for an unmanaged clamd")
		return nil, nil
	}
	if code, err := sc.Run(context.Background()); code != 0 || err != nil {
		t.Fatalf("%d %v", code, err)
	}
}

// Rule: the summary is written atomically. A failure between the fsync and the
// rename leaves the previous summary intact and no temporary file.
func TestScanSummaryIsAtomic(t *testing.T) {
	e := newScanEnv(t)
	old := []byte(`{"started":"2030-01-01T00:00:00Z","finished":"2030-01-01T01:00:00Z","exit":0,"scanned":0,"infected":0,"errors":0}`)
	if err := os.WriteFile(e.cfg.Scan.Summary, old, 0o640); err != nil {
		t.Fatal(err)
	}
	sc := e.scanner(e.fake(e.replay("infected")))
	sc.beforeRename = func() error { return errors.New("injected") }
	code, err := sc.Run(context.Background())
	if code != 2 || err == nil {
		t.Fatalf("%d %v", code, err)
	}
	if b, _ := os.ReadFile(e.cfg.Scan.Summary); !bytes.Equal(b, old) {
		t.Fatalf("the old summary changed: %s", b)
	}
	ents, _ := os.ReadDir(e.dir)
	for _, en := range ents {
		if strings.HasPrefix(en.Name(), ".last_scan-") {
			t.Fatalf("a temporary file was left: %s", en.Name())
		}
	}
}

// Rule: no scanned path is ever logged, from stdout or stderr. A marker path in the
// output must not reach a log line.
func TestScanNoPathInLogs(t *testing.T) {
	e := newScanEnv(t)
	body := `printf '/srv/MARKER-PATH/a: Eicar-Signature FOUND\n/srv/MARKER-PATH/b: Permission denied. ERROR\n\n----------- SCAN SUMMARY -----------\nInfected files: 1\nTotal errors: 1\n'
echo "ERROR: cannot read /srv/MARKER-PATH/c: Permission denied" >&2
exit 1`
	code, err := e.scanner(e.fake(body)).Run(context.Background())
	if code != 1 || err != nil {
		t.Fatalf("%d %v", code, err)
	}
	if strings.Contains(e.logs.String(), "MARKER") {
		t.Fatalf("a path reached the log:\n%s", e.logs.String())
	}
	if !strings.Contains(e.logs.String(), `"class":"permission denied"`) {
		t.Fatalf("the failure class was not logged:\n%s", e.logs.String())
	}
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !ok(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func readPid(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// hangingScan is a clamdscan stand-in that prints one detection, starts a child
// that outlives it, and then waits forever.
func (e *scanEnv) hanging() (bin, parentPid, childPid string) {
	parentPid, childPid = filepath.Join(e.dir, "ppid"), filepath.Join(e.dir, "cpid")
	return e.fake(`echo $$ > ` + parentPid + `
printf '/srv/x: Eicar FOUND\n'
sleep 300 &
echo $! > ` + childPid + `
wait`), parentPid, childPid
}

// Rule: when scan.timeout expires (the injected timer fires) the whole process
// group is gone, and the summary has exit 2 with the counts so far. Mutation: no
// group kill (the child survives), or no timeout.
func TestScanTimeoutStopsTheProcessGroup(t *testing.T) {
	e := newScanEnv(t)
	bin, ppid, cpid := e.hanging()
	fire := make(chan time.Time)
	sc := e.scanner(bin)
	var asked time.Duration
	sc.After = func(d time.Duration) <-chan time.Time { asked = d; return fire }
	type res struct {
		code int
		err  error
	}
	done := make(chan res, 1)
	go func() { c, err := sc.Run(context.Background()); done <- res{c, err} }()
	waitFor(t, "the child to start", func() bool { return readPid(cpid) != 0 && readPid(ppid) != 0 })
	parent, child := readPid(ppid), readPid(cpid)
	close(fire)
	r := <-done
	if r.code != 2 || r.err != nil {
		t.Fatalf("%d %v", r.code, r.err)
	}
	if asked != e.cfg.Scan.Timeout {
		t.Fatalf("timer asked for %s, want scan.timeout %s", asked, e.cfg.Scan.Timeout)
	}
	waitFor(t, "the process group to disappear", func() bool { return !alive(parent) && !alive(child) })
	s, ok := e.summary()
	if !ok || s.Exit != 2 || s.Infected != 1 {
		t.Fatalf("summary %+v present %v: want exit 2 and the counts so far", s, ok)
	}
	if !strings.Contains(e.logs.String(), "scan timed out") {
		t.Fatalf("no timeout line:\n%s", e.logs.String())
	}
}

// An interrupted scan (SIGTERM from systemd, a cancelled context) kills the child and
// writes NOTHING: it is not a result.
func TestScanInterruptedWritesNothing(t *testing.T) {
	e := newScanEnv(t)
	bin, ppid, cpid := e.hanging()
	ctx, cancel := context.WithCancel(context.Background())
	sc := e.scanner(bin)
	sc.After = func(time.Duration) <-chan time.Time { return nil }
	type res struct {
		code int
		err  error
	}
	done := make(chan res, 1)
	go func() { c, err := sc.Run(ctx); done <- res{c, err} }()
	waitFor(t, "the child to start", func() bool { return readPid(cpid) != 0 && readPid(ppid) != 0 })
	parent, child := readPid(ppid), readPid(cpid)
	cancel()
	r := <-done
	if r.code != 2 || !errors.Is(r.err, ErrScanInterrupted) {
		t.Fatalf("%d %v", r.code, r.err)
	}
	waitFor(t, "the process group to disappear", func() bool { return !alive(parent) && !alive(child) })
	if _, ok := e.summary(); ok {
		t.Fatal("an interrupted scan wrote a summary")
	}
}
