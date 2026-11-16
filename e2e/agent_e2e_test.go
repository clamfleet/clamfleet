//go:build e2e

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package e2e runs the real agent binary inside the clamfleet-test container
// (Debian 13, distro ClamAV) as the unprivileged "clamfleet" user and checks
// its report against independent sources: sigtool, clamd --version, systemctl
// and journalctl. Read docs/testing.md before running.
//
// The suite is opt-in by build tag. Inside it, a missing CFT_EXEC is a hard
// failure, never a skip: a skipped e2e suite looks exactly like a passing one.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

var (
	cftExec  []string // command prefix that runs a command in the container
	binary   string   // the static agent binary, built once
	srvBin   string   // the static server binary, built once
	repoRoot string
)

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}

func testMain(m *testing.M) int {
	cftExec = strings.Fields(os.Getenv("CFT_EXEC"))
	if len(cftExec) == 0 {
		fmt.Fprintln(os.Stderr, "e2e: CFT_EXEC is not set (the command prefix that runs a command inside the test container, e.g. \"ssh <host> sudo incus exec <container> --\"); see docs/testing.md")
		return 1
	}
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: go list:", err)
		return 1
	}
	repoRoot = strings.TrimSpace(string(out))
	dir, err := os.MkdirTemp("", "cfe2e")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	binary = filepath.Join(dir, "clamfleet-agent")
	srvBin = filepath.Join(dir, "clamfleet-server")
	for out, pkg := range map[string]string{binary: "cmd/clamfleet-agent", srvBin: "cmd/clamfleet-server"} {
		if err := build(out, pkg); err != nil {
			fmt.Fprintln(os.Stderr, "e2e:", err)
			return 1
		}
	}
	code := m.Run()
	// Leave the container as found, even when tests failed half way.
	if err := script("reset.sh"); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: final reset failed:", err)
		code = 1
	}
	return code
}

// build compiles one of our commands as a static binary (CGO_ENABLED=0: the
// container's libc is not the build machine's).
func build(out, pkg string) error {
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, "github.com/clamfleet/clamfleet/"+pkg)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if o, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build %s: %w\n%s", pkg, err, o)
	}
	return nil
}

// script runs one of deploy/test/*.sh (they read CFT_EXEC themselves).
func script(name string) error {
	cmd := exec.Command(filepath.Join(repoRoot, "deploy", "test", name))
	cmd.Stdin = nil
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w\n%s", name, err, out)
	}
	return nil
}

// ct runs a command inside the container. Arguments must contain no spaces or
// shell syntax: ssh re-parses them on the far side. Use sh for anything else.
func ct(ctx context.Context, stdin []byte, args ...string) (stdout, stderr string, code int) {
	cmd := exec.CommandContext(ctx, cftExec[0], append(append([]string{}, cftExec[1:]...), args...)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		code = -1
		se.WriteString(err.Error())
	}
	return so.String(), se.String(), code
}

// sh runs a shell script as root in the container (over stdin) and returns
// its stdout; a non-zero exit fails the test.
func sh(t *testing.T, scriptText string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	out, errOut, code := ct(ctx, []byte("set -eu\n"+scriptText), "bash", "-s")
	if code != 0 {
		t.Fatalf("container script failed (exit %d): %s\nstdout: %s\nstderr: %s", code, scriptText, out, errOut)
	}
	return strings.TrimSpace(out)
}

// fresh returns the container to its clean snapshot, recreates the agent user
// and installs the freshly built binary.
func fresh(t *testing.T) {
	t.Helper()
	for _, s := range []string{"reset.sh", "prepare-agent.sh"} {
		if err := script(s); err != nil {
			t.Fatal(err)
		}
	}
	pushBinary(t, binary, "clamfleet-agent")
	waitClamd(t)
}

// pushBinary installs a built binary as /usr/local/bin/<name> in the container.
func pushBinary(t *testing.T, path, name string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tarball bytes.Buffer
	if err := writeTar(&tarball, name, data); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, e, code := ct(ctx, tarball.Bytes(), "tar", "-xf", "-", "-C", "/usr/local/bin", "--no-same-owner"); code != 0 {
		t.Fatalf("pushing %s: exit %d: %s", name, code, e)
	}
}

// waitClamd blocks until clamd can really scan. reset.sh's "clamdscan --ping"
// returns while clamd is still loading signatures (observed on Debian 13: PONG
// about 5 s before the load finished), and an agent report taken in that
// window correctly says up=false, which would make the first test flaky.
// A scan needs the loaded engine, so it is the real readiness signal.
func waitClamd(t *testing.T) {
	t.Helper()
	// READY_FILE: under AppArmor (the VM) clamd may not read /etc/hostname; see reset.sh.
	ready := os.Getenv("READY_FILE")
	if ready == "" {
		ready = "/etc/hostname"
	}
	sh(t, "for _ in $(seq 1 90); do clamdscan --no-summary "+ready+" >/dev/null 2>&1 && exit 0; sleep 1; done; echo clamd never became ready >&2; exit 1")
}

// collect runs "clamfleet-agent collect --dry-run" as the unprivileged user
// (not root: root would hide the permission failures production will meet).
// wantSource derives freshclam.source from the container's facts, not from
// what the agent said: the journal counts when the unit's journal holds a run,
// the log file when the clamfleet user can read a run from it. Both counting
// gives "journal+log". It is computed independently of the agent's code, so
// the assertion fails if the agent names the wrong origin.
func wantSource(t *testing.T) string {
	t.Helper()
	journal := sh(t, "journalctl -u clamav-freshclam -o cat --no-pager -q | grep -c 'update process started' || true") != "0"
	file := sh(t, "runuser -u clamfleet -- grep -c 'update process started' /var/log/clamav/freshclam.log 2>/dev/null || true") != "0"
	switch {
	case journal && file:
		return proto.SourceJournalLog
	case journal:
		return proto.SourceJournal
	case file:
		return proto.SourceLog
	}
	return "null"
}

func sourceOf(r proto.Report) string {
	if r.Freshclam.Source == nil {
		return "null"
	}
	return *r.Freshclam.Source
}

func collect(t *testing.T, env ...string) (proto.Report, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	args := append(append([]string{"runuser", "-u", "clamfleet", "--", "env"}, env...), "/usr/local/bin/clamfleet-agent", "collect", "--dry-run")
	out, errOut, code := ct(ctx, nil, args...)
	if code != 0 {
		t.Fatalf("collect exited %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	var r proto.Report
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("stdout is not a report: %v\n%s", err, out)
	}
	for _, l := range strings.Split(strings.TrimSpace(errOut), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			t.Fatalf("stderr line is not JSON: %q", l)
		}
	}
	t.Logf("report: %s", strings.Join(strings.Fields(out), " "))
	t.Logf("stderr: %s", strings.TrimSpace(errOut))
	return r, errOut
}

// sigtoolVersion returns "Version" and "Signatures" printed by sigtool for one database.
func sigtoolInfo(t *testing.T, file string) (version int, sigs int64) {
	t.Helper()
	out := sh(t, "sigtool --info=/var/lib/clamav/"+file)
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, "Version: "); ok {
			version, _ = strconv.Atoi(v)
		}
		if v, ok := strings.CutPrefix(l, "Signatures: "); ok {
			sigs, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if version == 0 {
		t.Fatalf("no version in sigtool output: %s", out)
	}
	return
}

var ctimeRE = regexp.MustCompile(`ClamAV update process started at (.+)`)

// lastRunStart finds the newest "update process started" time in text. The
// container runs in UTC (checked by the caller), and freshclam's ctime has no zone.
func lastRunStart(t *testing.T, text string) time.Time {
	t.Helper()
	m := ctimeRE.FindAllStringSubmatch(text, -1)
	if len(m) == 0 {
		t.Fatalf("no run start in: %s", text)
	}
	ts, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", strings.TrimSpace(m[len(m)-1][1]), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestHealthyHost(t *testing.T) {
	fresh(t)
	if tz := sh(t, "date +%z"); tz != "+0000" {
		t.Fatalf("container is not on UTC (%s): freshclam times would be misread by this test", tz)
	}
	r, _ := collect(t)

	if r.Schema != 1 {
		t.Errorf("schema = %d", r.Schema)
	}
	if want := sh(t, "hostname"); r.Host != want {
		t.Errorf("host = %q, container says %q", r.Host, want)
	}
	if want := sh(t, ". /etc/os-release; echo \"$ID $VERSION_ID\""); r.OS.ID+" "+r.OS.Version != want || r.OS.ID != "debian" {
		t.Errorf("os = %+v, os-release says %q", r.OS, want)
	}
	if !r.Clamd.Up || r.Clamd.Error != nil {
		t.Errorf("clamd = %+v", r.Clamd)
	}
	if want, _, _ := strings.Cut(strings.TrimPrefix(sh(t, "clamd --version"), "ClamAV "), "/"); r.Clamd.Version == nil || *r.Clamd.Version != want {
		t.Errorf("clamd.version = %v, clamd --version says %q", r.Clamd.Version, want)
	}
	if r.Clamd.Queue == nil {
		t.Error("clamd.queue is null")
	}
	for name, db := range map[string]*proto.SigDB{"daily": r.Sigs.Daily, "main": r.Sigs.Main, "bytecode": r.Sigs.Bytecode} {
		if db == nil {
			t.Errorf("sigs.%s is null", name)
			continue
		}
		file := sh(t, "ls /var/lib/clamav/"+name+".c[vl]d | head -n1")
		wv, ws := sigtoolInfo(t, filepath.Base(file))
		if db.Version != wv || db.Sigs != ws {
			t.Errorf("sigs.%s = %+v, sigtool says version=%d sigs=%d", name, db, wv, ws)
		}
	}
	if want := sh(t, "systemctl is-active clamav-daemon"); r.Services.Clamd != want || want != "active" {
		t.Errorf("services.clamd = %q, systemctl says %q", r.Services.Clamd, want)
	}
	// freshclam is disabled in the clean snapshot (we never contact the CDN here).
	if want := sh(t, "systemctl is-active clamav-freshclam || true"); r.Services.Freshclam != want {
		t.Errorf("services.freshclam = %q, systemctl says %q", r.Services.Freshclam, want)
	}
	if want := sh(t, "systemctl is-active clamav-clamonacc || true"); r.Services.Clamonacc != want {
		t.Errorf("services.clamonacc = %q, systemctl says %q", r.Services.Clamonacc, want)
	}
	if r.LastScan != nil {
		t.Errorf("last_scan = %+v, want null", r.LastScan)
	}
	// The snapshot's freshclam ran once (the initial download), and both the
	// journal and the log file record it.
	want := lastRunStart(t, sh(t, "cat /var/log/clamav/freshclam.log"))
	if r.Freshclam.LastOK == nil || !r.Freshclam.LastOK.Equal(want) {
		t.Errorf("freshclam.last_ok = %v, log says %v", r.Freshclam.LastOK, want)
	}
	if r.Freshclam.LastError != nil {
		t.Errorf("freshclam.last_error = %v, want null", r.Freshclam.LastError)
	}
	// Records which source worked (M1 Q8): the journal, because the
	// agent user is in group systemd-journal.
	if j := sh(t, "journalctl -u clamav-freshclam -o cat --no-pager -q | grep -c 'update process started'"); j == "0" {
		t.Errorf("the journal holds no freshclam run, so the result came from the log file")
	}
	// The clean install has the run in the journal AND in the log file (640
	// clamav:clamav, readable by the agent's group until the first rotation).
	if got, want := sourceOf(r), wantSource(t); got != want || want != proto.SourceJournalLog {
		t.Errorf("freshclam.source = %s, the container's journal and log say %s (clean install expects %s)", got, want, proto.SourceJournalLog)
	}
	t.Log("freshclam source on Debian 13 clean install: systemd journal and, until its first rotation, the log file")
}

// clamdStopped stops clamd as an operator would. The socket unit stays active
// in case (a): that is the Debian state after "systemctl stop clamav-daemon",
// and connecting to it would START clamd again.
func TestClamdStoppedIsNotRestartedByTheAgent(t *testing.T) {
	cases := map[string]string{
		"service stopped, socket still listening": "systemctl stop clamav-daemon.service",
		"service and socket stopped":              "systemctl stop clamav-daemon.service clamav-daemon.socket",
	}
	for name, stop := range cases {
		t.Run(name, func(t *testing.T) {
			fresh(t)
			// Precondition: the socket unit is what makes the Q4 proof mean
			// something. Without an active clamav-daemon.socket a connection could
			// not start clamd anyway, and "not restarted" would pass vacuously.
			if got := sh(t, "systemctl is-active clamav-daemon.socket || true"); got != "active" {
				t.Fatalf("precondition: clamav-daemon.socket is %q, want active", got)
			}
			sh(t, stop)
			if got := sh(t, "systemctl is-active clamav-daemon.service || true"); got != "inactive" {
				t.Fatalf("precondition: clamd is %q", got)
			}
			r, _ := collect(t)
			if r.Clamd.Up || r.Clamd.Error == nil || r.Clamd.Version != nil || r.Clamd.Queue != nil {
				t.Errorf("clamd = %+v, want up=false with an error", r.Clamd)
			}
			if r.Services.Clamd != "inactive" {
				t.Errorf("services.clamd = %q", r.Services.Clamd)
			}
			if r.Sigs.Daily == nil || r.Sigs.Main == nil {
				t.Errorf("signatures must still be reported: %+v", r.Sigs)
			}
			// The M1 Q4 proof: the agent must not have started clamd.
			if got := sh(t, "systemctl is-active clamav-daemon.service || true"); got != "inactive" {
				t.Errorf("after the report clamd is %q: the agent started it", got)
			}
		})
	}
}

// A freshclam that cannot reach its mirror: a real unit, started with a
// drop-in that points freshclam at an unreachable loopback mirror (never the
// real CDN, which rate-limits). The failure must reach the report through the
// systemd journal (M1 Q8), and the unit state must follow start/stop.
func TestFreshclamFailingThenStopped(t *testing.T) {
	fresh(t)
	sh(t, `
grep -v -E '^(NotifyClamd|UpdateLogFile|DatabaseMirror|DNSDatabaseInfo|MaxAttempts|ConnectTimeout)' /etc/clamav/freshclam.conf > /tmp/fc-fail.conf
printf 'PrivateMirror http://127.0.0.1:9\nMaxAttempts 1\nConnectTimeout 5\n' >> /tmp/fc-fail.conf
mkdir -p /run/systemd/system/clamav-freshclam.service.d
printf '[Service]\nExecStart=\nExecStart=/usr/bin/freshclam -d --foreground=true --config-file=/tmp/fc-fail.conf\n' > /run/systemd/system/clamav-freshclam.service.d/e2e.conf
systemctl daemon-reload
systemctl start clamav-freshclam
for _ in $(seq 1 40); do journalctl -u clamav-freshclam -o cat --no-pager -q | grep -q 'Update failed' && break; sleep 1; done
`)
	r, _ := collect(t)
	if r.Services.Freshclam != "active" {
		t.Errorf("services.freshclam = %q, want active", r.Services.Freshclam)
	}
	journal := sh(t, "journalctl -u clamav-freshclam -o cat --no-pager -q")
	want := lastRunStart(t, journal)
	if r.Freshclam.LastError == nil || !r.Freshclam.LastError.Equal(want) {
		t.Errorf("freshclam.last_error = %v, journal says the failed run started %v", r.Freshclam.LastError, want)
	}
	if r.Freshclam.LastErrorMsg == nil || !strings.Contains(*r.Freshclam.LastErrorMsg, "Download failed") {
		t.Errorf("freshclam.last_error_msg = %v", r.Freshclam.LastErrorMsg)
	}
	// The failed run exists only in the journal (UpdateLogFile is removed from
	// the drop-in's config); the snapshot's initial run is in both.
	if got, want := sourceOf(r), wantSource(t); got != want {
		t.Errorf("freshclam.source = %s, the container's journal and log say %s", got, want)
	}
	// The journal also holds the snapshot's initial (successful) run.
	first := ctimeRE.FindStringSubmatch(journal)
	if first == nil {
		t.Fatalf("no run in journal: %s", journal)
	}
	wantOK, _ := time.ParseInLocation("Mon Jan _2 15:04:05 2006", strings.TrimSpace(first[1]), time.UTC)
	if r.Freshclam.LastOK == nil || !r.Freshclam.LastOK.Equal(wantOK) {
		t.Errorf("freshclam.last_ok = %v, the journal's first run started %v", r.Freshclam.LastOK, wantOK)
	}

	sh(t, "systemctl stop clamav-freshclam")
	r, _ = collect(t)
	if r.Services.Freshclam != "inactive" {
		t.Errorf("after stop: services.freshclam = %q, want inactive", r.Services.Freshclam)
	}
}

func TestLastScanAbsentThenPresent(t *testing.T) {
	fresh(t)
	if r, _ := collect(t); r.LastScan != nil {
		t.Fatalf("absent file: last_scan = %+v, want null", r.LastScan)
	}
	want := proto.LastScan{
		Started:  time.Date(2026, 11, 12, 2, 0, 0, 0, time.UTC),
		Finished: time.Date(2026, 11, 12, 2, 41, 10, 0, time.UTC),
		Exit:     1, Scanned: 120345, Infected: 2, Errors: 3,
	}
	raw, _ := json.Marshal(want)
	sh(t, "cat > /var/lib/clamfleet/last_scan.json <<'JSON'\n"+string(raw)+"\nJSON\nchmod 644 /var/lib/clamfleet/last_scan.json")
	r, _ := collect(t)
	if r.LastScan == nil || *r.LastScan != want {
		t.Fatalf("last_scan = %+v, want %+v", r.LastScan, want)
	}
}

// Documents the real Debian 13 behaviour (assumption A15): the freshclam log
// the agent can read today becomes unreadable for group clamav once logrotate
// recreates it as "640 clamav adm". With the journal available (the default)
// the report is unaffected; on a host without freshclam journal entries (for
// example freshclam run from cron, simulated here by an empty units.freshclam)
// the agent must degrade to database file times with a warning, not fail.
func TestFreshclamLogUnreadableAfterRotation(t *testing.T) {
	fresh(t)
	if got := sh(t, "stat -c '%U:%G %a' /var/log/clamav/freshclam.log"); got != "clamav:clamav 640" {
		t.Fatalf("fresh install log is %q; the premise of this test changed", got)
	}
	noJournal := "CLAMFLEET_AGENT_UNITS_FRESHCLAM="
	logRun := lastRunStart(t, sh(t, "cat /var/log/clamav/freshclam.log"))

	r, _ := collect(t, noJournal)
	if r.Freshclam.LastOK == nil || !r.Freshclam.LastOK.Equal(logRun) {
		t.Errorf("before rotation, from the log file: last_ok = %v, want %v", r.Freshclam.LastOK, logRun)
	}
	if got := sourceOf(r); got != proto.SourceLog {
		t.Errorf("without the journal, readable log: source = %s, want %s", got, proto.SourceLog)
	}

	sh(t, "logrotate -f /etc/logrotate.d/clamav-freshclam")
	got := sh(t, "stat -c '%U:%G %a' /var/log/clamav/freshclam.log")
	if got != "clamav:adm 640" {
		t.Fatalf("Debian's logrotate no longer recreates the log as clamav:adm 640 (got %q): revisit M1 Q8", got)
	}

	// Journal available: unchanged result, no warning about the log.
	r, stderr := collect(t)
	if r.Freshclam.LastOK == nil || !r.Freshclam.LastOK.Equal(logRun) || strings.Contains(stderr, "freshclam") {
		t.Errorf("with the journal: last_ok = %v, stderr = %s", r.Freshclam.LastOK, stderr)
	}
	// The rotated log is unreadable for the agent, so only the journal counts.
	if got := sourceOf(r); got != proto.SourceJournal {
		t.Errorf("with the journal, unreadable log: source = %s, want %s", got, proto.SourceJournal)
	}

	// Journal not used: the unreadable log forces the mtime fallback.
	r, stderr = collect(t, noJournal)
	if !strings.Contains(stderr, "permission denied") {
		t.Errorf("expected a permission warning on stderr, got: %s", stderr)
	}
	if r.Freshclam.LastError != nil {
		t.Errorf("last_error = %v: nothing can be known without the log", r.Freshclam.LastError)
	}
	if got := sourceOf(r); got != proto.SourceMtime {
		t.Errorf("without journal or log: source = %s, want %s", got, proto.SourceMtime)
	}
	mtime := sh(t, "stat -c %Y /var/lib/clamav/daily.cvd")
	secs, _ := strconv.ParseInt(mtime, 10, 64)
	if r.Freshclam.LastOK == nil || !r.Freshclam.LastOK.Equal(time.Unix(secs, 0).UTC()) {
		t.Errorf("last_ok = %v, daily.cvd mtime is %d", r.Freshclam.LastOK, secs)
	}
	t.Log("Debian 13 after logrotate: freshclam.log is clamav:adm 640 and unreadable by the agent; the journal keeps the result available")
}
