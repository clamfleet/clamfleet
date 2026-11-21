//go:build e2e

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Milestone 5 acceptance in the container: a real
// clamd, wired to the real `clamfleet-agent event` through VirusEvent, scans an
// EICAR test file, and the alert reaches the sink: with the agent running as a
// service, across a server outage, behind a backlog, in a mass detection, and
// when the spool cannot take the event.
//
// What the container cannot test: AppArmor. It has no apparmor package and clamd
// runs unconfined here, so a profile that refuses VirusEvent on a stock Debian host
// would pass this file. `make e2e-apparmor` (e2e/apparmor_e2e_test.go) runs the
// same path in a VM where AppArmor enforces.
//
// The EICAR string is built from two halves at run time and never appears in the
// repository as one string.
package e2e

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/alert"
)

const (
	eicarHalfA = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
	eicarHalfB = "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
	spoolDir   = "/var/lib/clamfleet/spool"
	// virusEventLine is what the installer (and docs/detections.md) tells an admin to add.
	virusEventLine = "VirusEvent /usr/local/bin/clamfleet-agent event"
)

// writeEICAR creates n EICAR files dir/prefix-i.com (readable by clamd's user).
func writeEICAR(t *testing.T, dir, prefix string, n int) {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString([]byte(eicarHalfA + eicarHalfB))
	sh(t, "install -d -m 755 "+dir+"; for i in $(seq 1 "+strconv.Itoa(n)+"); do printf %s "+b64+" | base64 -d > "+dir+"/"+prefix+"-$i.com; done; chmod 644 "+dir+"/*.com")
}

// enableVirusEvent wires clamd to the agent's event command and restarts it. It
// runs only in this file's scenarios, so the other suites keep their timing; the
// snapshot reset restores clamd.conf.
func enableVirusEvent(t *testing.T) {
	t.Helper()
	sh(t, "echo '"+virusEventLine+"' >> /etc/clamav/clamd.conf; systemctl restart clamav-daemon")
	waitClamd(t)
}

// scan runs clamdscan on a path in the container and returns its exit code and duration.
func scan(t *testing.T, args string) (code int, took time.Duration, out string) {
	t.Helper()
	start := time.Now()
	stdout, stderr, c := ct(t.Context(), []byte("clamdscan --no-summary "+args+"\n"), "bash", "-s")
	return c, time.Since(start), stdout + stderr
}

// detectionTarget adds the webhook target to the sink for detections only.
func detectionTarget(t *testing.T, burst int) string {
	t.Helper()
	out := sh(t, "printf '%s\\n' '"+sinkHook+"' | runuser -u clamfleet-server -- env SUDO_USER="+operator+
		" /usr/local/bin/clamfleet-server alert add-webhook ops --url-stdin --no-state-changes --detection-burst "+strconv.Itoa(burst))
	return strings.TrimSpace(out)
}

// detectionRig brings up the server, the sink, a webhook target for detections,
// a clamd wired to VirusEvent and the agent as a service (30 s report interval).
func detectionRig(t *testing.T, burst int) (key string) {
	t.Helper()
	freshServer(t)
	startSink(t)
	enableVirusEvent(t)
	key = detectionTarget(t, burst)
	startAgentService(t, 30*time.Second)
	waitSpool(t)
	return key
}

// waitSpool waits for the agent service to have created spool/events.
func waitSpool(t *testing.T) {
	t.Helper()
	sh(t, "for _ in $(seq 1 30); do [ -d "+spoolDir+"/events ] && [ -f "+spoolDir+"/usage ] && exit 0; sleep 1; done; journalctl -u "+agentUnit+" --no-pager >&2; echo spool not created >&2; exit 1")
}

// detections decodes the detection lines of the sink, in arrival order.
func detections(t *testing.T) []alert.DetectionPayload {
	t.Helper()
	hooks, _ := readSink(t)
	var out []alert.DetectionPayload
	for _, h := range hooks {
		var p alert.DetectionPayload
		if err := json.Unmarshal([]byte(h.Body), &p); err != nil {
			t.Fatal(err)
		}
		if p.Kind == alert.KindDetection {
			out = append(out, p)
		}
	}
	return out
}

func waitDetection(t *testing.T, path string, within time.Duration) (alert.DetectionPayload, time.Duration, time.Time) {
	t.Helper()
	start := time.Now()
	for {
		for _, d := range detections(t) {
			if d.Path == path {
				return d, time.Since(start), time.Now()
			}
		}
		if time.Since(start) > within {
			t.Fatalf("no detection for %s within %v\nserver journal:\n%s\nagent journal:\n%s\nclamd journal:\n%s", path, within,
				journal(t, serverUnit), journal(t, agentUnit), journal(t, "clamav-daemon"))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// notSpooled returns the lines of clamd's journal that come from the event
// command ("event not spooled: ..."). Only those are checked for the path: clamd
// may log its own FOUND lines there (LogSyslog), which are not ours.
func notSpooled(journalText string) []string {
	var out []string
	for _, l := range strings.Split(journalText, "\n") {
		if strings.Contains(l, "event not spooled") {
			out = append(out, l)
		}
	}
	return out
}

func spoolItems(t *testing.T, sub string) int {
	t.Helper()
	n, _ := strconv.Atoi(sh(t, "ls -A "+spoolDir+"/"+sub+" | grep -vc '^\\.tmp-' || true"))
	return n
}

func waitSpoolEmpty(t *testing.T, sub string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for spoolItems(t, sub) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("spool/%s still holds %d items after %v\nagent journal:\n%s", sub, spoolItems(t, sub), within, journal(t, agentUnit))
		}
		time.Sleep(time.Second)
	}
}

type eventsHost struct {
	EventCount int             `json:"event_count"`
	OpenEvents int             `json:"open_events"`
	LastReport json.RawMessage `json:"last_report"`
}

func eventsOf(t *testing.T) eventsHost {
	t.Helper()
	var h eventsHost
	if err := json.Unmarshal([]byte(srvCLI(t, "host", "show", hostName, "--json")), &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// virusEventOf reads clamd.virus_event from the host's newest report ("" if absent or null).
func virusEventOf(t *testing.T) string {
	t.Helper()
	var r struct {
		Clamd struct {
			VirusEvent *string `json:"virus_event"`
		} `json:"clamd"`
	}
	if raw := eventsOf(t).LastReport; len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
	}
	if r.Clamd.VirusEvent == nil {
		return ""
	}
	return *r.Clamd.VirusEvent
}

// The acceptance: an EICAR file scanned by the real clamd produces an alert
// within 30 s, with the real path and signature, and the spool is empty after.
func TestEICARAlertWithin30s(t *testing.T) {
	key := detectionRig(t, 0)
	writeEICAR(t, "/srv/e2e", "eicar", 1)

	t0 := time.Now()
	code, took, out := scan(t, "/srv/e2e/eicar-1.com")
	if code != 1 || !strings.Contains(out, "FOUND") {
		t.Fatalf("clamdscan exit %d: %s", code, out)
	}
	if took > 5*time.Second {
		t.Fatalf("clamdscan took %v: clamd waits for the event command, which must be fast", took)
	}
	d, _, at := waitDetection(t, "/srv/e2e/eicar-1.com", 30*time.Second)
	latency := at.Sub(t0)
	t.Logf("MEASURED: EICAR scan to alert %v (clamdscan returned in %v)", latency.Round(100*time.Millisecond), took.Round(time.Millisecond))
	if latency > 30*time.Second {
		t.Fatalf("alert after %v, acceptance is 30 s", latency)
	}
	if !strings.Contains(strings.ToUpper(d.Signature), "EICAR") || d.Source != "clamd" || d.Host != hostName {
		t.Fatalf("%+v", d)
	}
	// The signature header verifies with the key the CLI printed.
	hooks, _ := readSink(t)
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(key, "whsec_"))
	for _, h := range hooks {
		ts, _ := strconv.ParseInt(h.Header["Webhook-Timestamp"][0], 10, 64)
		if !alert.VerifySignature(raw, h.Header["Webhook-Id"][0], ts, []byte(h.Body), h.Header["Webhook-Signature"][0]) {
			t.Fatalf("a webhook request does not verify: %v", h.Header)
		}
	}
	waitSpoolEmpty(t, "events", 10*time.Second)
	if h := eventsOf(t); h.EventCount != 1 {
		t.Fatalf("event_count %d, want 1", h.EventCount)
	}
	// The next report carries virus_event "clamfleet": the report interval is 30 s.
	deadline := time.Now().Add(45 * time.Second)
	for virusEventOf(t) != "clamfleet" {
		if time.Now().After(deadline) {
			t.Fatalf("no report with virus_event clamfleet: %s", eventsOf(t).LastReport)
		}
		time.Sleep(2 * time.Second)
	}
}

// Acceptance: the event survives a server outage through the spool. It is
// written with the right owner and modes, delivered once after the restart, with
// ts before the restart and received_at after it.
func TestEventSurvivesServerDowntime(t *testing.T) {
	detectionRig(t, 0)
	writeEICAR(t, "/srv/e2e", "down", 1)
	sh(t, "systemctl stop "+serverUnit)
	if code, took, out := scan(t, "/srv/e2e/down-1.com"); code != 1 || took > 5*time.Second {
		t.Fatalf("scan with the server down: exit %d in %v: %s", code, took, out)
	}
	if n := spoolItems(t, "events"); n != 1 {
		t.Fatalf("%d items in spool/events, want 1", n)
	}
	// Written by clamd's user, group clamav, 0640; the directory is sticky 3770.
	if got := sh(t, "stat -c '%U %G %a' "+spoolDir+"/events/*.json"); got != "clamav clamav 640" {
		t.Fatalf("item owner/mode %q, want 'clamav clamav 640'", got)
	}
	if got := sh(t, "stat -c '%U %G %a' "+spoolDir+"/events"); got != "clamfleet clamav 3770" {
		t.Fatalf("spool/events %q, want 'clamfleet clamav 3770'", got)
	}
	time.Sleep(10 * time.Second)
	if n := spoolItems(t, "events"); n != 1 {
		t.Fatalf("the item left the spool while the server was down: %d", n)
	}
	aj := journal(t, agentUnit)
	if !strings.Contains(aj, `"class":"network"`) || strings.Contains(aj, "down-1.com") {
		t.Fatalf("agent journal (a network failure, never the path):\n%s", aj)
	}
	restartAt := time.Now()
	sh(t, "date +%s > /tmp/restart-at") // container clock, for the comparison below
	startServerUnit(t)
	d, _, _ := waitDetection(t, "/srv/e2e/down-1.com", 40*time.Second)
	ts, _ := time.Parse(time.RFC3339, d.TS)
	recv, _ := time.Parse(time.RFC3339, d.ReceivedAt)
	ra := sh(t, "cat /tmp/restart-at")
	n, _ := strconv.ParseInt(ra, 10, 64)
	restart := time.Unix(n, 0)
	if !ts.Before(restart) || recv.Before(restart) {
		t.Fatalf("ts %v received_at %v restart %v (host clock %v)", ts, recv, restart, restartAt)
	}
	waitSpoolEmpty(t, "events", 10*time.Second)
	time.Sleep(6 * time.Second)
	count := 0
	for _, x := range detections(t) {
		if x.Path == "/srv/e2e/down-1.com" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%d alerts for the detection, want exactly 1", count)
	}
}

// Both the agent and the server are down at the detection; the spool holds it;
// the server comes back, then the agent: delivered.
func TestEventSurvivesAgentAndServerDowntime(t *testing.T) {
	detectionRig(t, 0)
	writeEICAR(t, "/srv/e2e", "both", 1)
	sh(t, "systemctl stop "+agentUnit+" "+serverUnit)
	if code, _, out := scan(t, "/srv/e2e/both-1.com"); code != 1 {
		t.Fatalf("scan: %d %s", code, out)
	}
	if n := spoolItems(t, "events"); n != 1 {
		t.Fatalf("%d items in spool/events, want 1", n)
	}
	startServerUnit(t)
	startAgentService(t, 30*time.Second)
	waitDetection(t, "/srv/e2e/both-1.com", 40*time.Second)
	waitSpoolEmpty(t, "events", 10*time.Second)
}

// 300 detections wait during an outage. After the restart one fresh detection
// alerts within 30 s of its scan, and all 301 arrive.
func TestEICARDuringBacklog(t *testing.T) {
	detectionRig(t, 0)
	writeEICAR(t, "/srv/e2e/backlog", "b", 300)
	writeEICAR(t, "/srv/e2e", "fresh", 1)
	sh(t, "systemctl stop "+serverUnit)
	start := time.Now()
	if code, _, out := scan(t, "--multiscan /srv/e2e/backlog"); code != 1 {
		t.Fatalf("scan: %d %s", code, out)
	}
	t.Logf("MEASURED: 300 detections scanned and spooled in %v", time.Since(start).Round(100*time.Millisecond))
	if n := spoolItems(t, "events"); n != 300 {
		t.Fatalf("%d items spooled, want 300", n)
	}
	startServerUnit(t)
	t0 := time.Now()
	if code, _, out := scan(t, "/srv/e2e/fresh-1.com"); code != 1 {
		t.Fatalf("scan: %d %s", code, out)
	}
	_, _, at := waitDetection(t, "/srv/e2e/fresh-1.com", 30*time.Second)
	t.Logf("MEASURED: fresh detection alerted %v after its scan, behind a 300-event backlog", at.Sub(t0).Round(100*time.Millisecond))
	deadline := time.Now().Add(3 * time.Minute)
	for len(detections(t)) < 301 {
		if time.Now().After(deadline) {
			t.Fatalf("%d of 301 detections arrived", len(detections(t)))
		}
		time.Sleep(2 * time.Second)
	}
	waitSpoolEmpty(t, "events", 20*time.Second)
}

// A mass detection with the default burst of 10: all 200 are stored, exactly 10
// are sent one by one inside the window (the summary is proven with the injected
// clock; W is not shortened here), and the agent stays inside its memory budget.
func TestDetectionBurst(t *testing.T) {
	detectionRig(t, 10)
	writeEICAR(t, "/srv/e2e/burst", "w", 200)
	start := time.Now()
	if code, _, out := scan(t, "--multiscan /srv/e2e/burst"); code != 1 {
		t.Fatalf("scan: %d %s", code, out)
	}
	scanTook := time.Since(start)
	deadline := time.Now().Add(60 * time.Second)
	for eventsOf(t).EventCount < 200 {
		if time.Now().After(deadline) {
			t.Fatalf("%d of 200 events stored after 60 s\nagent journal:\n%s", eventsOf(t).EventCount, journal(t, agentUnit))
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("MEASURED: 200 detections scanned in %v (%v per detection including the VirusEvent), all stored %v after the scan started",
		scanTook.Round(10*time.Millisecond), (scanTook / 200).Round(time.Millisecond), time.Since(start).Round(100*time.Millisecond))
	rss := sh(t, "pid=$(pgrep -f '^/usr/local/bin/clamfleet-agent run' | head -n1); grep VmHWM /proc/$pid/status | awk '{print $2}'")
	kb, _ := strconv.Atoi(rss)
	t.Logf("MEASURED: agent peak RSS (VmHWM) %d kB", kb)
	if kb == 0 || kb > 30*1024 {
		t.Fatalf("agent VmHWM %d kB, want 1 to 30720 (spec 13: 30 MB)", kb)
	}
	time.Sleep(8 * time.Second) // let the dispatcher send what it will
	if n := len(detections(t)); n != 10 {
		t.Fatalf("%d individual detections within the window, want exactly 10 (the rest are held for the summary)", n)
	}
	if n := eventsOf(t).OpenEvents; n != 200 {
		t.Fatalf("%d open events, want 200", n)
	}
}

// The spool filesystem is full: the scan still returns fast, clamd still answers,
// the journal holds one line without the path, and nothing is half written.
func TestEventFullStorage(t *testing.T) {
	freshServer(t)
	startSink(t)
	enableVirusEvent(t)
	detectionTarget(t, 0)
	// A 256 KiB tmpfs under the whole spool, mounted before the agent service
	// creates its layout there (rename across filesystems would not work for
	// the quarantine, and a real disk fills as a whole anyway).
	sh(t, "mount -t tmpfs -o size=256k,mode=2750,uid=$(id -u clamfleet),gid=$(id -g clamav) tmpfs "+spoolDir)
	startAgentService(t, 30*time.Second)
	waitSpool(t)
	sh(t, "dd if=/dev/zero of="+spoolDir+"/events/filler bs=1k count=400 2>/dev/null || true; df -k "+spoolDir+" | tail -1")
	writeEICAR(t, "/srv/e2e", "full", 1)
	code, took, out := scan(t, "/srv/e2e/full-1.com")
	if code != 1 || took > 5*time.Second {
		t.Fatalf("scan on a full spool: exit %d in %v: %s", code, took, out)
	}
	if _, _, c := ct(t.Context(), []byte("clamdscan --ping 3\n"), "bash", "-s"); c != 0 {
		t.Fatal("clamd stopped answering")
	}
	cj := journal(t, "clamav-daemon")
	if lines := notSpooled(cj); len(lines) != 1 || strings.Contains(lines[0], "/srv/e2e/") {
		t.Fatalf("clamd journal must hold exactly one line of ours, with no path: %q\n%s", lines, cj)
	}
	time.Sleep(5 * time.Second) // a run pass
	if n := sh(t, "find "+spoolDir+" -name '.tmp-*' | wc -l"); n != "0" {
		t.Fatalf("%s temp files left after the full-storage failure", n)
	}
	if n := len(detections(t)); n != 0 {
		t.Fatalf("%d detections reached the sink although nothing could be spooled", n)
	}
}

// The agent user cannot be reached by clamd's user: spool/events lost its sticky
// bit and group mode, so `event` refuses (it will not write into a directory it
// cannot vouch for), says so once, and clamd carries on.
func TestEventWithoutSpoolAccess(t *testing.T) {
	detectionRig(t, 0)
	writeEICAR(t, "/srv/e2e", "noaccess", 1)
	sh(t, "chmod 0750 "+spoolDir+"/events")
	code, took, out := scan(t, "/srv/e2e/noaccess-1.com")
	if code != 1 || took > 5*time.Second {
		t.Fatalf("scan: exit %d in %v: %s", code, took, out)
	}
	if _, _, c := ct(t.Context(), []byte("clamdscan --ping 3\n"), "bash", "-s"); c != 0 {
		t.Fatal("clamd stopped answering")
	}
	cj := journal(t, "clamav-daemon")
	if lines := notSpooled(cj); len(lines) != 1 || strings.Contains(lines[0], "/srv/e2e/") || !strings.Contains(lines[0], "not a directory owned by the agent") {
		t.Fatalf("clamd journal must hold exactly one line of ours, with no path: %q\n%s", lines, cj)
	}
	if n := spoolItems(t, "events"); n != 0 {
		t.Fatalf("%d items spooled into a directory the event command refused", n)
	}
	sh(t, "chmod 3770 "+spoolDir+"/events")
}

// An agent.yaml that clamd's user cannot read: nothing is spooled anywhere (no
// fallback to a default directory), and the journal names the file.
func TestEventUnreadableConfig(t *testing.T) {
	detectionRig(t, 0)
	writeEICAR(t, "/srv/e2e", "badcfg", 1)
	sh(t, "chmod 0600 /etc/clamfleet/agent.yaml")
	code, took, out := scan(t, "/srv/e2e/badcfg-1.com")
	if code != 1 || took > 5*time.Second {
		t.Fatalf("scan: exit %d in %v: %s", code, took, out)
	}
	if _, _, c := ct(t.Context(), []byte("clamdscan --ping 3\n"), "bash", "-s"); c != 0 {
		t.Fatal("clamd stopped answering")
	}
	cj := journal(t, "clamav-daemon")
	if lines := notSpooled(cj); len(lines) != 1 || !strings.Contains(lines[0], "cannot read config /etc/clamfleet/agent.yaml: permission denied") || strings.Contains(lines[0], "/srv/e2e/") {
		t.Fatalf("clamd journal must hold exactly one line of ours, naming the config and no path: %q\n%s", lines, cj)
	}
	// Nothing in events/ and nothing in any other directory of the default spool either.
	if n := sh(t, "find /var/lib/clamfleet -type f \\( -name '*.json' -o -name '.tmp-*' \\) ! -path '*/reports/*' | wc -l"); n != "0" {
		t.Fatalf("%s spooled files after an unreadable config", n)
	}
	sh(t, "chmod 0644 /etc/clamfleet/agent.yaml")
}
