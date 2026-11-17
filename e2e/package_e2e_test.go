//go:build e2e

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// The packages, for real: the .deb files are installed in the
// clamfleet-test container with apt, started by systemd under their hardening, upgraded and
// removed. `make e2e` builds them first (`make packages VERSION=0.6.0-e2e1`); a missing
// package fails the suite, it never skips.
//
// Every scenario starts from the container's clean snapshot with NOTHING of ours in it:
// the package creates the users, directories, units and the key file, and the test then
// does what the install notice tells an administrator to do (a host, a token, the
// VirusEvent line). The earlier suites run from bare binaries and keep doing so.
//
// The failed upgrade (an unwritable backup.dir before an upgrade that brings a migration) uses a
// test-only migration overlay behind the e2e_migration build tag (migrations/e2e_overlay.go): the
// "new" package is built with it, so the two packages differ by one schema change.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	pkgVersionOld = "0.6.0-e2e1"
	pkgVersionNew = "0.6.0-e2e2"
	// the Debian form of the versions (a pre-release becomes ~ in a deb)
	debOld = "0.6.0~e2e1"
	debNew = "0.6.0~e2e2"
)

// debFile returns the path of a built package, failing when it is missing.
func debFile(t *testing.T, dir, name, version string) string {
	t.Helper()
	p := filepath.Join(dir, fmt.Sprintf("%s_%s_amd64.deb", name, version))
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("package %s is missing (run `make packages VERSION=%s`): %v", p, pkgVersionOld, err)
	}
	return p
}

// pushPackages copies files into /root/pkgs in the container.
func pushPackages(t *testing.T, paths ...string) {
	t.Helper()
	files := map[string][]byte{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		files[filepath.Base(p)] = b
	}
	var tarball bytes.Buffer
	if err := writeTarFiles(&tarball, files); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	sh(t, "mkdir -p /root/pkgs")
	if _, e, code := ct(ctx, tarball.Bytes(), "tar", "-xf", "-", "-C", "/root/pkgs", "--no-same-owner"); code != 0 {
		t.Fatalf("pushing packages: exit %d: %s", code, e)
	}
}

// aptInstall installs local .deb files (already pushed) and returns apt's output.
func aptInstall(t *testing.T, names ...string) string {
	t.Helper()
	args := ""
	for _, n := range names {
		args += " /root/pkgs/" + n
	}
	return sh(t, "DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confold"+args+" 2>&1")
}

// freshBare returns the container to its clean snapshot with nothing of ours in it.
func freshBare(t *testing.T) {
	t.Helper()
	if err := script("reset.sh"); err != nil {
		t.Fatal(err)
	}
	waitClamd(t)
}

// installOld resets the container and installs the e2e1 agent and server packages.
func installOld(t *testing.T) {
	t.Helper()
	freshBare(t)
	dist := filepath.Join(repoRoot, "dist")
	agent, server := debFile(t, dist, "clamfleet-agent", debOld), debFile(t, dist, "clamfleet-server", debOld)
	pushPackages(t, agent, server)
	aptInstall(t, filepath.Base(server), filepath.Base(agent))
	waitServerHealthy(t)
}

const (
	pkgServer = "/usr/bin/clamfleet-server"
	pkgAgent  = "/usr/bin/clamfleet-agent"
)

// pkgCLI runs the packaged admin CLI as the server user.
func pkgCLI(t *testing.T, args ...string) string {
	t.Helper()
	return sh(t, "runuser -u clamfleet-server -- env SUDO_USER="+operator+" "+pkgServer+" "+strings.Join(args, " "))
}

// sedConfig edits a file and fails when the pattern changed nothing, so a drifted example
// config cannot silently leave a test running on defaults.
func sedConfig(t *testing.T, file, expr string) {
	t.Helper()
	sh(t, "cp "+file+" /tmp/before.yaml; sed -i '"+expr+"' "+file+"; if cmp -s /tmp/before.yaml "+file+"; then echo 'sed changed nothing: "+expr+"' >&2; exit 1; fi")
}

// waitServerHealthy waits until the packaged server answers GET /healthz with 200, for at most 30 s,
// and fails with the unit's journal otherwise. It replaces `systemctl is-active`: the unit is Type=simple,
// so it is "active" from the exec, before the database is migrated and the port is bound, and a curl
// right after that was refused (exit 7), which failed TestMetricsScrape about 1 run in 10. Type=notify
// would fix it in the unit but its start timeout would include the pre-migration backup (milestone 6c,
// decision 17), so the readiness check stays here.
func waitServerHealthy(t *testing.T) {
	t.Helper()
	sh(t, "for _ in $(seq 1 60); do "+
		"[ \"$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8443/healthz || true)\" = 200 ] && exit 0; sleep 0.5; done; "+
		"journalctl -u clamfleet-server --no-pager >&2; echo 'server did not answer /healthz within 30 s' >&2; exit 1")
}

func restartServer(t *testing.T) {
	t.Helper()
	sh(t, "systemctl restart clamfleet-server")
	waitServerHealthy(t)
}

// registerAgent does what the install notice says: a host on the server, its token in a
// root:clamfleet 0640 file, the server URL (loopback plaintext: the packaged default
// server), then starts the agent service.
func registerAgent(t *testing.T) {
	t.Helper()
	tok := pkgCLI(t, "host", "add", hostName)
	writeToken(t, tok)
	sedConfig(t, "/etc/clamfleet/agent.yaml", "s|^server:.*|server: http://127.0.0.1:8443|")
	sh(t, "systemctl start clamfleet-agent")
}

// packagedHost is host show for the packaged server.
func packagedHost(t *testing.T, name string) eventsHost {
	t.Helper()
	var h eventsHost
	if err := json.Unmarshal([]byte(pkgCLI(t, "host", "show", name, "--json")), &h); err != nil {
		t.Fatal(err)
	}
	return h
}

func waitReport(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		var h struct {
			ReportCount int     `json:"report_count"`
			State       *string `json:"state"`
		}
		if json.Unmarshal([]byte(pkgCLI(t, "host", "show", hostName, "--json")), &h) == nil && h.ReportCount > 0 && h.State != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no report with a state within %v\nagent journal:\n%s\nserver journal:\n%s", within, journal(t, "clamfleet-agent"), journal(t, "clamfleet-server"))
		}
		time.Sleep(time.Second)
	}
}

func noErrorLines(t *testing.T, units ...string) {
	t.Helper()
	for _, u := range units {
		if n := sh(t, "journalctl -u "+u+" -o cat --no-pager -q | grep -c '\"level\":\"ERROR\"' || true"); n != "0" {
			t.Errorf("%s logged %s error lines:\n%s", u, n, journal(t, u))
		}
	}
}

// The acceptance: both packages install, the server starts and listens on loopback only,
// the agent waits for its token (condition failed, not a restart loop), and after the
// documented first steps the host reports.
func TestDebInstallAndStart(t *testing.T) {
	installOld(t)

	waitServerHealthy(t)
	listeners := sh(t, "ss -ltnH | awk '{print $4}' | grep ':8443$' || true")
	if listeners != "127.0.0.1:8443" {
		t.Fatalf("the server listens on %q, want 127.0.0.1:8443 only", listeners)
	}

	// Users, groups, modes: the milestone 5 spool modes, the key file, the configuration.
	if g := sh(t, "id -nG clamfleet"); !strings.Contains(" "+g+" ", " clamav ") || !strings.Contains(" "+g+" ", " systemd-journal ") {
		t.Fatalf("clamfleet is in groups %q, want clamav and systemd-journal", g)
	}
	for path, want := range map[string]string{
		"/var/lib/clamfleet":               "750 clamfleet:clamav",
		"/var/lib/clamfleet/spool":         "2750 clamfleet:clamav",
		"/var/lib/clamfleet-server":        "700 clamfleet-server:clamfleet-server",
		"/etc/clamfleet/server-secret.key": "640 root:clamfleet-server",
		"/etc/clamfleet/server.yaml":       "640 root:clamfleet-server",
		"/etc/clamfleet/agent.yaml":        "644 root:root",
	} {
		if got := sh(t, "stat -c '%a %U:%G' "+path); got != want {
			t.Errorf("%s is %s, want %s", path, got, want)
		}
	}

	// The agent has no token yet: inactive with an unmet condition, not failed.
	st := sh(t, "systemctl show -p ActiveState,Result,ConditionResult clamfleet-agent")
	for _, want := range []string{"ActiveState=inactive", "Result=success", "ConditionResult=no"} {
		if !strings.Contains(st, want) {
			t.Fatalf("agent without a token: %s, want %s", st, want)
		}
	}

	registerAgent(t)
	waitReport(t, 30*time.Second)

	for _, tm := range []string{"clamfleet-scan.timer", "clamfleet-server-backup.timer"} {
		if got := sh(t, "systemctl is-enabled "+tm+" || true"); got != "disabled" {
			t.Errorf("%s is %q, want disabled (it ships disabled)", tm, got)
		}
	}
	noErrorLines(t, "clamfleet-server", "clamfleet-agent")
}

// packagedDetectionRig installs, registers the agent, starts the sink, lets the server reach
// it (loopback is off by default) and wires clamd with the VirusEvent line the notice gives.
func packagedDetectionRig(t *testing.T) {
	t.Helper()
	installOld(t)
	startSink(t)
	sedConfig(t, "/etc/clamfleet/server.yaml", "s/allow_loopback: false/allow_loopback: true/")
	restartServer(t)
	sh(t, "printf '%s\\n' '"+sinkHook+"' | runuser -u clamfleet-server -- env SUDO_USER="+operator+" "+pkgServer+" alert add-webhook ops --url-stdin --no-state-changes --detection-burst 0")
	registerAgent(t)
	sh(t, "echo 'VirusEvent "+pkgAgent+" event' >> /etc/clamav/clamd.conf; systemctl restart clamav-daemon")
	waitClamd(t)
	waitSpool(t)
	waitReport(t, 30*time.Second)
}

// This is the test that a 0640 agent.yaml would have failed: the event command runs as
// clamd's user, reads agent.yaml with no fallback, and spools nothing if it cannot. After
// a packaged install, an EICAR scan reaches the sink and clamd's journal has no line from us.
func TestDebDetectionThroughPackagedAgent(t *testing.T) {
	packagedDetectionRig(t)
	if got := sh(t, "stat -c '%a %U:%G' /etc/clamfleet/agent.yaml /etc/clamfleet/token"); got != "644 root:root\n640 root:clamfleet" {
		t.Fatalf("modes: %q, want agent.yaml 644 root:root and token 640 root:clamfleet", got)
	}
	writeEICAR(t, "/srv/e2e", "eicar", 1)
	code, _, out := scan(t, "/srv/e2e/eicar-1.com")
	if code != 1 || !strings.Contains(out, "FOUND") {
		t.Fatalf("clamdscan exit %d: %s", code, out)
	}
	d, _, _ := waitDetection(t, "/srv/e2e/eicar-1.com", 30*time.Second)
	if !strings.Contains(d.Signature, "Eicar") {
		t.Fatalf("detection %+v", d)
	}
	if lines := notSpooled(journal(t, "clamav-daemon")); len(lines) != 0 {
		t.Fatalf("clamd's journal holds lines from our command: %q", lines)
	}
}

// The scheduled scan: the timer's service runs clamdscan on scan.paths, exits 1 on an
// infection, writes last_scan.json (carried by the next report), and the detection itself
// arrives through VirusEvent. With clamd stopped the service fails and does NOT start clamd,
// socket unit included.
func TestScanTimerRun(t *testing.T) {
	packagedDetectionRig(t)
	sedConfig(t, "/etc/clamfleet/agent.yaml", "s|^scan:.*|scan: {paths: [/srv/e2e], summary: /var/lib/clamfleet/last_scan.json}|")
	writeEICAR(t, "/srv/e2e", "eicar", 1)
	sh(t, "systemctl start clamfleet-scan.service || true")
	if st := sh(t, "systemctl show -p Result,ExecMainStatus clamfleet-scan.service"); !strings.Contains(st, "ExecMainStatus=1") || !strings.Contains(st, "Result=exit-code") {
		t.Fatalf("scan service: %s, want exit status 1 (infected)\n%s", st, journal(t, "clamfleet-scan"))
	}
	var s struct {
		Exit     int   `json:"exit"`
		Infected int64 `json:"infected"`
	}
	if err := json.Unmarshal([]byte(sh(t, "cat /var/lib/clamfleet/last_scan.json")), &s); err != nil || s.Infected != 1 || s.Exit != 1 {
		t.Fatalf("last_scan.json: %+v %v", s, err)
	}
	waitDetection(t, "/srv/e2e/eicar-1.com", 30*time.Second)
	sh(t, "systemctl restart clamfleet-agent")
	deadline := time.Now().Add(30 * time.Second)
	for {
		var r struct {
			LastReport struct {
				LastScan *struct {
					Infected int64 `json:"infected"`
				} `json:"last_scan"`
			} `json:"last_report"`
		}
		if json.Unmarshal([]byte(pkgCLI(t, "host", "show", hostName, "--json")), &r) == nil && r.LastReport.LastScan != nil && r.LastReport.LastScan.Infected == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the report never carried last_scan")
		}
		time.Sleep(time.Second)
	}

	// clamd down: the scan fails, clamd stays down, the summary is untouched.
	before := sh(t, "cat /var/lib/clamfleet/last_scan.json")
	sh(t, "systemctl stop clamav-daemon clamav-daemon.socket")
	sh(t, "systemctl start clamfleet-scan.service || true")
	if st := sh(t, "systemctl show -p Result,ExecMainStatus clamfleet-scan.service"); !strings.Contains(st, "ExecMainStatus=2") {
		t.Fatalf("scan with clamd down: %s, want exit status 2", st)
	}
	for _, u := range []string{"clamav-daemon", "clamav-daemon.socket"} {
		if got := sh(t, "systemctl is-active "+u+" || true"); got != "inactive" {
			t.Fatalf("%s is %q after a scan with clamd down: the scan started it", u, got)
		}
	}
	if after := sh(t, "cat /var/lib/clamfleet/last_scan.json"); after != before {
		t.Fatal("the summary changed although no scan ran")
	}
}

// The retention acceptance: stop the packaged server, put the hack/seeddb database in place,
// set retention.reports_days: 14, start: the journal holds the pruned counts and host show
// the expected report count.
func TestOldRowsRemovedPerConfig(t *testing.T) {
	installOld(t)
	out := filepath.Join(t.TempDir(), "seeddb")
	if err := build(out, "hack/seeddb"); err != nil {
		t.Fatal(err)
	}
	pushBinary(t, out, "seeddb")
	sh(t, "systemctl stop clamfleet-server")
	manifest := sh(t, "rm -f /tmp/seed.db; /usr/local/bin/seeddb --db /tmp/seed.db --now \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"")
	var m struct {
		AfterReports14 struct {
			Reports int `json:"reports"`
		} `json:"after_reports_days_14"`
	}
	if err := json.Unmarshal([]byte(manifest), &m); err != nil {
		t.Fatal(err)
	}
	sh(t, "rm -f /var/lib/clamfleet-server/clamfleet.db*; install -o clamfleet-server -g clamfleet-server -m 600 /tmp/seed.db /var/lib/clamfleet-server/clamfleet.db; rm /tmp/seed.db")
	sedConfig(t, "/etc/clamfleet/server.yaml", "s/^  reports_days: 30 /  reports_days: 14 /")
	sh(t, "systemctl start clamfleet-server")
	sh(t, "for _ in $(seq 1 30); do journalctl -u clamfleet-server -o cat --no-pager -q | grep -q 'old audit rows pruned' && exit 0; sleep 1; done; journalctl -u clamfleet-server --no-pager >&2; exit 1")
	j := journal(t, "clamfleet-server")
	for _, msg := range []string{"old reports pruned", "old events pruned", "old state changes pruned", "old alert history pruned"} {
		if !strings.Contains(j, msg) {
			t.Errorf("no %q line:\n%s", msg, j)
		}
	}
	var h struct {
		ReportCount int `json:"report_count"`
	}
	if err := json.Unmarshal([]byte(pkgCLI(t, "host", "show", "seed01", "--json")), &h); err != nil || h.ReportCount != m.AfterReports14.Reports {
		t.Fatalf("report_count %d (%v), want %d", h.ReportCount, err, m.AfterReports14.Reports)
	}
	if strings.Contains(j, "/srv/seed") {
		t.Fatal("a path reached the journal")
	}
}

// /metrics through the packaged server: off by default, 200 with the token and 401 without.
func TestMetricsScrape(t *testing.T) {
	installOld(t)
	registerAgent(t)
	waitReport(t, 30*time.Second)
	curl := func(auth string) string {
		h := ""
		if auth != "" {
			h = " -H 'Authorization: Bearer " + auth + "'"
		}
		return sh(t, "curl -s -o /tmp/m.out -w '%{http_code}'"+h+" http://127.0.0.1:8443/metrics")
	}
	if got := curl(""); got != "404" {
		t.Fatalf("metrics are off by default: got %s, want 404", got)
	}
	sh(t, "head -c 48 /dev/urandom | base64 -w0 > /etc/clamfleet/metrics-token; chown root:clamfleet-server /etc/clamfleet/metrics-token; chmod 640 /etc/clamfleet/metrics-token")
	sedConfig(t, "/etc/clamfleet/server.yaml", `/^metrics:/,/^[a-z]/ {s/enabled: false/enabled: true/; s|token_file: ""|token_file: /etc/clamfleet/metrics-token|}`)
	restartServer(t)
	if got := curl(""); got != "401" {
		t.Fatalf("without the token: %s, want 401", got)
	}
	tok := sh(t, "cat /etc/clamfleet/metrics-token")
	if got := curl(tok); got != "200" {
		t.Fatalf("with the token: %s, want 200", got)
	}
	if body := sh(t, "cat /tmp/m.out"); !strings.Contains(body, "clamfleet_hosts{state=") || !strings.Contains(body, `host="`+hostName+`"`) {
		t.Fatalf("metrics body:\n%s", body)
	}
}

// Upgrade: the configuration edit, the key file, the host and its data survive; the
// service restarts (server and agent).
func TestDebUpgradeKeepsConfigAndData(t *testing.T) {
	installOld(t)
	registerAgent(t)
	waitReport(t, 30*time.Second)
	sedConfig(t, "/etc/clamfleet/server.yaml", "s/^  audit_days: 365 /  audit_days: 120 /")
	restartServer(t)
	keyBefore := sh(t, "sha256sum /etc/clamfleet/server-secret.key")
	pidBefore := sh(t, "systemctl show -p MainPID --value clamfleet-server")
	agentPidBefore := sh(t, "systemctl show -p MainPID --value clamfleet-agent")

	dir := t.TempDir()
	cmd := exec.Command("make", "-C", repoRoot, "packages", "VERSION="+pkgVersionNew, "PKG_DIR="+dir)
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make packages (e2e2): %v\n%s", err, o)
	}
	agent, server := debFile(t, dir, "clamfleet-agent", debNew), debFile(t, dir, "clamfleet-server", debNew)
	pushPackages(t, agent, server)
	out := aptInstall(t, filepath.Base(server), filepath.Base(agent))
	if !strings.Contains(out, "Unpacking clamfleet-server ("+debNew+") over ("+debOld+")") {
		t.Fatalf("not an upgrade:\n%s", out)
	}

	if got := sh(t, "grep -c '^  audit_days: 120 ' /etc/clamfleet/server.yaml"); got != "1" {
		t.Fatal("the upgrade lost the edit in server.yaml")
	}
	if got := sh(t, "sha256sum /etc/clamfleet/server-secret.key"); got != keyBefore {
		t.Fatal("the key file changed in an upgrade")
	}
	if got := sh(t, "stat -c '%a %U:%G' /etc/clamfleet/server.yaml"); got != "640 root:clamfleet-server" {
		t.Fatalf("server.yaml is %s after the upgrade, want 640 root:clamfleet-server", got)
	}
	for unit, before := range map[string]string{"clamfleet-server": pidBefore, "clamfleet-agent": agentPidBefore} {
		after := sh(t, "systemctl show -p MainPID --value "+unit)
		if after == before || after == "0" {
			t.Errorf("%s was not restarted by the upgrade (pid %s before, %s after)", unit, before, after)
		}
	}
	if h := packagedHost(t, hostName); h.EventCount != 0 {
		t.Fatalf("%+v", h)
	}
	if sh(t, "runuser -u clamfleet-server -- "+pkgServer+" host list | grep -c "+hostName) != "1" {
		t.Fatal("the host is gone after the upgrade")
	}
	noErrorLines(t, "clamfleet-server")
}

// Removal and purge: the units go, the server's database and key file STAY (also after a
// purge), and the purge says so; the agent's state directory goes on purge.
func TestDebRemoveAndPurge(t *testing.T) {
	installOld(t)
	registerAgent(t)
	waitReport(t, 30*time.Second)

	sh(t, "DEBIAN_FRONTEND=noninteractive apt-get remove -y clamfleet-agent clamfleet-server 2>&1")
	for _, u := range []string{"clamfleet-agent.service", "clamfleet-server.service", "clamfleet-scan.timer", "clamfleet-server-backup.timer"} {
		if got := sh(t, "ls /usr/lib/systemd/system/"+u+" 2>&1 | grep -c 'No such file' || true"); got != "1" {
			t.Errorf("unit file %s is still installed after remove", u)
		}
	}
	if got := sh(t, "systemctl is-active clamfleet-server || true"); got == "active" {
		t.Fatal("the server is still running after remove")
	}
	sh(t, "test -f /var/lib/clamfleet-server/clamfleet.db")

	sh(t, "DEBIAN_FRONTEND=noninteractive apt-get purge -y clamfleet-agent 2>&1")
	sh(t, "test ! -e /var/lib/clamfleet")
	out := sh(t, "DEBIAN_FRONTEND=noninteractive apt-get purge -y clamfleet-server 2>&1")
	if !strings.Contains(out, "were NOT removed") {
		t.Fatalf("the purge did not say where the data is:\n%s", out)
	}
	sh(t, "test -f /var/lib/clamfleet-server/clamfleet.db && test -f /etc/clamfleet/server-secret.key")
}

// Purge never crosses a mount point, and with one inside it removes nothing and names it: a tmpfs mounted at spool/events (as in the full-storage
// scenario of milestone 5) with a marker file survives the purge, and the notice names it.
func TestDebPurgeAcrossAMount(t *testing.T) {
	installOld(t)
	sh(t, "mkdir -p /var/lib/clamfleet/spool/events; mount -t tmpfs -o size=1m tmpfs /var/lib/clamfleet/spool/events; echo keep > /var/lib/clamfleet/spool/events/marker; echo gone > /var/lib/clamfleet/last_scan.json")
	out := sh(t, "DEBIAN_FRONTEND=noninteractive apt-get purge -y clamfleet-agent 2>&1")
	defer sh(t, "umount /var/lib/clamfleet/spool/events || true")
	if got := sh(t, "cat /var/lib/clamfleet/spool/events/marker"); got != "keep" {
		t.Fatalf("the file inside the mount did not survive the purge: %q", got)
	}
	if !strings.Contains(out, "it holds or is a mount point") || !strings.Contains(out, "/var/lib/clamfleet/spool/events") {
		t.Fatalf("the notice does not name the mount:\n%s", out)
	}
	// With a mount inside, the purge removes NOTHING (it never walks a tree it cannot fully leave).
	sh(t, "test -f /var/lib/clamfleet/last_scan.json")
}

// A failed upgrade leaves the data alone. The "new" package is built with the test-only
// migration overlay (-tags e2e_migration, migrations/e2e_overlay.go), so upgrading to it means a schema
// change. The backup directory is unwritable when the upgrade restarts the server, so the backup before the
// migration fails and the server must: refuse to migrate (schema unchanged), prune NOTHING (the seeded
// rows are older than the default retention, which the server was running with a long retention to
// prove the baseline), restart in the loop Restart=on-failure gives it, and recover by itself once the
// directory is fixed, with a pre-migrate backup.
func TestDebFailedUpgradeLeavesDataAlone(t *testing.T) {
	installOld(t)
	seed := filepath.Join(t.TempDir(), "seeddb")
	if err := build(seed, "hack/seeddb"); err != nil {
		t.Fatal(err)
	}
	pushBinary(t, seed, "seeddb")
	sh(t, "systemctl stop clamfleet-server")
	sh(t, "rm -f /tmp/seed.db; /usr/local/bin/seeddb --db /tmp/seed.db --now \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" >/dev/null; "+
		"rm -f /var/lib/clamfleet-server/clamfleet.db*; install -o clamfleet-server -g clamfleet-server -m 600 /tmp/seed.db /var/lib/clamfleet-server/clamfleet.db; rm /tmp/seed.db")
	// A long retention while the old server runs: the first pass prunes nothing, so every seeded row exists.
	for _, e := range []string{
		"s/^  reports_days: 30 /  reports_days: 90 /", "s/^  events_days: 365 /  events_days: 3650 /",
		"s/^  state_changes_days: 365 /  state_changes_days: 3650 /", "s/^  alert_log_days: 90 /  alert_log_days: 3650 /",
		"s/^  audit_days: 365 /  audit_days: 3650 /",
	} {
		sedConfig(t, "/etc/clamfleet/server.yaml", e)
	}
	sh(t, "systemctl start clamfleet-server")
	waitServerHealthy(t)
	var before struct {
		ReportCount int `json:"report_count"`
		EventCount  int `json:"event_count"`
	}
	if err := json.Unmarshal([]byte(pkgCLI(t, "host", "show", "seed01", "--json")), &before); err != nil || before.ReportCount != 4 || before.EventCount != 3 {
		t.Fatalf("baseline with the long retention: %+v %v, want 4 reports and 3 events", before, err)
	}
	if n := sh(t, "journalctl -u clamfleet-server -o cat --no-pager -q | grep -c 'pruned' || true"); n != "0" {
		t.Fatalf("the baseline pass pruned something (%s lines)", n)
	}
	// Back to the default retention WITHOUT restarting, and an unwritable backup directory.
	for _, e := range []string{
		"s/^  reports_days: 90 /  reports_days: 30 /", "s/^  events_days: 3650 /  events_days: 365 /",
		"s/^  state_changes_days: 3650 /  state_changes_days: 365 /", "s/^  alert_log_days: 3650 /  alert_log_days: 90 /",
		"s/^  audit_days: 3650 /  audit_days: 365 /",
	} {
		sedConfig(t, "/etc/clamfleet/server.yaml", e)
	}
	sh(t, "install -d -o clamfleet-server -g clamfleet-server -m 0500 /var/lib/clamfleet-server/backups")

	dir := t.TempDir()
	cmd := exec.Command("make", "-C", repoRoot, "packages", "VERSION="+pkgVersionNew, "PKG_DIR="+dir, "E2E_BUILD_TAGS=e2e_migration")
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make packages (e2e2 with the overlay): %v\n%s", err, o)
	}
	agent, server := debFile(t, dir, "clamfleet-agent", debNew), debFile(t, dir, "clamfleet-server", debNew)
	pushPackages(t, agent, server)
	out := aptInstall(t, filepath.Base(server), filepath.Base(agent))
	if !strings.Contains(out, "Unpacking clamfleet-server ("+debNew+") over ("+debOld+")") {
		t.Fatalf("not an upgrade:\n%s", out)
	}

	// The restarted server refuses to migrate and keeps restarting (Restart=on-failure).
	sh(t, "for _ in $(seq 1 40); do [ \"$(systemctl show -p NRestarts --value clamfleet-server)\" -ge 1 ] && exit 0; sleep 1; done; journalctl -u clamfleet-server --no-pager >&2; exit 1")
	j := journal(t, "clamfleet-server")
	if !strings.Contains(j, "the migration was not run") {
		t.Fatalf("the server did not refuse the migration:\n%s", j)
	}
	if strings.Contains(j, "old reports pruned") || strings.Contains(j, "old audit rows pruned") {
		t.Fatalf("a retention prune ran although the backup failed:\n%s", j)
	}
	// The schema is unchanged: the new binary says the database is out of date.
	if got := sh(t, "runuser -u clamfleet-server -- "+pkgServer+" host list 2>&1 || true"); !strings.Contains(got, "out of date") {
		t.Fatalf("the database does not look un-migrated: %s", got)
	}
	if n := sh(t, "ls /var/lib/clamfleet-server/backups | grep -c pre-migrate || true"); n != "0" {
		t.Fatalf("%s pre-migrate backups exist although the directory was unwritable", n)
	}

	// Fix the directory: the next restart succeeds with a backup, migrates, and only now prunes.
	sh(t, "chmod 0700 /var/lib/clamfleet-server/backups; systemctl reset-failed clamfleet-server || true; systemctl restart clamfleet-server")
	sh(t, "for _ in $(seq 1 30); do journalctl -u clamfleet-server -o cat --no-pager -q | grep -q 'old audit rows pruned' && exit 0; sleep 1; done; journalctl -u clamfleet-server --no-pager >&2; exit 1")
	// The old package is at the newest production migration and the overlay adds exactly one: derive the
	// versions from the migration files, so the next real migration does not break this test again.
	files, err := filepath.Glob(filepath.Join(repoRoot, "migrations", "sqlite", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("cannot count the migrations: %v", err)
	}
	wantName := fmt.Sprintf("pre-migrate-v%d-to-v%d-", len(files), len(files)+1)
	if n := sh(t, "ls /var/lib/clamfleet-server/backups | grep -c '^"+wantName+"' || true"); n != "1" {
		t.Fatalf("want one %s backup, got %s", wantName, n)
	}
	j = journal(t, "clamfleet-server")
	for _, msg := range []string{"old reports pruned", "old events pruned", "old state changes pruned", "old alert history pruned"} {
		if !strings.Contains(j, msg) {
			t.Errorf("no %q line after recovery (the old rows were gone before): %s", msg, j)
		}
	}
	var after struct {
		ReportCount int `json:"report_count"`
		EventCount  int `json:"event_count"`
	}
	if err := json.Unmarshal([]byte(pkgCLI(t, "host", "show", "seed01", "--json")), &after); err != nil || after.ReportCount != 3 || after.EventCount != 2 {
		t.Fatalf("after recovery: %+v %v, want 3 reports and 2 events (the old rows pruned only now)", after, err)
	}
}
