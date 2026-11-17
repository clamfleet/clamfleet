//go:build e2e && e2e_el9

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// RHEL 9 and SELinux (M5 decision 7 moved it to milestone 6), run in the
// throwaway AlmaLinux 9 VM by `make e2e-el9`: the .rpm files are installed with dnf, SELinux is
// Enforcing, clamd runs in antivirus_t, and the event command has to write its spool through the
// module the package loads. A container cannot test any of this: it shares the Debian host's
// kernel, which has no SELinux.
//
// Same helpers and TestMain as the container suite; the environment points them at the VM
// (CFT_EXEC=$CFE_EXEC, INCUS_HOST=$CFE_HOST, CT=clamfleet-el9, SNAP=clean, READY_FILE under
// /var/lib/clamav), so every scenario starts from the VM's `clean` snapshot. Needs both build
// tags. A missing CFE_EXEC fails the target, it never skips.
//
// The claim this proves is "tested on AlmaLinux 9", not RHEL itself (RHEL needs a subscription).
//
// EICAR files live in /var/lib/clamav/e2e: the harness's own domain cannot hand clamd a path
// under /srv (clamdscan reports "Can't access file"), and antivirus_db_t is readable by clamd.
package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

const elDir = "/var/lib/clamav/e2e"

func rpmFile(t *testing.T, dir, name, version string) string {
	t.Helper()
	p := filepath.Join(dir, fmt.Sprintf("%s-%s-1.x86_64.rpm", name, version))
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("package %s is missing (run `make packages VERSION=%s`): %v", p, pkgVersionOld, err)
	}
	return p
}

// el9Fresh restores the VM, installs both packages (el9-prepare.sh) and returns once clamd scans.
func el9Fresh(t *testing.T) {
	t.Helper()
	if err := script("reset.sh"); err != nil {
		t.Fatal(err)
	}
	dist := filepath.Join(repoRoot, "dist")
	os.Setenv("CF_AGENT_RPM", rpmFile(t, dist, "clamfleet-agent", debOld))
	os.Setenv("CF_SERVER_RPM", rpmFile(t, dist, "clamfleet-server", debOld))
	if err := script("el9-prepare.sh"); err != nil {
		t.Fatal(err)
	}
	waitClamd(t)
}

// el9Registered starts the packaged server (the rpm follows the preset: disabled), registers
// the host and starts the packaged agent.
func el9Registered(t *testing.T) {
	t.Helper()
	sh(t, "systemctl enable --now clamfleet-server")
	waitServerHealthy(t)
	registerAgent(t)
	waitReport(t, 30*time.Second)
}

// el9Rig is el9Fresh plus the server, the agent, the sink and a detection target.
func el9Rig(t *testing.T) {
	t.Helper()
	el9Fresh(t)
	startSink(t)
	sedConfig(t, "/etc/clamfleet/server.yaml", "s/allow_loopback: false/allow_loopback: true/")
	el9Registered(t)
	sedConfigRestartServerAndTarget(t)
	waitSpool(t)
	sh(t, "install -d -m 755 "+elDir)
	writeEICAR(t, elDir, "eicar", 3)
	sh(t, "chmod 755 "+elDir)
}

func sedConfigRestartServerAndTarget(t *testing.T) {
	t.Helper()
	restartServer(t)
	sh(t, "printf '%s\\n' '"+sinkHook+"' | runuser -u clamfleet-server -- env SUDO_USER="+operator+" "+pkgServer+" alert add-webhook ops --url-stdin --no-state-changes --detection-burst 0")
}

// avcs returns the AVC denials of the audit log since an epoch second. ausearch's own -ts parsing
// is not trusted across the VM's clock; the epoch in each record is.
func avcs(t *testing.T, since string) []string {
	t.Helper()
	out := sh(t, `awk -v s=`+since+` '/type=AVC/ { match($0, /audit\(([0-9]+)/, m); if (m[1] >= s) print }' /var/log/audit/audit.log || true`)
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func epoch(t *testing.T) string { return sh(t, "date +%s") }

// ours returns the denials that concern clamd's domain, minus the harness's own and the one
// known stock denial. The harness (incus exec, through a CIL module `incus-agent-harness` in the
// VM) runs in init_t and initrc_t and is denied things unrelated to us; clamd reading
// /selinux/enforce is a stock denial of the image (an unlabeled stray directory), filtered and not fixed.
func elOurs(lines []string) []string {
	var out []string
	for _, l := range lines {
		if !strings.Contains(l, "scontext=system_u:system_r:antivirus_t") {
			continue
		}
		// clamd looks at /selinux, an unlabeled directory the image ships (stock, unrelated to us).
		if strings.Contains(l, "/selinux/enforce") || strings.Contains(l, `name="enforce"`) || (strings.Contains(l, `name="selinux"`) && strings.Contains(l, "tcontext=system_u:object_r:unlabeled_t")) {
			continue
		}
		out = append(out, l)
	}
	return out
}

// preconditions: without them a pass would mean nothing.
func elPreconditions(t *testing.T) {
	t.Helper()
	if got := sh(t, "getenforce"); got != "Enforcing" {
		t.Fatalf("getenforce = %q, want Enforcing", got)
	}
	if ps := sh(t, "ps -eZ | grep ' clamd$' || true"); !strings.Contains(ps, ":antivirus_t:") {
		t.Fatalf("clamd runs as %q, want antivirus_t", ps)
	}
	if mods := sh(t, "semodule -lfull | grep -w clamfleet || true"); !strings.Contains(mods, "300") {
		t.Fatalf("semodule -lfull lists %q, want the module clamfleet at priority 300", mods)
	}
	for _, p := range []string{spoolDir + "/events", spoolDir + "/usage"} {
		if z := sh(t, "ls -dZ "+p); !strings.Contains(z, ":clamfleet_spool_t:") {
			t.Fatalf("%s is labelled %q, want clamfleet_spool_t", p, z)
		}
	}
}

// The rpm: installs, follows the preset (the server is NOT enabled), starts when told to,
// loads the module at priority 300 and labels the spool, creates the users and the modes, and the
// agent waits for its token. The group is clamscan.
func TestEL9RpmInstallAndStart(t *testing.T) {
	el9Fresh(t)
	elPreconditions(t)
	if got := sh(t, "systemctl is-enabled clamfleet-server || true"); got != "disabled" {
		t.Fatalf("clamfleet-server is %q after install, want disabled (the RHEL family follows the preset)", got)
	}
	sh(t, "systemctl enable --now clamfleet-server")
	waitServerHealthy(t)
	if l := sh(t, "ss -ltnH | awk '{print $4}' | grep ':8443$' || true"); l != "127.0.0.1:8443" {
		t.Fatalf("the server listens on %q, want 127.0.0.1:8443 only", l)
	}
	// virusgroup: EPEL's /run/clamd.scan is clamscan:virusgroup 0710, so the agent needs that group to reach clamd's socket.
	if g := sh(t, "id -nG clamfleet"); !strings.Contains(" "+g+" ", " clamscan ") || !strings.Contains(" "+g+" ", " virusgroup ") || !strings.Contains(" "+g+" ", " systemd-journal ") {
		t.Fatalf("clamfleet is in groups %q, want clamscan, virusgroup and systemd-journal", g)
	}
	for path, want := range map[string]string{
		"/var/lib/clamfleet":               "750 clamfleet:clamscan",
		"/var/lib/clamfleet/spool":         "2750 clamfleet:clamscan",
		"/var/lib/clamfleet/spool/events":  "3770 clamfleet:clamscan",
		"/var/lib/clamfleet/spool/usage":   "660 clamfleet:clamscan",
		"/var/lib/clamfleet-server":        "700 clamfleet-server:clamfleet-server",
		"/etc/clamfleet/server-secret.key": "640 root:clamfleet-server",
		"/etc/clamfleet/agent.yaml":        "644 root:root",
	} {
		if got := sh(t, "stat -c '%a %U:%G' "+path); got != want {
			t.Errorf("%s is %s, want %s", path, got, want)
		}
	}
	st := sh(t, "systemctl show -p ActiveState,Result,ConditionResult clamfleet-agent")
	for _, want := range []string{"ActiveState=inactive", "Result=success", "ConditionResult=no"} {
		if !strings.Contains(st, want) {
			t.Fatalf("agent without a token: %s, want %s", st, want)
		}
	}
	registerAgent(t)
	waitReport(t, 30*time.Second)
	// The hardened agent unit works on this distribution too (D-Bus for systemctl, the journal,
	// clamd's socket): the report has no collection problem.
	var h struct {
		LastReport proto.Report `json:"last_report"`
	}
	if err := json.Unmarshal([]byte(pkgCLI(t, "host", "show", hostName, "--json")), &h); err != nil {
		t.Fatal(err)
	}
	if !h.LastReport.Clamd.Up || h.LastReport.Services.Clamd != "active" {
		t.Fatalf("the packaged agent's report under hardening: clamd %+v services %+v", h.LastReport.Clamd, h.LastReport.Services)
	}
	for _, tm := range []string{"clamfleet-scan.timer", "clamfleet-server-backup.timer"} {
		if got := sh(t, "systemctl is-enabled "+tm+" || true"); got != "disabled" {
			t.Errorf("%s is %q, want disabled", tm, got)
		}
	}
	noErrorLines(t, "clamfleet-server", "clamfleet-agent")
}

// The M1 acceptance for RHEL 9: collect --dry-run with the packaged RHEL example configuration
// reports what independent sources say: sigtool, clamd --version, systemd.
func TestEL9DryRun(t *testing.T) {
	el9Fresh(t)
	out := sh(t, "runuser -u clamfleet -- "+pkgAgent+" collect --dry-run")
	var r proto.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("not a report: %v\n%s", err, out)
	}
	if want := sh(t, ". /etc/os-release; echo \"$ID\""); r.OS.ID != want {
		t.Errorf("os.id = %q, os-release says %q", r.OS.ID, want)
	}
	if !r.Clamd.Up || r.Clamd.Error != nil {
		t.Errorf("clamd = %+v", r.Clamd)
	}
	if want, _, _ := strings.Cut(strings.TrimPrefix(sh(t, "clamd --version"), "ClamAV "), "/"); r.Clamd.Version == nil || *r.Clamd.Version != want {
		t.Errorf("clamd.version = %v, clamd --version says %q", r.Clamd.Version, want)
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
	if want := sh(t, "systemctl is-active clamd@scan"); r.Services.Clamd != want || want != "active" {
		t.Errorf("services.clamd = %q, systemctl says %q", r.Services.Clamd, want)
	}
	if want := sh(t, "systemctl is-active clamav-freshclam || true"); r.Services.Freshclam != want {
		t.Errorf("services.freshclam = %q, systemctl says %q", r.Services.Freshclam, want)
	}
	t.Logf("freshclam on the RHEL family: %+v", r.Freshclam)
}

// The detection path under SELinux Enforcing: an EICAR scan by the real clamd reaches the sink,
// clamd's journal holds nothing from our command, and the audit log has no denial for clamd's
// domain (apart from the stock /selinux/enforce one): no spool, shell or binary denial. It also
// proves antivirus_t can read the packaged agent.yaml, which the event command needs.
func TestSELinuxEICARAlert(t *testing.T) {
	el9Rig(t)
	elPreconditions(t)
	since := epoch(t)
	t0 := time.Now()
	code, took, out := scan(t, elDir+"/eicar-1.com")
	if code != 1 || !strings.Contains(out, "FOUND") {
		t.Fatalf("clamdscan exit %d: %s", code, out)
	}
	_, _, at := waitDetection(t, elDir+"/eicar-1.com", 30*time.Second)
	t.Logf("MEASURED (AlmaLinux 9, SELinux enforcing): scan to alert %v, clamdscan returned in %v", at.Sub(t0).Round(100*time.Millisecond), took.Round(time.Millisecond))
	// clamd@scan is Type=forking: clamd closes stderr, so a failing event command leaves NO line in
	// clamd's journal on this family (it does on Debian). The audit log is what shows a denial here.
	if d := elOurs(avcs(t, since)); len(d) != 0 {
		t.Fatalf("SELinux denied something to clamd's domain on the allowed path:\n%s", strings.Join(d, "\n"))
	}
	waitSpoolEmpty(t, "events", 10*time.Second)
}

// The module is what makes it work, and the test above can fail: with the module removed (at
// priority 300) and the spool relabelled to var_lib_t, the same scan is denied, clamd's journal
// holds our "event not spooled" line, and nothing reaches the sink.
func TestSELinuxModuleIsNeeded(t *testing.T) {
	el9Rig(t)
	sh(t, "semodule -X 300 -r clamfleet && restorecon -R -F /var/lib/clamfleet")
	for _, p := range []string{spoolDir + "/events", spoolDir + "/usage"} {
		if z := sh(t, "ls -dZ "+p); !strings.Contains(z, ":var_lib_t:") {
			t.Fatalf("%s is %q after removing the module, want var_lib_t", p, z)
		}
	}
	since := epoch(t)
	if code, _, out := scan(t, elDir+"/eicar-2.com"); code != 1 {
		t.Fatalf("scan: %d %s", code, out)
	}
	time.Sleep(5 * time.Second)
	d := elOurs(avcs(t, since))
	found := false
	for _, l := range d {
		found = found || (strings.Contains(l, "tcontext=system_u:object_r:var_lib_t") && strings.Contains(l, "comm=\"clamfleet-agent\""))
	}
	if !found {
		t.Fatalf("no AVC denial for the event command on the var_lib_t spool:\n%s", strings.Join(d, "\n"))
	}
	// Without the module there is no log line anywhere (clamd closes stderr, see above): only the audit
	// log and the missing detection tell. That is what docs/detections.md says for the RHEL family.
	if n := spoolItems(t, "events"); n != 0 {
		t.Fatalf("%d items in spool/events although SELinux denied the write", n)
	}
	for _, dt := range detections(t) {
		if dt.Path == elDir+"/eicar-2.com" {
			t.Fatal("a detection reached the sink without the module: the previous test proves nothing")
		}
	}
}

// The module allows the spool and nothing else: the event command pointed (through its --config)
// at another spool directory that holds a real events/ with the right owner and mode, labelled
// var_lib_t and loosened to 0755 so ordinary permissions allow it, is denied by SELinux, and no
// file appears there.
func TestSELinuxEventCannotWriteElsewhere(t *testing.T) {
	el9Rig(t)
	// The targeted policy hides some denials of clamd's domain with dontaudit rules; the negative claim
	// ("denied") needs them visible. The snapshot reset undoes this, but the policy is rebuilt after the test anyway.
	sh(t, "semodule -DB")
	defer sh(t, "semodule -B")
	other := spoolDir + "/reports"
	// The agent service owns spool/reports and removes entries it does not recognise (a stray events/
	// directory included), so it must not run while the other spool is staged.
	sh(t, "systemctl stop clamfleet-agent")
	// The event command takes the agent's identity from the owner of spool.dir, so reports/ is the agent's;
	// 0755 so ordinary permissions let clamd's user in and only SELinux can refuse.
	sh(t, "install -d -o clamfleet -g clamscan -m 3770 "+other+"/events; chown clamfleet:clamscan "+other+"; chmod 0755 "+other+"; chcon -R -t var_lib_t "+other)
	sh(t, "cat > /etc/clamfleet/agent-other.yaml <<'YAML'\nserver: http://127.0.0.1:8443\nspool: {dir: "+other+", max_mb: 1}\nYAML\nchmod 644 /etc/clamfleet/agent-other.yaml; restorecon /etc/clamfleet/agent-other.yaml")
	sh(t, "sed -i 's|^VirusEvent .*|VirusEvent /usr/bin/clamfleet-agent event --config /etc/clamfleet/agent-other.yaml|' /etc/clamd.d/scan.conf; systemctl restart clamd@scan")
	waitClamd(t)
	since := epoch(t)
	if code, _, out := scan(t, elDir+"/eicar-3.com"); code != 1 {
		t.Fatalf("scan: %d %s", code, out)
	}
	time.Sleep(5 * time.Second)
	d := elOurs(avcs(t, since))
	found := false
	for _, l := range d {
		// The real spool is allowed by the module, so a denial of the event command on a var_lib_t
		// directory can only be the other spool.
		found = found || (strings.Contains(l, "comm=\"clamfleet-agent\"") && strings.Contains(l, "tcontext=system_u:object_r:var_lib_t") && strings.Contains(l, "name=\"events\""))
	}
	if !found {
		t.Fatalf("no AVC denial for the event command under spool/reports:\n%s", strings.Join(d, "\n"))
	}
	if n := sh(t, "find "+other+"/events -type f | wc -l"); n != "0" {
		t.Fatalf("%s files appeared in spool/reports/events: SELinux did not stop the write", n)
	}
}

// The milestone 5 scenario on EL9: with the server down the event is spooled (group clamscan) and is
// delivered once the server is back.
func TestEL9EventSurvivesServerDowntime(t *testing.T) {
	el9Rig(t)
	sh(t, "systemctl stop clamfleet-server")
	if code, _, out := scan(t, elDir+"/eicar-1.com"); code != 1 {
		t.Fatalf("scan: %d %s", code, out)
	}
	deadline := time.Now().Add(15 * time.Second)
	for spoolItems(t, "events") == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the event was not spooled while the server was down\nclamd journal:\n%s", journal(t, "clamd@scan"))
		}
		time.Sleep(500 * time.Millisecond)
	}
	if g := sh(t, "stat -c '%G' "+spoolDir+"/events/*.json | sort -u"); g != "clamscan" {
		t.Fatalf("the spooled event has group %q, want clamscan", g)
	}
	sh(t, "systemctl start clamfleet-server")
	waitDetection(t, elDir+"/eicar-1.com", 60*time.Second)
	waitSpoolEmpty(t, "events", 30*time.Second)
}

// Upgrade and removal for real: the module stays loaded at 300 across an upgrade (the old
// package's scripts run AFTER the new one's), the configuration edit is kept, the services restart;
// dnf remove takes the module away at every priority and the units with it.
func TestEL9RpmUpgradeAndRemove(t *testing.T) {
	el9Fresh(t)
	el9Registered(t)
	sedConfig(t, "/etc/clamfleet/server.yaml", "s/^  audit_days: 365 /  audit_days: 120 /")
	restartServer(t)
	pidBefore := sh(t, "systemctl show -p MainPID --value clamfleet-server")
	agentPidBefore := sh(t, "systemctl show -p MainPID --value clamfleet-agent")

	dir := t.TempDir()
	if o, err := exec.Command("make", "-C", repoRoot, "packages", "VERSION="+pkgVersionNew, "PKG_DIR="+dir).CombinedOutput(); err != nil {
		t.Fatalf("make packages (e2e2): %v\n%s", err, o)
	}
	agent, server := rpmFile(t, dir, "clamfleet-agent", debNew), rpmFile(t, dir, "clamfleet-server", debNew)
	pushPackages(t, agent, server)
	out := sh(t, "dnf upgrade -y /root/pkgs/*"+strings.ReplaceAll(pkgVersionNew, "-", "~")+"*.rpm 2>&1")
	if !strings.Contains(out, "Upgrading") && !strings.Contains(out, "Upgraded") {
		t.Fatalf("not an upgrade:\n%s", out)
	}
	if mods := sh(t, "semodule -lfull | grep -w clamfleet || true"); !strings.Contains(mods, "300") {
		t.Fatalf("after the upgrade semodule -lfull lists %q, want clamfleet at priority 300", mods)
	}
	if got := sh(t, "grep -c '^  audit_days: 120 ' /etc/clamfleet/server.yaml"); got != "1" {
		t.Fatal("the upgrade lost the edit in server.yaml")
	}
	if got := sh(t, "ls /etc/clamfleet/*.rpmnew /etc/clamfleet/*.rpmsave 2>/dev/null | wc -l"); got != "0" {
		t.Fatalf("the upgrade left %s .rpmnew/.rpmsave files for an unchanged packaged config", got)
	}
	for unit, before := range map[string]string{"clamfleet-server": pidBefore, "clamfleet-agent": agentPidBefore} {
		if after := sh(t, "systemctl show -p MainPID --value "+unit); after == before || after == "0" {
			t.Errorf("%s was not restarted by the upgrade (pid %s before, %s after)", unit, before, after)
		}
	}
	elPreconditions(t)

	sh(t, "dnf remove -y clamfleet-agent clamfleet-server 2>&1")
	if mods := sh(t, "semodule -lfull | grep -w clamfleet || true"); mods != "" {
		t.Fatalf("after dnf remove the module is still loaded: %q", mods)
	}
	for _, u := range []string{"clamfleet-agent.service", "clamfleet-server.service", "clamfleet-scan.timer"} {
		if got := sh(t, "ls /usr/lib/systemd/system/"+u+" 2>&1 | grep -c 'No such file' || true"); got != "1" {
			t.Errorf("unit file %s is still installed after remove", u)
		}
	}
	sh(t, "test -f /var/lib/clamfleet-server/clamfleet.db && test -f /etc/clamfleet/server-secret.key")
}

// The rules the module adds to clamd's domain, mechanically: `sesearch -A -s antivirus_t` with and
// without the module, diffed. The difference must be exactly the two reviewed rules on the module's
// own type and nothing on a stock type (clamd, freshclam and clamonacc share this domain).
func TestSELinuxRuleSet(t *testing.T) {
	el9Fresh(t)
	rules := func() []string {
		var out []string
		for _, l := range strings.Split(sh(t, "sesearch -A -s antivirus_t | sort"), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				out = append(out, l)
			}
		}
		return out
	}
	with := rules()
	sh(t, "semodule -X 300 -r clamfleet")
	without := rules()
	set := func(l []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range l {
			m[x] = true
		}
		return m
	}
	w, wo := set(with), set(without)
	var added, removed []string
	for l := range w {
		if !wo[l] {
			added = append(added, l)
		}
	}
	for l := range wo {
		if !w[l] {
			removed = append(removed, l)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	// The reviewed list: written from `sesearch` on the VM, one rule per class, both on clamfleet_spool_t.
	want := []string{
		"allow antivirus_t clamfleet_spool_t:dir { add_name getattr open read remove_name search write };",
		"allow antivirus_t clamfleet_spool_t:file { create getattr link lock open read setattr unlink write };",
	}
	if strings.Join(added, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the module adds these rules to antivirus_t:\n%s\nwant exactly:\n%s", strings.Join(added, "\n"), strings.Join(want, "\n"))
	}
	if len(removed) != 0 {
		t.Fatalf("the module removes rules from antivirus_t: %v", removed)
	}
}
