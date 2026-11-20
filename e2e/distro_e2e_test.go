//go:build e2e && e2e_distro

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// The scenario set that is the same for every release we claim and for both package formats:
// install, dry run, detection, upgrade and remove, sudo attribution and a static check of the
// confinement files. Nothing here names a release: the facts come from `release(t)` (the table
// in distro_test.go), and an unknown release fails. The same code runs on a machine with its
// MAC enforcing (an Incus VM: `make e2e-apparmor`, `make e2e-el9`) and on one without (a CI
// container); the MAC steps run where `macEnforced` says so, and the VM targets set E2E_MAC=1
// so that a VM which lost its MAC fails instead of passing without it.
//
// Per-release suites keep what only one release can say (the AppArmor denial scenarios,
// the SELinux module scenarios); this file keeps what must hold everywhere.
//
// Every scenario starts from the machine's clean state (reset.sh) with NOTHING of ours in it and
// installs the real packages, as package_e2e_test.go and el9_e2e_test.go do.
package e2e

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// moduleTypeRule is the one rule that declaring our file type adds on its own, which the module's CIL
// never writes: the stock policy's attribute rules apply to every type with the file_type attribute,
// and sesearch shows them expanded to the new type. It appears only in a whole-policy search (on
// antivirus_t the search is scoped to the domain's own rules, which this is not). Seen on
// AlmaLinux 10, where clamd is not in antivirus_t and the whole policy is compared (R1 decision 10).
const moduleTypeRule = "allow clamfleet_spool_t clamfleet_spool_t:filesystem associate;"

// distroFresh resets the machine, installs both packages of the release's format and returns
// once clamd scans. The release is read right after the reset (see below): an unknown one fails before any package is installed.
func distroFresh(t *testing.T) distro {
	t.Helper()
	// Reset first, then read the release: on a Docker leg the reset is what creates the machine, so
	// asking /etc/os-release before it fails with "No such container". On a VM the order makes no
	// difference (the snapshot is the same release).
	if err := script("reset.sh"); err != nil {
		t.Fatal(err)
	}
	d := release(t)
	dist := filepath.Join(repoRoot, "dist")
	d.installPkgs(t, false, d.pkgFile(t, dist, "clamfleet-server", debOld), d.pkgFile(t, dist, "clamfleet-agent", debOld))
	waitClamd(t)
	return d
}

// distroServerUp starts the packaged server and waits for it. The deb starts its service on
// install and the rpm does not (it follows the preset: disabled), so this enables and starts it
// for both: idempotent where it is already up.
func distroServerUp(t *testing.T) {
	t.Helper()
	sh(t, "systemctl enable --now clamfleet-server")
	waitServerHealthy(t)
}

// mustMode checks `stat -c '%a %U:%G'` of each path.
func mustMode(t *testing.T, want map[string]string) {
	t.Helper()
	for path, mode := range want {
		if got := sh(t, "stat -c '%a %U:%G' "+path); got != mode {
			t.Errorf("%s is %s, want %s", path, got, mode)
		}
	}
}

// macPreconditions asserts the confinement is in place (the packages loaded their profile or
// module), on a machine that enforces one.
func macPreconditions(t *testing.T, d distro) {
	t.Helper()
	if d.MAC == "selinux" {
		elPreconditions(t, d)
		return
	}
	aaPreconditions(t, d)
}

// Both packages install, the server starts (itself on a deb, by hand on an rpm), listens on
// loopback only, the groups and modes are the release's, the agent waits for its token (condition
// failed, not a restart loop) and after the documented first steps the host reports.
func TestDistroInstallAndStart(t *testing.T) {
	d := distroFresh(t)
	mac := macEnforced(t, d)
	if mac {
		macPreconditions(t, d)
	}

	// The family difference that is on purpose: a deb starts its server on install, an rpm follows
	// the preset (disabled) and needs the administrator to enable it.
	enabled := sh(t, "systemctl is-enabled clamfleet-server || true")
	if want := map[string]string{"deb": "enabled", "rpm": "disabled"}[d.Family]; enabled != want {
		t.Fatalf("clamfleet-server is %q after install, want %q on the %s family", enabled, want, d.Family)
	}
	distroServerUp(t)
	if l := sh(t, "ss -ltnH | awk '{print $4}' | grep ':8443$' || true"); l != "127.0.0.1:8443" {
		t.Fatalf("the server listens on %q, want 127.0.0.1:8443 only", l)
	}

	groups := " " + sh(t, "id -nG clamfleet") + " "
	for _, g := range d.AgentGroups {
		if !strings.Contains(groups, " "+g+" ") {
			t.Fatalf("clamfleet is in groups %q, want %v", strings.TrimSpace(groups), d.AgentGroups)
		}
	}
	spool := "750 clamfleet:" + d.ClamdGroup
	mustMode(t, map[string]string{
		"/var/lib/clamfleet":               spool,
		"/var/lib/clamfleet/spool":         "2750 clamfleet:" + d.ClamdGroup,
		"/var/lib/clamfleet-server":        "700 clamfleet-server:clamfleet-server",
		"/etc/clamfleet/server-secret.key": "640 root:clamfleet-server",
		"/etc/clamfleet/agent.yaml":        "644 root:root",
	})
	// The package installs the family's example as the configuration: a file that drifted to the
	// other family's example would name the wrong units and paths.
	if got := sh(t, "cmp /etc/clamfleet/agent.yaml /usr/share/doc/clamfleet-agent/"+d.Example+" && echo same"); got != "same" {
		t.Fatalf("agent.yaml is not the packaged %s", d.Example)
	}

	st := sh(t, "systemctl show -p ActiveState,Result,ConditionResult clamfleet-agent")
	for _, want := range []string{"ActiveState=inactive", "Result=success", "ConditionResult=no"} {
		if !strings.Contains(st, want) {
			t.Fatalf("agent without a token: %s, want %s", st, want)
		}
	}

	registerAgent(t)
	waitReport(t, 30*time.Second)
	// The agent has created its spool now: the milestone 5 modes, on this release.
	mustMode(t, map[string]string{
		spoolDir + "/events": "3770 clamfleet:" + d.ClamdGroup,
		spoolDir + "/usage":  "660 clamfleet:" + d.ClamdGroup,
	})
	// The hardened agent unit works on this release too (D-Bus for systemctl, the journal, clamd's
	// socket): the report has no collection problem.
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
			t.Errorf("%s is %q, want disabled (it ships disabled)", tm, got)
		}
	}
	noErrorLines(t, "clamfleet-server", "clamfleet-agent")
}

// collect --dry-run with the packaged example configuration reports what independent sources say:
// sigtool, clamd --version and systemd, using the release's own unit names from the table. A
// wrong unit name in the table (or in the packaged example) fails here.
func TestDistroDryRun(t *testing.T) {
	d := distroFresh(t)
	out := sh(t, "runuser -u clamfleet -- "+pkgAgent+" collect --dry-run")
	var r proto.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("not a report: %v\n%s", err, out)
	}
	if want := sh(t, ". /etc/os-release; echo \"$ID\""); r.OS.ID != want {
		t.Errorf("os.id = %q, os-release says %q", r.OS.ID, want)
	}
	if !r.Clamd.Up || r.Clamd.Error != nil {
		// The Error field is a pointer: print its text, a bare %+v shows only an address.
		errText := "<nil>"
		if r.Clamd.Error != nil {
			errText = *r.Clamd.Error
		}
		t.Errorf("clamd = %+v, error %q", r.Clamd, errText)
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
	// systemctl exits non-zero for a unit that is not active; `|| true` keeps the answer, which is
	// compared, instead of failing the script on the exit code.
	if want := sh(t, "systemctl is-active "+d.ClamdUnit+" || true"); r.Services.Clamd != want || want != "active" {
		t.Errorf("services.clamd = %q, systemctl says %q for %s", r.Services.Clamd, want, d.ClamdUnit)
	}
	if want := sh(t, "systemctl is-active "+d.FreshclamUnit+" || true"); r.Services.Freshclam != want {
		t.Errorf("services.freshclam = %q, systemctl says %q for %s", r.Services.Freshclam, want, d.FreshclamUnit)
	}
	t.Logf("freshclam on %s: %+v", d.Family, r.Freshclam)
}

// wireClamd does what the install notice tells an administrator, per family: on AppArmor the
// two lines of the packaged local include (clamd's profile lets the shell run our binary under
// ITS profile) and a reload of clamd's profile; everywhere the VirusEvent line, then a restart.
// On the RHEL family the package's %post has already loaded the module, so nothing else is needed.
// A stray commented `#VirusEvent` of a stock file is dropped with any earlier line: one line stays.
func wireClamd(t *testing.T, d distro, mac bool) {
	t.Helper()
	if mac && d.MAC == "apparmor" {
		sh(t, "touch /etc/apparmor.d/local/usr.sbin.clamd; "+
			"grep -q 'Px -> clamfleet-agent-event' /etc/apparmor.d/local/usr.sbin.clamd || cat /usr/share/doc/clamfleet-agent/usr.sbin.clamd.local >> /etc/apparmor.d/local/usr.sbin.clamd; "+
			"apparmor_parser -r /etc/apparmor.d/usr.sbin.clamd; "+
			// AppArmor's DENIED lines go through printk, which drops more than 10 messages in 5 s: without
			// this a denial the scenario looks for can be lost (as in aa-prepare.sh). Runtime only.
			"sysctl -qw kernel.printk_ratelimit=0")
	}
	sh(t, "sed -i '/^#\\?VirusEvent /d' "+d.ClamdConf+"; echo 'VirusEvent "+pkgAgent+" event' >> "+d.ClamdConf+"; systemctl restart "+d.ClamdUnit)
	waitClamd(t)
}

// The detection path through the packaged agent on this release: an EICAR scan by the real clamd
// reaches the sink, clamd's journal holds nothing from our command, and where the MAC enforces,
// it logged no denial for us (apart from the release's stock ones). This is the test a 0640
// agent.yaml, a profile that refuses the event command, or a module that lacks a rule would fail.
func TestDistroDetection(t *testing.T) {
	d := distroFresh(t)
	mac := macEnforced(t, d)
	distroServerUp(t)
	startSink(t)
	sedConfig(t, "/etc/clamfleet/server.yaml", "s/allow_loopback: false/allow_loopback: true/")
	restartServer(t)
	sh(t, "printf '%s\\n' '"+sinkHook+"' | runuser -u clamfleet-server -- env SUDO_USER="+operator+" "+pkgServer+" alert add-webhook ops --url-stdin --no-state-changes --detection-burst 0")
	registerAgent(t)
	wireClamd(t, d, mac)
	waitSpool(t)
	waitReport(t, 30*time.Second)
	if mac {
		macPreconditions(t, d)
	}
	if got := sh(t, "stat -c '%a %U:%G' /etc/clamfleet/agent.yaml /etc/clamfleet/token"); got != "644 root:root\n640 root:clamfleet" {
		t.Fatalf("modes: %q, want agent.yaml 644 root:root and token 640 root:clamfleet", got)
	}

	writeEICAR(t, d.EICARDir, "eicar", 1)
	since := macSince(t, d)
	file := d.EICARDir + "/eicar-1.com"
	if code, _, out := scan(t, file); code != 1 || !strings.Contains(out, "FOUND") {
		t.Fatalf("clamdscan exit %d: %s", code, out)
	}
	det, _, _ := waitDetection(t, file, 30*time.Second)
	if !strings.Contains(det.Signature, "Eicar") {
		t.Fatalf("detection %+v", det)
	}
	// On the RHEL family clamd is Type=forking and closes stderr, so a failing event command leaves no
	// line here: the denial check below is what shows it. On the deb family this line is the first sign.
	if lines := notSpooled(journal(t, strings.TrimSuffix(d.ClamdUnit, ".service"))); len(lines) != 0 {
		t.Fatalf("clamd's journal holds lines from our command: %q", lines)
	}
	if mac {
		if den := macDenials(t, d, since); len(den) != 0 {
			t.Fatalf("%s denied something on the allowed path:\n%s", d.MAC, strings.Join(den, "\n"))
		}
	}
	waitSpoolEmpty(t, "events", 10*time.Second)
}

// Upgrade and removal for real: the configuration edit and the key file are kept, the services
// restart, the confinement is still in place after the upgrade (an rpm's old scripts run AFTER the
// new package's, so the module must survive that order); removal takes the units, and the
// confinement of the event command, away, and leaves the server's data.
func TestDistroUpgradeAndRemove(t *testing.T) {
	d := distroFresh(t)
	mac := macEnforced(t, d)
	distroServerUp(t)
	registerAgent(t)
	waitReport(t, 30*time.Second)
	sedConfig(t, "/etc/clamfleet/server.yaml", "s/^  audit_days: 365 /  audit_days: 120 /")
	restartServer(t)
	keyBefore := sh(t, "sha256sum /etc/clamfleet/server-secret.key")
	pidBefore := sh(t, "systemctl show -p MainPID --value clamfleet-server")
	agentPidBefore := sh(t, "systemctl show -p MainPID --value clamfleet-agent")

	dir := t.TempDir()
	if o, err := exec.Command("make", "-C", repoRoot, "packages", "VERSION="+pkgVersionNew, "PKG_DIR="+dir).CombinedOutput(); err != nil {
		t.Fatalf("make packages (e2e2): %v\n%s", err, o)
	}
	out := d.installPkgs(t, true, d.pkgFile(t, dir, "clamfleet-server", debNew), d.pkgFile(t, dir, "clamfleet-agent", debNew))
	if d.Family == "deb" && !strings.Contains(out, "Unpacking clamfleet-server ("+debNew+") over ("+debOld+")") {
		t.Fatalf("not an upgrade:\n%s", out)
	}
	if d.Family == "rpm" && !strings.Contains(out, "Upgrading") && !strings.Contains(out, "Upgraded") {
		t.Fatalf("not an upgrade:\n%s", out)
	}

	if got := sh(t, "grep -c '^  audit_days: 120 ' /etc/clamfleet/server.yaml"); got != "1" {
		t.Fatal("the upgrade lost the edit in server.yaml")
	}
	if got := sh(t, "sha256sum /etc/clamfleet/server-secret.key"); got != keyBefore {
		t.Fatal("the key file changed in an upgrade")
	}
	mustMode(t, map[string]string{"/etc/clamfleet/server.yaml": "640 root:clamfleet-server"})
	if got := sh(t, "ls /etc/clamfleet/*.rpmnew /etc/clamfleet/*.rpmsave /etc/clamfleet/*.dpkg-dist 2>/dev/null | wc -l"); got != "0" {
		t.Fatalf("the upgrade left %s .rpmnew/.rpmsave/.dpkg-dist files for an unchanged packaged config", got)
	}
	for unit, before := range map[string]string{"clamfleet-server": pidBefore, "clamfleet-agent": agentPidBefore} {
		if after := sh(t, "systemctl show -p MainPID --value "+unit); after == before || after == "0" {
			t.Errorf("%s was not restarted by the upgrade (pid %s before, %s after)", unit, before, after)
		}
	}
	if sh(t, "runuser -u clamfleet-server -- "+pkgServer+" host list | grep -c "+hostName) != "1" {
		t.Fatal("the host is gone after the upgrade")
	}
	noErrorLines(t, "clamfleet-server")
	if mac {
		macPreconditions(t, d)
	}

	if d.Family == "rpm" {
		sh(t, "dnf remove -y clamfleet-agent clamfleet-server 2>&1 </dev/null")
	} else {
		sh(t, "DEBIAN_FRONTEND=noninteractive apt-get remove -y clamfleet-agent clamfleet-server 2>&1")
	}
	for _, u := range []string{"clamfleet-agent.service", "clamfleet-server.service", "clamfleet-scan.timer", "clamfleet-server-backup.timer"} {
		if got := sh(t, "ls /usr/lib/systemd/system/"+u+" 2>&1 | grep -c 'No such file' || true"); got != "1" {
			t.Errorf("unit file %s is still installed after remove", u)
		}
	}
	if got := sh(t, "systemctl is-active clamfleet-server || true"); got == "active" {
		t.Fatal("the server is still running after remove")
	}
	if mac {
		// No stale confinement is left for a binary that is no longer there.
		if d.MAC == "selinux" {
			if mods := sh(t, "semodule -lfull | grep -w clamfleet || true"); mods != "" {
				t.Fatalf("after remove the module is still loaded: %q", mods)
			}
		} else {
			var st struct {
				Profiles map[string]string `json:"profiles"`
			}
			if err := json.Unmarshal([]byte(sh(t, "aa-status --json")), &st); err != nil {
				t.Fatal(err)
			}
			if mode, loaded := st.Profiles["clamfleet-agent-event"]; loaded {
				t.Fatalf("the profile clamfleet-agent-event is still loaded (%s) after remove", mode)
			}
		}
	}
	sh(t, "test -f /var/lib/clamfleet-server/clamfleet.db && test -f /etc/clamfleet/server-secret.key")
}

// The audit actor of an admin command is the person who typed `sudo -u clamfleet-server ...`, not
// the server user: the CLI reads SUDO_USER, so this needs the release's real sudo to set it. The
// other scenarios set SUDO_USER by hand; this is the one that runs a real sudo, which is what
// would catch a sudo implementation that does not pass it on (sudo-rs on Ubuntu 26.04 is the
// reason this test exists).
func TestDistroSudoAttribution(t *testing.T) {
	distroFresh(t)
	distroServerUp(t)
	const person, host = "e2eoperator", "sudo-host"
	// Cleanup is registered right after useradd so a failing step cannot leave the user or the
	// sudoers file behind on a machine the next scenario reuses.
	sh(t, "useradd -m "+person)
	t.Cleanup(func() { sh(t, "rm -f /etc/sudoers.d/"+person+"; userdel -r "+person+" || true") })
	// The drop-in is written aside, syntax-checked and only then installed: a bad file left in
	// /etc/sudoers.d would lock sudo out for everyone.
	sh(t, "f=$(mktemp); trap 'rm -f \"$f\"' EXIT; printf '%s ALL=(clamfleet-server) NOPASSWD: "+pkgServer+"\\n' "+person+" > \"$f\"; "+
		"visudo -cf \"$f\" && install -m 0440 \"$f\" /etc/sudoers.d/"+person)
	tok := sh(t, "runuser -u "+person+" -- sudo -u clamfleet-server "+pkgServer+" host add "+host)
	if !strings.HasPrefix(tok, "cfa_") {
		t.Fatalf("host add through sudo printed %q, want only the token", tok)
	}
	// Read without SUDO_USER: only the audit row we are after may name the person.
	var h shownHost
	if err := json.Unmarshal([]byte(sh(t, "runuser -u clamfleet-server -- "+pkgServer+" host show "+host+" --json")), &h); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range h.Audit {
		if a.Action == "host.add" {
			found = true
			if a.Actor != person {
				t.Errorf("host.add is audited as %q, want %q (the person behind sudo)", a.Actor, person)
			}
		}
	}
	if !found {
		t.Fatalf("no host.add audit row: %+v", h.Audit)
	}
}

// The confinement files of this release, checked statically with the release's OWN tools and
// without loading anything into a kernel: on AppArmor `apparmor_parser -QK` (compile, no kernel
// load, no cache) of our profile and of clamd's stock profile with our local include appended; on
// SELinux the shipped CIL compiled into the stored policy (`semodule -n`, no reload) and the rules
// it adds to clamd's domain read from that policy, which must be exactly the two reviewed ones.
//
// This is the only check that sees a profile or module the release's tools refuse in a container,
// where the package's postinstall skips loading because MAC is off: a package that fails to install
// on a stock host of an older release (AppArmor 3.0.x on Debian 12 or Ubuntu 22.04) would pass
// everything else. A missing tool fails: it is never a reason to skip.
func TestDistroStaticMAC(t *testing.T) {
	d := distroFresh(t)
	if d.MAC == "apparmor" {
		// A copy of the tree with the local include in place: the real files are not touched.
		// -b makes the copy the base for #include, so clamd's `#include <local/usr.sbin.clamd>` reads ours.
		sh(t, "export PATH=$PATH:/usr/sbin:/sbin; "+
			"t=$(mktemp -d); trap 'rm -rf \"$t\"' EXIT; cp -a /etc/apparmor.d \"$t/aa\"; mkdir -p \"$t/aa/local\"; "+
			"touch \"$t/aa/local/usr.sbin.clamd\"; cat /usr/share/doc/clamfleet-agent/usr.sbin.clamd.local >> \"$t/aa/local/usr.sbin.clamd\"; "+
			"apparmor_parser -QK -b \"$t/aa\" \"$t/aa/clamfleet-agent-event\"; "+
			"apparmor_parser -QK -b \"$t/aa\" \"$t/aa/usr.sbin.clamd\"")
		return
	}
	const cil = "/usr/share/selinux/packages/clamfleet/clamfleet.cil"
	// The binary policy the store writes: the highest policy.NN under the configured store.
	// On antivirus_t the search is scoped to it. Where clamd is not in antivirus_t (EL10: no such
	// type exists, and sesearch -s on an unknown type fails) the whole policy is compared, so
	// "the module adds nothing" is asserted against every rule rather than against none.
	scope := "-s antivirus_t"
	if d.ClamdDomain != "antivirus_t" {
		scope = ""
	}
	rules := func() []string {
		return nonEmpty(sh(t, "export PATH=$PATH:/usr/sbin:/sbin; . /etc/selinux/config; "+
			"pol=$(ls /etc/selinux/$SELINUXTYPE/policy/policy.* | sort -V | tail -n1); sesearch -A "+scope+" \"$pol\" | sort"))
	}
	// -n commits to the store without reloading the kernel's policy; restored at the end so the
	// store and the loaded policy agree again.
	sh(t, "export PATH=$PATH:/usr/sbin:/sbin; semodule -n -X 300 -i "+cil)
	with := rules()
	sh(t, "export PATH=$PATH:/usr/sbin:/sbin; semodule -n -X 300 -r clamfleet")
	without := rules()
	sh(t, "export PATH=$PATH:/usr/sbin:/sbin; semodule -n -X 300 -i "+cil)

	in := func(l []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range l {
			m[x] = true
		}
		return m
	}
	w, wo := in(with), in(without)
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
	// The reviewed list (TestSELinuxRuleSet states the same against the live policy): one rule per
	// class, both on the module's own type and on no stock type (clamd, freshclam and clamonacc share the domain).
	// Empty on a release without antivirus_t, where the optional block is inactive (R1 decision 9).
	want := append([]string(nil), d.ModuleRules...)
	if scope == "" {
		// A whole-policy search also shows the rule the new type brings with it (moduleTypeRule). The
		// comparison stays exact: this one rule and nothing else.
		want = append(want, moduleTypeRule)
	}
	sort.Strings(want)
	if strings.Join(added, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the module adds these rules to the policy:\n%s\nwant exactly:\n%s", strings.Join(added, "\n"), strings.Join(want, "\n"))
	}
	if len(removed) != 0 {
		t.Fatalf("the module removes rules from the policy: %v", removed)
	}
}
