//go:build e2e && (e2e_apparmor || e2e_el9 || e2e_distro)

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// The per-release facts table and the helpers every distribution-aware suite shares: the
// AppArmor suite (e2e_apparmor), the SELinux suite (e2e_el9) and the format-neutral
// TestDistro* scenarios (distro_e2e_test.go, e2e_distro).
//
// Why a table: what differs between the releases we claim (unit names, the clamd
// configuration path, the group clamd's user is in, where an EICAR file may live under the
// release's own MAC policy, the example configuration a package installs, the stock
// denials a release's own clamd policy produces) used to be hard-coded in the suite of
// whichever VM first needed it. A table row is the one place a new release is described,
// and a release with no row FAILS: a default would test the new release as if it were
// Debian 13 and pass for the wrong reason.
//
// Build constraint: compiled only when one of the suites that uses it is, so a plain `make e2e` build
// (and staticcheck on that tag set) never sees helpers nothing in it calls.
//
// A row is added only together with the run that observed its facts (the stock denials in
// particular are read from a real run with our VirusEvent removed, never guessed): a
// release without that evidence stays out of the table and fails loudly.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stockDenial describes one MAC denial that the release's OWN clamd policy produces on a
// detection whether or not our VirusEvent is configured. It is filtered out so that anything
// else is a finding (for our profile or module); Why is mandatory because an unexplained
// entry in an allowlist is how a real denial gets swallowed.
type stockDenial struct {
	All []string // every fragment must be in the log line
	Why string
}

// distro holds the facts of one release. Family decides the package tools: "deb" is apt-get
// and dpkg, "rpm" is dnf.
type distro struct {
	Family        string
	MAC           string   // "apparmor" or "selinux": the confinement this release ships for clamd
	ClamdUnit     string   // clamd's service, as systemd names it
	FreshclamUnit string   // freshclam's service
	ClamdConf     string   // the clamd configuration file the administrator adds VirusEvent to
	ClamdGroup    string   // the group of the spool (clamd's group, what the agent shares)
	AgentGroups   []string // the groups the clamfleet user must be in
	EICARDir      string   // where EICAR files live: a place clamd's MAC policy lets it read
	Example       string   // the file under /usr/share/doc/clamfleet-agent the package installs as agent.yaml
	StockDenials  []stockDenial
}

// distros is keyed by os-release `ID VERSION_ID`, the VERSION_ID being the major number for the
// RHEL family (see lookupDistro). Only releases with a recorded run are listed (file header).
var distros = map[string]distro{
	"debian 13": {
		Family:        "deb",
		MAC:           "apparmor",
		ClamdUnit:     "clamav-daemon.service",
		FreshclamUnit: "clamav-freshclam.service",
		ClamdConf:     "/etc/clamav/clamd.conf",
		ClamdGroup:    "clamav",
		AgentGroups:   []string{"clamav", "systemd-journal"},
		// Debian's clamd profile allows /tmp/** and nothing under /srv.
		EICARDir: "/tmp/e2e",
		Example:  "agent.yaml.example",
		StockDenials: []stockDenial{{
			All: []string{`profile="/usr/sbin/clamd"`, `name="/etc/hostname"`},
			Why: "Debian's stock clamd profile does not allow reading /etc/hostname, and clamd tries on every detection whether or not a VirusEvent is configured (seen on the VM with the VirusEvent line removed)",
		}},
	},
	"almalinux 9": {
		Family:        "rpm",
		MAC:           "selinux",
		ClamdUnit:     "clamd@scan.service",
		FreshclamUnit: "clamav-freshclam.service",
		ClamdConf:     "/etc/clamd.d/scan.conf",
		ClamdGroup:    "clamscan",
		// virusgroup: EPEL's /run/clamd.scan is clamscan:virusgroup 0710, so the agent needs that group to reach clamd's socket.
		AgentGroups: []string{"clamscan", "virusgroup", "systemd-journal"},
		// The harness's own domain cannot hand clamd a path under /srv; antivirus_db_t is readable by clamd.
		EICARDir: "/var/lib/clamav/e2e",
		Example:  "agent.rhel9.yaml.example",
		StockDenials: []stockDenial{
			{All: []string{"/selinux/enforce"}, Why: "clamd looks at /selinux, an unlabeled directory the image ships (stock, unrelated to us)"},
			{All: []string{`name="enforce"`}, Why: "the same /selinux/enforce lookup, logged by name"},
			{All: []string{`name="selinux"`, "tcontext=system_u:object_r:unlabeled_t"}, Why: "the same unlabeled /selinux directory, logged by name"},
		},
	},
}

// lookupDistro returns the facts of a release or an error naming the key it looked for. The
// RHEL family is keyed by the major version: its VERSION_ID carries the minor (almalinux
// "9.8"), which changes with every point release and says nothing about the policy facts.
func lookupDistro(id, versionID string) (distro, error) {
	switch id {
	case "almalinux", "rocky", "rhel", "centos":
		versionID, _, _ = strings.Cut(versionID, ".")
	}
	key := id + " " + versionID
	d, ok := distros[key]
	if !ok {
		return distro{}, fmt.Errorf("no facts for release %q: add a row to distros in e2e/distro_test.go, with the run that observed it", key)
	}
	return d, nil
}

// release reads /etc/os-release on the machine under test and returns its facts. An unknown
// release is t.Fatal, never a default.
func release(t *testing.T) distro {
	t.Helper()
	got := sh(t, `. /etc/os-release; echo "${ID:-} ${VERSION_ID:-}"`)
	id, ver, _ := strings.Cut(got, " ")
	d, err := lookupDistro(id, ver)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// notStock drops the release's stock denials from a list of log lines.
func (d distro) notStock(lines []string) []string {
	var out []string
next:
	for _, l := range lines {
		for _, s := range d.StockDenials {
			all := true
			for _, f := range s.All {
				all = all && strings.Contains(l, f)
			}
			if all {
				continue next
			}
		}
		out = append(out, l)
	}
	return out
}

// macEnforced reports whether this machine's own mandatory access control confines clamd:
// AppArmor enabled (deb family) or SELinux Enforcing (rpm family). The L2 containers share the
// host's kernel, which has neither, and the scenarios then skip only the MAC steps. The VM
// targets set E2E_MAC=1: there a machine where it is off is a broken VM, and the answer
// "no" must fail instead of letting the scenario pass without any confinement. A missing
// tool fails too: "tool absent" must never read as "MAC off".
func macEnforced(t *testing.T, d distro) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tool, probe := "aa-enabled", "aa-enabled >/dev/null 2>&1 && echo on || echo off"
	if d.MAC == "selinux" {
		tool, probe = "getenforce", `[ "$(getenforce)" = Enforcing ] && echo on || echo off`
	}
	if _, _, code := ct(ctx, []byte("PATH=$PATH:/usr/sbin:/sbin command -v "+tool+" >/dev/null\n"), "bash", "-s"); code != 0 {
		t.Fatalf("%s is not installed: the MAC state of this release cannot be read", tool)
	}
	out, _, _ := ct(ctx, []byte("PATH=$PATH:/usr/sbin:/sbin\n"+probe+"\n"), "bash", "-s")
	on := strings.TrimSpace(out) == "on"
	if !on && os.Getenv("E2E_MAC") == "1" {
		t.Fatalf("E2E_MAC=1 but %s says this machine does not enforce it", d.MAC)
	}
	return on
}

// utcNow is the machine's UTC wall clock, for journalctl --since.
func utcNow(t *testing.T) string { return sh(t, "date -u '+%Y-%m-%d %H:%M:%S'") }

// epoch is the machine's clock in seconds, for the audit log.
func epoch(t *testing.T) string { return sh(t, "date +%s") }

// denied returns the AppArmor DENIED lines of the kernel log since a time.
func denied(t *testing.T, since string) []string {
	t.Helper()
	out := sh(t, "journalctl -k --utc --since '"+since+"' --no-pager -o cat | grep 'apparmor=\"DENIED\"' || true")
	return nonEmpty(out)
}

// avcs returns the AVC denials of the audit log since an epoch second. ausearch's own -ts parsing
// is not trusted across the VM's clock; the epoch in each record is.
func avcs(t *testing.T, since string) []string {
	t.Helper()
	out := sh(t, `awk -v s=`+since+` '/type=AVC/ { match($0, /audit\(([0-9]+)/, m); if (m[1] >= s) print }' /var/log/audit/audit.log || true`)
	return nonEmpty(out)
}

func nonEmpty(text string) []string {
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// macSince is the marker macDenials takes: the clock the family's log is read with.
func macSince(t *testing.T, d distro) string {
	t.Helper()
	if d.MAC == "selinux" {
		return epoch(t)
	}
	return utcNow(t)
}

// macDenials returns the denials of the release's MAC since the marker that concern us:
// everything the kernel logged except the release's stock denials. Under SELinux the audit log
// also holds the harness's own (incus exec, through a CIL module `incus-agent-harness` in the
// VM, runs in init_t and initrc_t), so only clamd's domain counts there.
func macDenials(t *testing.T, d distro, since string) []string {
	t.Helper()
	if d.MAC == "selinux" {
		var ours []string
		for _, l := range avcs(t, since) {
			if strings.Contains(l, "scontext=system_u:system_r:antivirus_t") {
				ours = append(ours, l)
			}
		}
		return d.notStock(ours)
	}
	return d.notStock(denied(t, since))
}

// has reports whether some line contains every fragment.
func has(lines []string, fragments ...string) bool {
	for _, l := range lines {
		ok := true
		for _, f := range fragments {
			ok = ok && strings.Contains(l, f)
		}
		if ok {
			return true
		}
	}
	return false
}

// aaPreconditions asserts AppArmor really confines clamd and knows the profile; without
// them a pass would mean nothing.
func aaPreconditions(t *testing.T, d distro) {
	t.Helper()
	var st struct {
		Profiles map[string]string `json:"profiles"`
	}
	if err := json.Unmarshal([]byte(sh(t, "aa-status --json")), &st); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"clamfleet-agent-event", "/usr/sbin/clamd"} {
		if st.Profiles[p] != "enforce" {
			t.Fatalf("profile %s is %q in aa-status, want enforce", p, st.Profiles[p])
		}
	}
	// AppArmor 4 and later stack profiles and put the confinement of a process in
	// attr/apparmor/current; the plain attr/current may then hold another LSM's answer or be absent.
	// Read the AppArmor one when it exists, as the kernel documents it.
	pid := "$(systemctl show -p MainPID --value " + d.ClamdUnit + ")"
	cur := sh(t, "f=/proc/"+pid+"/attr/apparmor/current; [ -e \"$f\" ] || f=/proc/"+pid+"/attr/current; cat \"$f\"")
	if cur != "/usr/sbin/clamd (enforce)" {
		t.Fatalf("clamd runs as %q, want '/usr/sbin/clamd (enforce)'", cur)
	}
}

// elPreconditions asserts SELinux is Enforcing, clamd runs in antivirus_t, our module is at
// priority 300 and the spool is labelled; without them a pass would mean nothing.
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

// rpmFile returns the path of a built rpm, failing when it is missing.
func rpmFile(t *testing.T, dir, name, version string) string {
	t.Helper()
	p := filepath.Join(dir, fmt.Sprintf("%s-%s-1.x86_64.rpm", name, version))
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("package %s is missing (run `make packages VERSION=%s`): %v", p, pkgVersionOld, err)
	}
	return p
}

// pkgFile returns the built package of the release's format.
func (d distro) pkgFile(t *testing.T, dir, name, version string) string {
	t.Helper()
	if d.Family == "rpm" {
		return rpmFile(t, dir, name, version)
	}
	return debFile(t, dir, name, version)
}

// installPkgs pushes the files to /root/pkgs and installs or upgrades them with the family's
// tool in one transaction, returning the tool's output.
func (d distro) installPkgs(t *testing.T, upgrade bool, paths ...string) string {
	t.Helper()
	pushPackages(t, paths...)
	var names []string
	for _, p := range paths {
		names = append(names, filepath.Base(p))
	}
	if d.Family == "rpm" {
		verb := "install"
		if upgrade {
			verb = "upgrade"
		}
		return sh(t, "dnf "+verb+" -y"+" /root/pkgs/"+strings.Join(names, " /root/pkgs/")+" 2>&1 </dev/null")
	}
	return aptInstall(t, names...)
}
