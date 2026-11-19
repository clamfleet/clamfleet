//go:build e2e && (e2e_apparmor || e2e_el9 || e2e_distro)

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// The helpers every distribution-aware suite shares: the AppArmor suite (e2e_apparmor), the
// SELinux suite (e2e_el9) and the format-neutral TestDistro* scenarios (distro_e2e_test.go,
// e2e_distro). The per-release facts table they read is in distro_facts_test.go, untagged so
// that its validation runs in plain `make check`.
//
// Build constraint: compiled only when one of the suites that uses it is, so a plain `make e2e` build
// (and staticcheck on that tag set) never sees helpers nothing in it calls.
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

// macEnforced reports whether this machine's own mandatory access control confines clamd:
// AppArmor enabled (deb family) or SELinux Enforcing (rpm family). The L2 containers share the
// host's kernel, which has neither, and the scenarios then skip only the MAC steps. The VM
// targets set E2E_MAC=1: there a machine where it is off is a broken VM, and the answer
// "no" must fail instead of letting the scenario pass without any confinement. A missing
// tool fails too: "tool absent" must never read as "MAC off".
// The L2 container targets set E2E_MAC=0: a container reports the RUNNER's kernel, and the
// runner is an Ubuntu VM with AppArmor on, where aa-enabled can answer yes inside a privileged
// container that clamd is in no way confined by. 0 means "this level has no MAC", asserted by
// the caller, not probed; the tool must still be installed.
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
	if os.Getenv("E2E_MAC") == "0" {
		return false
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

// elPreconditions asserts SELinux is Enforcing, clamd runs in the release's domain
// (d.ClamdDomain: antivirus_t, or unconfined_service_t on EL10), our module is at priority 300
// and the spool is labelled; without them a pass would mean nothing.
func elPreconditions(t *testing.T, d distro) {
	t.Helper()
	if got := sh(t, "getenforce"); got != "Enforcing" {
		t.Fatalf("getenforce = %q, want Enforcing", got)
	}
	if ps := sh(t, "ps -eZ | grep ' clamd$' || true"); !strings.Contains(ps, ":"+d.ClamdDomain+":") {
		t.Fatalf("clamd runs as %q, want %s", ps, d.ClamdDomain)
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
