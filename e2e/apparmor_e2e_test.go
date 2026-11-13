//go:build e2e && e2e_apparmor

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Milestone 5, decision 7: the detection path on a host where AppArmor enforces
// (docs/plans/milestone-5.md 6.6), run in the throwaway Debian 13 VM by
// `make e2e-apparmor`. The container suite cannot do this: it has no apparmor
// package and clamd runs unconfined there, so a profile that refuses VirusEvent on
// a stock Debian host would pass it.
//
// Same helpers and TestMain as the container suite; the environment points them at
// the VM (CFT_EXEC=$CFA_EXEC, INCUS_HOST=$CFA_HOST, CT=clamfleet-aa, SNAP=clean),
// so every scenario starts from the VM's `clean` snapshot. Needs both build tags, so
// `make e2e` never compiles it. A missing CFA_EXEC fails the target, it never skips.
//
// EICAR files live in /tmp/e2e: Debian's clamd profile allows /tmp/**, and nothing
// under /srv.
package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const aaDir = "/tmp/e2e"

// apparmorRig brings up the server, the sink and the target as in the container,
// then installs the AppArmor files and wires clamd (aa-prepare.sh), and starts the
// agent service. The agent binary goes to /usr/bin: that is the path the profile names.
func apparmorRig(t *testing.T) {
	t.Helper()
	freshServer(t)
	startSink(t)
	sh(t, "install -m 755 /usr/local/bin/clamfleet-agent /usr/bin/clamfleet-agent")
	if err := script("aa-prepare.sh"); err != nil {
		t.Fatal(err)
	}
	waitClamd(t)
	detectionTarget(t, 0)
	startAgentService(t, 30*time.Second)
	waitSpool(t)
	writeEICAR(t, aaDir, "eicar", 1)
}

// utcNow is the container's UTC wall clock, for journalctl --since.
func utcNow(t *testing.T) string { return sh(t, "date -u '+%Y-%m-%d %H:%M:%S'") }

// denied returns the AppArmor DENIED lines of the kernel log since a time.
func denied(t *testing.T, since string) []string {
	t.Helper()
	out := sh(t, "journalctl -k --utc --since '"+since+"' --no-pager -o cat | grep 'apparmor=\"DENIED\"' || true")
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// ours drops the one denial that is not ours: Debian's stock clamd profile does not allow
// clamd to read /etc/hostname, and clamd tries on every detection whether or not a
// VirusEvent is configured (checked on the VM with the line removed). Everything else
// is a finding, for clamd's profile or for the event profile.
func ours(lines []string) []string {
	var out []string
	for _, l := range lines {
		if strings.Contains(l, `profile="/usr/sbin/clamd"`) && strings.Contains(l, `name="/etc/hostname"`) {
			continue
		}
		out = append(out, l)
	}
	return out
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

// preconditions asserts AppArmor really confines clamd and knows the profile; without
// them a pass would mean nothing.
func preconditions(t *testing.T) {
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
	if cur := sh(t, "cat /proc/$(systemctl show -p MainPID --value clamav-daemon)/attr/current"); cur != "/usr/sbin/clamd (enforce)" {
		t.Fatalf("clamd runs as %q, want '/usr/sbin/clamd (enforce)'", cur)
	}
}

// setVirusEvent replaces the VirusEvent line and restarts clamd.
func setVirusEvent(t *testing.T, command string) {
	t.Helper()
	sh(t, "sed -i '/^VirusEvent /d' /etc/clamav/clamd.conf; echo 'VirusEvent "+command+"' >> /etc/clamav/clamd.conf; systemctl restart clamav-daemon")
	waitClamd(t)
}

// The allowed path: an EICAR scan by the confined clamd reaches the sink, our command
// leaves nothing in clamd's journal, and the kernel log has no DENIED line for clamd
// or for the event profile (this covers the open and fsync of events/, the usage
// lock, the link and the unlink), apart from the stock /etc/hostname one (see ours).
func TestAppArmorEICARAlert(t *testing.T) {
	apparmorRig(t)
	preconditions(t)
	since := utcNow(t)
	t0 := time.Now()
	code, took, out := scan(t, aaDir+"/eicar-1.com")
	if code != 1 || !strings.Contains(out, "FOUND") {
		t.Fatalf("clamdscan exit %d: %s", code, out)
	}
	_, _, at := waitDetection(t, aaDir+"/eicar-1.com", 30*time.Second)
	t.Logf("MEASURED (AppArmor enforcing): scan to alert %v, clamdscan returned in %v", at.Sub(t0).Round(100*time.Millisecond), took.Round(time.Millisecond))
	if lines := notSpooled(journal(t, "clamav-daemon")); len(lines) != 0 {
		t.Fatalf("clamd's journal holds lines from our command: %q", lines)
	}
	if d := ours(denied(t, since)); len(d) != 0 {
		t.Fatalf("AppArmor denied something on the allowed path:\n%s", strings.Join(d, "\n"))
	}
	waitSpoolEmpty(t, "events", 10*time.Second)
}

// The transition really happens: the shell inherits clamd's profile and the agent
// is entered under clamfleet-agent-event. VirusEvent points the command at the
// token as its config: the DENIED line must name the event profile. With `ix`
// instead of `Px` it would name /usr/sbin/clamd; unconfined there would be no line.
func TestAppArmorTransitionFromClamd(t *testing.T) {
	apparmorRig(t)
	preconditions(t)
	openUpToken(t)
	setVirusEvent(t, "/usr/bin/clamfleet-agent event --config /etc/clamfleet/token")
	since := utcNow(t)
	if code, _, out := scan(t, aaDir+"/eicar-1.com"); code != 1 {
		t.Fatalf("scan: %d %s", code, out)
	}
	time.Sleep(2 * time.Second)
	d := denied(t, since)
	if !has(d, `profile="clamfleet-agent-event"`, `name="/etc/clamfleet/token"`) {
		t.Fatalf("no DENIED line for the token under profile clamfleet-agent-event:\n%s", strings.Join(d, "\n"))
	}
	if has(d, `profile="/usr/sbin/clamd"`, "token") {
		t.Fatalf("the token was refused under clamd's profile: the transition did not happen (ix instead of Px?):\n%s", strings.Join(d, "\n"))
	}
}

// aaRun runs a clamfleet-agent command as the user clamd runs it as (clamav) under the
// event profile with aa-exec (the CLAM_VIRUSEVENT variables are set for the event command).
// The scenarios loosen the file modes first, so ordinary permissions allow what is tried and
// only AppArmor can refuse; a refusal by the kernel's permission check would not be logged
// by AppArmor at all, and root would not do: without capabilities in the profile a root
// process is refused by the profile's capability rules before any file rule is reached.
// The default config path is used: the profile can read /etc/clamfleet/agent.yaml and nothing
// else of ours.
func aaRun(t *testing.T, args string) (out string, code int) {
	t.Helper()
	stdout, stderr, c := ct(t.Context(), []byte("runuser -u clamav -- env CLAM_VIRUSEVENT_FILENAME=/tmp/e2e/denied.com CLAM_VIRUSEVENT_VIRUSNAME=Sig "+
		"aa-exec -p clamfleet-agent-event -- /usr/bin/clamfleet-agent "+args+" 2>&1\n"), "bash", "-s")
	return stdout + stderr, c
}

// openUpToken makes the token readable by everyone, for the scenarios that point the event
// command at it: with the production mode (root:clamfleet 0640) the kernel's own permission
// check would refuse clamd's user first, and AppArmor would never be asked.
func openUpToken(t *testing.T) { t.Helper(); sh(t, "chmod 644 /etc/clamfleet/token") }

// withAgentConfig replaces /etc/clamfleet/agent.yaml for the duration of a step.
func withAgentConfig(t *testing.T, yaml string, step func()) {
	t.Helper()
	sh(t, "cp /etc/clamfleet/agent.yaml /etc/clamfleet/agent.yaml.orig; cat > /etc/clamfleet/agent.yaml <<'YAML'\n"+yaml+"YAML\nchmod 644 /etc/clamfleet/agent.yaml")
	defer sh(t, "mv /etc/clamfleet/agent.yaml.orig /etc/clamfleet/agent.yaml")
	step()
}

// The profile refuses what it must: the token, writes outside spool/events, the network.
// Each case is run as clamd's user with ordinary permissions loosened (see aaRun), so a
// DENIED line naming the profile can only come from the profile's own rules.
func TestAppArmorEventProfileDenies(t *testing.T) {
	apparmorRig(t)

	// 1. The token as the config file: a permission error, not a YAML error.
	openUpToken(t)
	since := utcNow(t)
	out, code := aaRun(t, "event --config /etc/clamfleet/token")
	if code != 1 || !strings.Contains(out, "permission denied") || strings.Contains(strings.ToLower(out), "yaml") {
		t.Fatalf("event --config token: exit %d: %s", code, out)
	}
	if d := denied(t, since); !has(d, `profile="clamfleet-agent-event"`, `name="/etc/clamfleet/token"`) {
		t.Fatalf("no DENIED line for the token:\n%s", strings.Join(d, "\n"))
	}

	// 2. Writing outside spool/events: a config whose spool.dir is another spool
	// directory that holds a real events/ with the right owner and mode, so the event
	// command's own checks (real directories, owner, sticky) pass and only the profile
	// can refuse. Nothing appears there.
	for _, other := range []string{"reports", "quarantine"} {
		dir := spoolDir + "/" + other
		// 0755 so the kernel's permission check lets clamd's user in: only the profile can refuse.
		sh(t, "install -d -o clamfleet -g clamav -m 3770 "+dir+"/events; chmod 0755 "+dir)
		withAgentConfig(t, "server: https://127.0.0.1:8443\nspool: {dir: "+dir+", max_mb: 1}\n", func() {
			since = utcNow(t)
			out, code = aaRun(t, "event")
		})
		if code != 1 {
			t.Fatalf("event with spool.dir %s: exit %d: %s", other, code, out)
		}
		d := denied(t, since)
		if !has(d, `profile="clamfleet-agent-event"`, "spool/"+other) {
			t.Fatalf("no DENIED line for spool/%s:\n%s\nevent said: %s", other, strings.Join(d, "\n"), out)
		}
		if n := sh(t, "find "+dir+"/events -type f | wc -l"); n != "0" {
			t.Fatalf("%s files appeared in spool/%s/events: the profile did not stop the write", n, other)
		}
	}

	// 3. No network: `run --once` as clamd's user under the profile reads a "token" the profile
	// may read (the host name, one line, token-shaped) and so reaches the connect, which
	// is refused (the profile has no network rule, so AppArmor denies creating the inet socket).
	withAgentConfig(t, "server: https://127.0.0.1:8443\ntoken_file: /proc/sys/kernel/hostname\n", func() {
		since = utcNow(t)
		out, code = aaRun(t, "run --once")
	})
	if code != 1 {
		t.Fatalf("run --once under the event profile: exit %d: %s", code, out)
	}
	if d := denied(t, since); !has(d, `profile="clamfleet-agent-event"`, `class="net"`, `family="inet"`) {
		t.Fatalf("no DENIED line for the inet socket:\n%s\nagent said: %s", strings.Join(d, "\n"), out)
	}
}

// clamd's local lines allow only the shell and our binary: a VirusEvent of
// /usr/bin/touch is refused by clamd's profile, and no file appears.
func TestClamdOnlyExecsTheAgent(t *testing.T) {
	apparmorRig(t)
	setVirusEvent(t, "/usr/bin/touch /tmp/e2e/touched")
	since := utcNow(t)
	if code, _, out := scan(t, aaDir+"/eicar-1.com"); code != 1 {
		t.Fatalf("scan: %d %s", code, out)
	}
	time.Sleep(2 * time.Second)
	d := denied(t, since)
	if !has(d, `profile="/usr/sbin/clamd"`, `operation="exec"`, "touch") {
		t.Fatalf("no DENIED exec line for touch under clamd's profile:\n%s", strings.Join(d, "\n"))
	}
	if n := sh(t, "ls /tmp/e2e/touched 2>/dev/null | wc -l"); n != "0" {
		t.Fatal("touch ran under clamd's profile")
	}
}
