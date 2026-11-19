// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// The per-release facts table, its lookup and the stock-denial filter, with the test that
// validates every row.
//
// Why a separate, untagged file: a row with an empty field fails far from its cause. An
// `All: nil` stock denial matches every log line and silently turns every MAC denial check
// green; an empty AgentGroups makes the group assertion vacuous. TestDistroFacts catches that
// in plain `make check`, with no VM, so it must compile without the e2e tags. Nothing here may
// import or call e2e-only code (sh, ct, TestMain live under the e2e tags); the helpers that need
// a machine stay in distro_test.go.
//
// Why: what differs between the releases we claim (unit names, the clamd configuration path,
// the group clamd's user is in, where an EICAR file may live under the release's own MAC
// policy, the example configuration a package installs, the stock denials a release's own
// clamd policy produces) used to be hard-coded in the suite of whichever VM first needed it.
// A table row is the one place a new release is described, and a release with no row FAILS: a
// default would test the new release as if it were Debian 13 and pass for the wrong reason.
//
// A row is added only together with the run that observed its facts (the stock denials in
// particular are read from a real run with our VirusEvent removed, never guessed): a
// release without that evidence stays out of the table and fails loudly.
package e2e

import (
	"fmt"
	"strings"
	"testing"
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
		return distro{}, fmt.Errorf("no facts for release %q: add a row to distros in e2e/distro_facts_test.go, with the run that observed it", key)
	}
	return d, nil
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

// TestDistroFacts validates every row and the lookup, so that a row with an empty field cannot
// pass for a row with evidence.
func TestDistroFacts(t *testing.T) {
	for key, d := range distros {
		t.Run(key, func(t *testing.T) {
			if d.Family != "deb" && d.Family != "rpm" {
				t.Errorf("Family = %q, want deb or rpm", d.Family)
			}
			if d.MAC != "apparmor" && d.MAC != "selinux" {
				t.Errorf("MAC = %q, want apparmor or selinux", d.MAC)
			}
			for name, v := range map[string]string{
				"ClamdUnit": d.ClamdUnit, "FreshclamUnit": d.FreshclamUnit, "ClamdConf": d.ClamdConf,
				"ClamdGroup": d.ClamdGroup, "EICARDir": d.EICARDir, "Example": d.Example,
			} {
				if strings.TrimSpace(v) == "" {
					t.Errorf("%s is empty", name)
				}
			}
			if len(d.AgentGroups) == 0 {
				t.Error("AgentGroups is empty: the group assertion would be vacuous")
			}
			for _, g := range d.AgentGroups {
				if strings.TrimSpace(g) == "" {
					t.Error("AgentGroups holds an empty group")
				}
			}
			for i, s := range d.StockDenials {
				if len(s.All) == 0 {
					t.Errorf("StockDenials[%d] has no fragment: it would match every denial", i)
				}
				for _, f := range s.All {
					if strings.TrimSpace(f) == "" {
						t.Errorf("StockDenials[%d] has an empty fragment: it would match every denial", i)
					}
				}
				if strings.TrimSpace(s.Why) == "" {
					t.Errorf("StockDenials[%d] has no Why", i)
				}
			}
		})
	}

	for _, c := range [][2]string{{"debian", "99"}, {"", ""}} {
		if _, err := lookupDistro(c[0], c[1]); err == nil {
			t.Errorf("lookupDistro(%q, %q) succeeded, want an error", c[0], c[1])
		}
	}
	// The RHEL family is keyed by the major version: the minor changes with every point release.
	d, err := lookupDistro("almalinux", "9.8")
	if err != nil {
		t.Fatal(err)
	}
	if d.Family != "rpm" || d.MAC != "selinux" {
		t.Errorf("almalinux 9.8 resolved to %+v", d)
	}
}

// TestNotStock pins the filter: a line holding every fragment of a stock denial is dropped, a
// line holding only some of them is a finding and stays.
func TestNotStock(t *testing.T) {
	d := distro{StockDenials: []stockDenial{{All: []string{"a", "b"}, Why: "test"}}}
	got := d.notStock([]string{"xx a yy b", "only a", "other"})
	if len(got) != 2 || got[0] != "only a" || got[1] != "other" {
		t.Errorf("notStock = %q, want [only a, other]", got)
	}
}
