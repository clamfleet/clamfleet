// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import "testing"

func TestParseVirusEvent(t *testing.T) {
	for _, c := range []struct {
		name, conf, want string
	}{
		{"unset", "LocalSocket /run/clamd.sock\n", "none"},
		{"empty file", "", "none"},
		{"commented out", "#VirusEvent /usr/bin/clamfleet-agent event\n", "none"},
		{"lowercase key is not an option clamd knows", "virusevent /usr/bin/clamfleet-agent event\n", "none"},
		{"clamfleet", "VirusEvent /usr/bin/clamfleet-agent event\n", "clamfleet"},
		{"clamfleet with tab and leading blanks", "  \tVirusEvent\t/usr/local/bin/clamfleet-agent event\n", "clamfleet"},
		{"clamfleet with extra flag", "VirusEvent /usr/bin/clamfleet-agent event --config /etc/clamfleet/agent.yaml\n", "clamfleet"},
		{"quoted", "VirusEvent \"/usr/bin/clamfleet-agent event\"\n", "clamfleet"},
		{"inline comment", "VirusEvent /usr/bin/clamfleet-agent event # for ClamFleet\n", "clamfleet"},
		{"run is not event", "VirusEvent /usr/bin/clamfleet-agent run\n", "other"},
		{"a wrapper script", "VirusEvent /usr/local/bin/notify-and-report\n", "other"},
		{"another binary mentioning ours", "VirusEvent /usr/bin/logger clamfleet-agent event\n", "other"},
		{"first occurrence wins (other first)", "VirusEvent /bin/true\nVirusEvent /usr/bin/clamfleet-agent event\n", "other"},
		{"first occurrence wins (ours first)", "VirusEvent /usr/bin/clamfleet-agent event\nVirusEvent /bin/true\n", "clamfleet"},
		{"commented line does not count as first", "#VirusEvent /bin/true\nVirusEvent /usr/bin/clamfleet-agent event\n", "clamfleet"},
		{"unterminated quote", "VirusEvent \"/usr/bin/clamfleet-agent event\n", "none"},
		{"key without value", "VirusEvent\nLocalSocket /x\n", "none"},
		{"only a comment as value", "VirusEvent # nothing\n", "none"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := ParseVirusEvent([]byte(c.conf)); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

// The collector reports what clamd.conf says, and null (not "none") when the
// file cannot be read: an unknown must never raise the health warning.
func TestCollectVirusEvent(t *testing.T) {
	c, _ := fullTree(t, healthyUnits)
	r, _, err := c.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if r.Clamd.VirusEvent == nil || *r.Clamd.VirusEvent != "none" {
		t.Fatalf("virus_event = %v, want none", r.Clamd.VirusEvent)
	}
	c.Cfg.ClamdConf += ".missing"
	r, _, err = c.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if r.Clamd.VirusEvent != nil {
		t.Fatalf("virus_event = %q, want null for an unreadable clamd.conf", *r.Clamd.VirusEvent)
	}
}
