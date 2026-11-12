//go:build e2e

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Milestone 3 acceptance (spec 14), in the container, with the real server and
// the real agent as services: stopping clamd turns the host CRIT within one
// report interval, and stopping the agent turns it STALE after three intervals (see staleInterval for why the interval is 10 s).
// The state is read the way an operator reads it, through `host show --json`.
//
// The server runs with deploy/test/server.yaml, whose health: block raises the
// signature-age thresholds (the snapshot's signatures are frozen, so without it
// the host starts CRIT and the clamd transition would be invisible) and sets
// eval_interval to 2s. The baseline is therefore WARN (freshclam_inactive), and
// each test asserts that first.
package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The agent's report interval in these tests. The server clamps the agent's
// interval_seconds to at least 10 s (it is agent-supplied: see health.Interval),
// so the STALE test cannot use a 5 s interval: it would be judged as 10 s and the
// window would be 30 s, not 15 s. The CRIT test does not depend on the window, so
// it keeps the faster 5 s interval to stay short.
const (
	critInterval  = 5 * time.Second
	staleInterval = 10 * time.Second // the clamp floor; window = 3 x 10 s = 30 s
)

type healthHost struct {
	LastSeen    *time.Time `json:"last_seen"`
	State       *string    `json:"state"`
	StateReason []struct {
		Rule     string `json:"rule"`
		Severity string `json:"severity"`
		Msg      string `json:"msg"`
	} `json:"state_reason"`
	StateChanges []struct {
		TS   time.Time `json:"ts"`
		From *string   `json:"from_state"`
		To   string    `json:"to_state"`
	} `json:"state_changes"` // newest first
}

func (h healthHost) state() string {
	if h.State == nil {
		return "pending"
	}
	return *h.State
}

func (h healthHost) hasRule(rule string) bool {
	for _, r := range h.StateReason {
		if r.Rule == rule {
			return true
		}
	}
	return false
}

func showHealth(t *testing.T) healthHost {
	t.Helper()
	var h healthHost
	if err := json.Unmarshal([]byte(srvCLI(t, "host", "show", hostName, "--json")), &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// waitHealth polls until the host is in state want or the timeout passes, and
// returns the last view either way (the caller asserts on it).
func waitHealth(t *testing.T, want string, timeout time.Duration) healthHost {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		h := showHealth(t)
		if h.state() == want || time.Now().After(deadline) {
			return h
		}
		time.Sleep(time.Second)
	}
}

// startAgentService runs the real agent as a service at the given interval.
func startAgentService(t *testing.T, interval time.Duration) {
	t.Helper()
	sh(t, "systemd-run --quiet --collect --unit="+agentUnit+" --uid=clamfleet "+
		"--setenv=SSL_CERT_FILE=/etc/clamfleet/ca.pem --setenv=CLAMFLEET_AGENT_INTERVAL="+interval.String()+" "+
		"/usr/local/bin/clamfleet-agent run")
}

// historyOf lists "from>to" oldest first, for failure messages.
func (h healthHost) historyOf() string {
	var parts []string
	for i := len(h.StateChanges) - 1; i >= 0; i-- {
		c := h.StateChanges[i]
		from := "none"
		if c.From != nil {
			from = *c.From
		}
		parts = append(parts, from+">"+c.To)
	}
	return strings.Join(parts, " ")
}

func TestHealthClamdStoppedTurnsCrit(t *testing.T) {
	freshServer(t)
	startAgentService(t, critInterval)

	base := waitHealth(t, "WARN", 30*time.Second)
	if base.state() != "WARN" || !base.hasRule("freshclam_inactive") || len(base.StateReason) != 1 {
		t.Fatalf("baseline: state %s reasons %+v (want exactly WARN freshclam_inactive)\nagent journal:\n%s", base.state(), base.StateReason, journal(t, agentUnit))
	}

	// Stopping the service alone is not enough on Debian: the socket unit would
	// start it again on the next connection (docs/testing.md).
	sh(t, "systemctl stop clamav-daemon.socket clamav-daemon.service")
	// Within one report interval, plus slack for collection and the request.
	crit := waitHealth(t, "CRIT", critInterval+5*time.Second)
	if crit.state() != "CRIT" || !crit.hasRule("clamd_down") {
		t.Fatalf("after stopping clamd: state %s reasons %+v history %s\nagent journal:\n%s",
			crit.state(), crit.StateReason, crit.historyOf(), journal(t, agentUnit))
	}
	last := crit.StateChanges[0]
	if last.From == nil || *last.From != "WARN" || last.To != "CRIT" {
		t.Fatalf("last transition is not WARN>CRIT: %s", crit.historyOf())
	}

	// Recovery: clamd back (really able to scan), and the next report clears the CRIT.
	sh(t, "systemctl start clamav-daemon.socket clamav-daemon.service")
	waitClamd(t)
	back := waitHealth(t, "WARN", 30*time.Second)
	if back.state() != "WARN" || back.hasRule("clamd_down") {
		t.Fatalf("after restarting clamd: state %s reasons %+v history %s", back.state(), back.StateReason, back.historyOf())
	}
	if got, want := back.historyOf(), "none>WARN WARN>CRIT CRIT>WARN"; got != want {
		t.Fatalf("history %q, want %q", got, want)
	}
}

func TestHealthAgentStoppedTurnsStale(t *testing.T) {
	freshServer(t)
	startAgentService(t, staleInterval)

	base := waitHealth(t, "WARN", 30*time.Second)
	if base.state() != "WARN" {
		t.Fatalf("baseline: state %s reasons %+v\nagent journal:\n%s", base.state(), base.StateReason, journal(t, agentUnit))
	}
	sh(t, "systemctl stop "+agentUnit)

	// 18 s after the stop the host is at most 10 + 18 = 28 s silent: inside the
	// 3 x 10 s = 30 s window, so it must not be STALE yet.
	time.Sleep(18 * time.Second)
	if h := showHealth(t); h.state() == "STALE" {
		t.Fatalf("STALE after only ~28 s of silence (limit 30 s): %s", h.historyOf())
	}

	stale := waitHealth(t, "STALE", 30*time.Second)
	if stale.state() != "STALE" || !stale.hasRule("stale") {
		t.Fatalf("agent stopped: state %s reasons %+v history %s", stale.state(), stale.StateReason, stale.historyOf())
	}
	// Measured on the server's own clock (last_seen and the transition time are
	// both server time), so no clock of the test host or the agent is involved:
	// STALE only after 30 s of silence, and noticed within one evaluation
	// interval (2 s) plus slack.
	silence := stale.StateChanges[0].TS.Sub(*stale.LastSeen)
	if silence < 30*time.Second || silence > 30*time.Second+2*time.Second+5*time.Second {
		t.Fatalf("STALE came after %s of silence, want between 30 s and 37 s", silence)
	}
	n := 0
	for _, c := range stale.StateChanges {
		if c.To == "STALE" {
			n++
		}
	}
	if n != 1 || stale.StateChanges[0].From == nil || *stale.StateChanges[0].From != "WARN" {
		t.Fatalf("want exactly one WARN>STALE transition, history %s", stale.historyOf())
	}
	// The reasons keep what the last report said: STALE does not hide them.
	if !stale.hasRule("freshclam_inactive") {
		t.Errorf("STALE hid the other reasons: %+v", stale.StateReason)
	}
}
