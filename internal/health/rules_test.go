// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package health

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// now is far from the real date on purpose: a time.Now() slipping into the
// rules would show up as a wrong age.
var now = time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

// healthy is a report that matches no rule at `now` with the default thresholds
// (the zero-value freshclam unit is set, daily is fresh, fleet newest = 100).
func healthy() *proto.Report {
	return &proto.Report{
		Schema:          1,
		IntervalSeconds: ptr(300),
		Clamd:           proto.Clamd{Up: true, Version: ptr("1.4.3")},
		Sigs: proto.Sigs{
			Daily: &proto.SigDB{Version: 100, Built: now.Add(-2 * time.Hour), Sigs: 1},
		},
		Freshclam: proto.Freshclam{LastOK: ptr(now.Add(-time.Hour))},
		Services:  proto.Services{Clamd: "active", Freshclam: "active", Clamonacc: "inactive"},
		LastScan:  &proto.LastScan{Finished: now.Add(-time.Hour), Exit: 0},
	}
}

// input builds an Input for a host last seen 1 minute ago whose server started
// long ago, with the healthy report. Tests mutate what they exercise.
func input(r *proto.Report) Input {
	seen := now.Add(-time.Minute)
	return Input{
		Now: now, StartedAt: now.Add(-100 * 24 * time.Hour), CreatedAt: now.Add(-200 * 24 * time.Hour),
		LastSeen: &seen, Report: r, FleetNewestDaily: 100,
	}
}

func rules(r Result) []string {
	var out []string
	for _, x := range r.Reasons {
		out = append(out, x.Rule)
	}
	return out
}

func TestHealthyHostIsOKWithNoReasons(t *testing.T) {
	r := Evaluate(input(healthy()), DefaultThresholds())
	if r.State != StateOK || len(r.Reasons) != 0 {
		t.Fatalf("%+v", r)
	}
}

// Every rule just under and just over its boundary. The comparison is strict
// (">"): the value exactly at the limit does not match.
func TestRuleBoundaries(t *testing.T) {
	th := DefaultThresholds()
	h := func(n int) time.Duration { return time.Duration(n) * time.Hour }
	cases := []struct {
		name   string
		mutate func(in *Input, r *proto.Report)
		want   []string // rules expected, in output order
		state  string
	}{
		{"daily exactly 24h: no warn", func(in *Input, r *proto.Report) { r.Sigs.Daily.Built = now.Add(-h(24)) }, nil, StateOK},
		{"daily 24h+1s: warn", func(in *Input, r *proto.Report) { r.Sigs.Daily.Built = now.Add(-h(24) - time.Second) }, []string{RuleDailyOld}, StateWarn},
		{"daily exactly 72h: warn only", func(in *Input, r *proto.Report) { r.Sigs.Daily.Built = now.Add(-h(72)) }, []string{RuleDailyOld}, StateWarn},
		{"daily 72h+1s: crit replaces warn", func(in *Input, r *proto.Report) { r.Sigs.Daily.Built = now.Add(-h(72) - time.Second) }, []string{RuleDailyOldCrit}, StateCrit},
		{"behind by 2: no warn", func(in *Input, r *proto.Report) { in.FleetNewestDaily = 102 }, nil, StateOK},
		{"behind by 3: warn", func(in *Input, r *proto.Report) { in.FleetNewestDaily = 103 }, []string{RuleDailyBehind}, StateWarn},
		{"ahead of the fleet: no warn", func(in *Input, r *proto.Report) { in.FleetNewestDaily = 50 }, nil, StateOK},
		{"stale at exactly 3 x interval: not stale", func(in *Input, r *proto.Report) { in.LastSeen = ptr(now.Add(-900 * time.Second)) }, nil, StateOK},
		{"stale at 3 x interval + 1s", func(in *Input, r *proto.Report) { in.LastSeen = ptr(now.Add(-901 * time.Second)) }, []string{RuleStale}, StateStale},
		{"scan exit 0 is fine", func(in *Input, r *proto.Report) { r.LastScan.Exit = 0 }, nil, StateOK},
		{"scan exit 1 (infected) is not a failure", func(in *Input, r *proto.Report) { r.LastScan.Exit = 1 }, nil, StateOK},
		{"scan exit 2 is a failure", func(in *Input, r *proto.Report) { r.LastScan.Exit = 2 }, []string{RuleScanFailed}, StateWarn},
		{"scan exactly 48h ago: ok", func(in *Input, r *proto.Report) { r.LastScan.Finished = now.Add(-h(48)) }, nil, StateOK},
		{"scan 48h+1s ago: missed", func(in *Input, r *proto.Report) { r.LastScan.Finished = now.Add(-h(48) - time.Second) }, []string{RuleScanMissed}, StateWarn},
		{"no scan summary at all: no scan rule", func(in *Input, r *proto.Report) { r.LastScan = nil }, nil, StateOK},
		{"clamd down", func(in *Input, r *proto.Report) { r.Clamd.Up = false }, []string{RuleClamdDown}, StateCrit},
		{"daily missing is crit", func(in *Input, r *proto.Report) { r.Sigs.Daily = nil }, []string{RuleDailyMissing}, StateCrit},
		{"freshclam not active", func(in *Input, r *proto.Report) { r.Services.Freshclam = "inactive" }, []string{RuleFreshclamOff}, StateWarn},
		{"freshclam unit not-found counts", func(in *Input, r *proto.Report) { r.Services.Freshclam = proto.ServiceNotFound }, []string{RuleFreshclamOff}, StateWarn},
		{"freshclam state missing counts", func(in *Input, r *proto.Report) { r.Services.Freshclam = "" }, []string{RuleFreshclamOff}, StateWarn},
	}
	for _, tc := range cases {
		in := input(healthy())
		tc.mutate(&in, in.Report)
		got := Evaluate(in, th)
		if got.State != tc.state || !reflect.DeepEqual(rules(got), tc.want) {
			t.Errorf("%s: state %q rules %v, want %q %v", tc.name, got.State, rules(got), tc.state, tc.want)
		}
	}
}

func TestScanMissedCanBeSwitchedOff(t *testing.T) {
	th := DefaultThresholds()
	th.ScanWarnHours = 0
	in := input(healthy())
	in.Report.LastScan.Finished = now.Add(-10000 * time.Hour)
	if got := Evaluate(in, th); got.State != StateOK {
		t.Fatalf("scan_warn_hours=0 must switch the rule off: %+v", got)
	}
}

func TestFreshclamFailedOnlyWhenErrorIsNewerThanSuccess(t *testing.T) {
	th := DefaultThresholds()
	ok, bad := now.Add(-3*time.Hour), now.Add(-2*time.Hour)
	cases := []struct {
		name string
		fc   proto.Freshclam
		want bool
	}{
		{"error after success", proto.Freshclam{LastOK: &ok, LastError: &bad}, true},
		{"success after error (recovered)", proto.Freshclam{LastOK: &bad, LastError: &ok}, false},
		{"error, never a success", proto.Freshclam{LastError: &bad}, true},
		{"same instant is not newer", proto.Freshclam{LastOK: &ok, LastError: &ok}, false},
		{"no error", proto.Freshclam{LastOK: &ok}, false},
		{"nothing known", proto.Freshclam{}, false},
	}
	for _, tc := range cases {
		in := input(healthy())
		in.Report.Freshclam = tc.fc
		got := false
		for _, r := range Evaluate(in, th).Reasons {
			got = got || r.Rule == RuleFreshclamFailed
		}
		if got != tc.want {
			t.Errorf("%s: freshclam_failed = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// STALE wins, CRIT beats WARN, and every matching rule is listed.
func TestSeverityOrderAndAllReasonsListed(t *testing.T) {
	in := input(healthy())
	in.LastSeen = ptr(now.Add(-24 * time.Hour))
	in.Report.Clamd.Up = false
	in.Report.Services.Freshclam = "failed"
	in.Report.LastScan.Exit = 2
	got := Evaluate(in, DefaultThresholds())
	want := []string{RuleStale, RuleClamdDown, RuleFreshclamOff, RuleScanFailed}
	if got.State != StateStale || !reflect.DeepEqual(rules(got), want) {
		t.Fatalf("state %q rules %v, want STALE %v", got.State, rules(got), want)
	}
	sev := []string{StateStale, StateCrit, StateWarn, StateWarn}
	for i, r := range got.Reasons {
		if r.Severity != sev[i] {
			t.Errorf("reason %d (%s) severity %s, want %s", i, r.Rule, r.Severity, sev[i])
		}
	}

	in = input(healthy())
	in.Report.Clamd.Up = false
	in.Report.Services.Freshclam = "inactive"
	if got := Evaluate(in, DefaultThresholds()); got.State != StateCrit {
		t.Fatalf("CRIT must outrank WARN: %+v", got)
	}
}

// Same input, same output, rules sorted by severity then code: M4 renders them.
func TestReasonOrderIsDeterministic(t *testing.T) {
	in := input(healthy())
	in.Report.Services.Freshclam = "inactive"
	in.Report.LastScan.Exit = 2
	in.FleetNewestDaily = 200
	first := Evaluate(in, DefaultThresholds())
	want := []string{RuleDailyBehind, RuleFreshclamOff, RuleScanFailed} // all WARN: by code
	if !reflect.DeepEqual(rules(first), want) {
		t.Fatalf("rules %v, want %v", rules(first), want)
	}
	for i := 0; i < 20; i++ {
		if got := Evaluate(in, DefaultThresholds()); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d differs: %+v vs %+v", i, got, first)
		}
	}
}

func TestNeverReportedPendingThenStale(t *testing.T) {
	th := DefaultThresholds() // 3 x 5m = 15m window
	mk := func(created time.Duration) Input {
		return Input{Now: now, StartedAt: now.Add(-100 * time.Hour), CreatedAt: now.Add(-created)}
	}
	if got := Evaluate(mk(15*time.Minute), th); got.State != StatePending || len(got.Reasons) != 0 {
		t.Fatalf("exactly at the window: %+v, want pending", got)
	}
	got := Evaluate(mk(15*time.Minute+time.Second), th)
	if got.State != StateStale || !reflect.DeepEqual(rules(got), []string{RuleNeverReported}) {
		t.Fatalf("after the window: %+v", got)
	}
}

// A server that was down must not mark the fleet STALE the moment it starts.
func TestRestartGrace(t *testing.T) {
	th := DefaultThresholds()
	in := input(healthy())
	in.LastSeen = ptr(now.Add(-6 * time.Hour)) // silent for hours while the server was down
	in.StartedAt = now
	if got := Evaluate(in, th); got.State != StateOK {
		t.Fatalf("just after a restart: %+v", got)
	}
	in.Now = now.Add(15 * time.Minute) // exactly the window after the start
	if got := Evaluate(in, th); got.State != StateOK {
		t.Fatalf("at the end of the grace window: %+v", got)
	}
	in.Now = now.Add(15*time.Minute + time.Second)
	if got := Evaluate(in, th); got.State != StateStale {
		t.Fatalf("after the grace window: %+v", got)
	}
	// The same grace applies to a host that never reported.
	nr := Input{Now: now, StartedAt: now, CreatedAt: now.Add(-48 * time.Hour)}
	if got := Evaluate(nr, th); got.State != StatePending {
		t.Fatalf("never-reported host right after a restart: %+v", got)
	}
}

// M3 decision 4: the interval comes from the agent, clamped 10 s .. 24 h, with the
// server default as fallback.
func TestIntervalSelection(t *testing.T) {
	th := DefaultThresholds()
	th.DefaultInterval = 7 * time.Minute
	cases := []struct {
		name string
		secs *int
		want time.Duration
	}{
		{"agent value used", ptr(60), time.Minute},
		{"null: server default", nil, 7 * time.Minute},
		{"zero: server default", ptr(0), 7 * time.Minute},
		{"negative: server default", ptr(-5), 7 * time.Minute},
		{"below the floor is raised", ptr(1), 10 * time.Second},
		{"exactly the floor", ptr(10), 10 * time.Second},
		{"above the ceiling is lowered", ptr(7 * 24 * 3600), 24 * time.Hour},
		{"overflow-sized value", ptr(int(^uint(0) >> 1)), 24 * time.Hour},
	}
	for _, tc := range cases {
		r := healthy()
		r.IntervalSeconds = tc.secs
		if got := Interval(input(r), th); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
	if got := Interval(Input{}, th); got != 7*time.Minute {
		t.Fatalf("no report: %s", got)
	}
	// End to end: a 60 s agent is STALE after 3 minutes, not after the default 21.
	in := input(healthy())
	in.Report.IntervalSeconds = ptr(60)
	in.LastSeen = ptr(now.Add(-181 * time.Second))
	if got := Evaluate(in, th); got.State != StateStale {
		t.Fatalf("%+v", got)
	}
}

func TestAgentTextHasNoControlCharacters(t *testing.T) {
	in := input(healthy())
	in.Report.Clamd.Up = false
	in.Report.Clamd.Error = ptr("bad\x1b[2Jthing\nnext")
	msg := Evaluate(in, DefaultThresholds()).Reasons[0].Msg
	if strings.ContainsAny(msg, "\x1b\n") {
		t.Fatalf("control characters survived: %q", msg)
	}
	in.Report.Clamd.Error = ptr("harmless\u202etxt.exe \u200b\u2066x")
	if msg := Evaluate(in, DefaultThresholds()).Reasons[0].Msg; strings.ContainsAny(msg, "\u202e\u200b\u2066") {
		t.Fatalf("format/bidi characters survived: %q", msg)
	}
	in.Report.Clamd.Error = nil
	in.Report.Clamd.Up = true
	in.Report.Services.Freshclam = "evil\x07"
	for _, r := range Evaluate(in, DefaultThresholds()).Reasons {
		if strings.ContainsRune(r.Msg, 7) {
			t.Fatalf("control character in %q", r.Msg)
		}
	}
}

func TestClamdErrorTextIsIncludedButBounded(t *testing.T) {
	in := input(healthy())
	in.Report.Clamd.Up = false
	in.Report.Clamd.Error = ptr("ping: timeout")
	got := Evaluate(in, DefaultThresholds())
	if len(got.Reasons) != 1 || !strings.Contains(got.Reasons[0].Msg, "ping: timeout") {
		t.Fatalf("%+v", got)
	}
	in.Report.Clamd.Error = ptr(strings.Repeat("é", 5000))
	msg := Evaluate(in, DefaultThresholds()).Reasons[0].Msg
	if len(msg) > 400 || !strings.HasSuffix(msg, "...") {
		t.Fatalf("agent text not bounded: %d bytes", len(msg))
	}
	if strings.ContainsRune(strings.TrimSuffix(msg, "..."), 0xFFFD) {
		t.Fatal("truncation cut a rune in half")
	}
}

// A host that reports but whose stored report is corrupt is judged from
// last_seen, with its own reason; it is not "never reported".
func TestUnreadableReport(t *testing.T) {
	th := DefaultThresholds() // window 15 m
	mk := func(silent time.Duration) Input {
		seen := now.Add(-silent)
		return Input{Now: now, StartedAt: now.Add(-100 * 24 * time.Hour), CreatedAt: now.Add(-200 * 24 * time.Hour),
			LastSeen: &seen, ReportUnreadable: true}
	}
	got := Evaluate(mk(time.Minute), th)
	if got.State != StateWarn || !reflect.DeepEqual(rules(got), []string{RuleReportUnreadable}) {
		t.Fatalf("reporting host: %+v", got)
	}
	if got := Evaluate(mk(15*time.Minute), th); got.State != StateWarn {
		t.Fatalf("at the window: %+v", got)
	}
	got = Evaluate(mk(15*time.Minute+time.Second), th)
	if got.State != StateStale || !reflect.DeepEqual(rules(got), []string{RuleStale, RuleReportUnreadable}) {
		t.Fatalf("silent host: %+v", got)
	}
	// Without last_seen the flag changes nothing: a host that never reported.
	nr := Input{Now: now, StartedAt: now.Add(-time.Hour), CreatedAt: now.Add(-time.Hour), ReportUnreadable: true}
	if got := Evaluate(nr, th); !reflect.DeepEqual(rules(got), []string{RuleNeverReported}) {
		t.Fatalf("%+v", got)
	}
}

// virusevent_missing fires only for an explicit "none": null (clamd.conf not
// readable, or an agent from before milestone 5) and "other" (a wrapper we
// cannot see into) stay quiet, and the switch turns it off.
func TestVirusEventMissing(t *testing.T) {
	for _, c := range []struct {
		name    string
		value   *string
		require bool
		want    []string
	}{
		{"none fires", ptr(proto.VirusEventNone), true, []string{RuleVirusEventMissing}},
		{"clamfleet is fine", ptr(proto.VirusEventClamfleet), true, nil},
		{"other is not judged", ptr(proto.VirusEventOther), true, nil},
		{"null is not judged", nil, true, nil},
		{"switched off", ptr(proto.VirusEventNone), false, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := healthy()
			r.Clamd.VirusEvent = c.value
			th := DefaultThresholds()
			th.RequireVirusEvent = c.require
			res := Evaluate(input(r), th)
			if got := rules(res); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("rules = %v, want %v", got, c.want)
			}
			if len(c.want) > 0 && res.State != StateWarn {
				t.Fatalf("state %s, want WARN", res.State)
			}
		})
	}
	if !DefaultThresholds().RequireVirusEvent {
		t.Fatal("the rule is on by default")
	}
}
