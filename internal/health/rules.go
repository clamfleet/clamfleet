// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package health decides a host's state (spec 9) and keeps it current.
//
// rules.go: the pure part. Evaluate maps what the server knows about one host
// to a state (OK < WARN < CRIT < STALE) and the list of reasons behind it. It
// performs no I/O and reads no clock: "now" and the server start time are
// inputs, so every boundary is testable to the second.
//
// Dependencies: internal/proto only. The evaluator (evaluator.go) adds the
// store and the loop.
package health

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// States. The state is stored as this text; Go validates it (no CHECK
// constraint in the schema, so a new state is never a table rebuild).
const (
	// StatePending is the empty string: not evaluated yet. The database holds
	// NULL for it. A host is pending from registration until its first report
	// (or until the STALE window passes with none, see never_reported).
	StatePending = ""
	StateOK      = "OK"
	StateWarn    = "WARN"
	StateCrit    = "CRIT"
	StateStale   = "STALE"
)

// Reason codes. They are a stable public vocabulary: alert templates (M4) and
// the UI key on them, so never rename one.
const (
	RuleStale            = "stale"
	RuleNeverReported    = "never_reported"
	RuleReportUnreadable = "report_unreadable"
	RuleClamdDown        = "clamd_down"
	RuleDailyMissing     = "daily_missing"
	RuleDailyOldCrit     = "daily_old_crit"
	RuleDailyOld         = "daily_old"
	RuleFreshclamFailed  = "freshclam_failed"
	RuleFreshclamOff     = "freshclam_inactive"
	RuleDailyBehind      = "daily_behind"
	RuleScanFailed       = "scan_failed"
	RuleScanMissed       = "scan_missed"
)

const (
	// Bounds of the agent-supplied interval (see Interval).
	minAgentInterval = 10 * time.Second
	maxAgentInterval = 24 * time.Hour
	// maxClamdErrorInReason keeps agent text in a reason short.
	maxClamdErrorInReason = 200
)

// Thresholds are the tunable numbers of the rules (server config `health:`).
type Thresholds struct {
	// StaleFactor: STALE after this many report intervals without a report.
	StaleFactor int
	// DefaultInterval is used for a host whose report carries no (usable)
	// interval_seconds: older agents, or a host that never reported.
	DefaultInterval time.Duration
	// DailyWarnHours and DailyCritHours: age of the daily database.
	DailyWarnHours, DailyCritHours int
	// BehindWarn: WARN when the daily version trails the fleet's newest by
	// more than this many versions.
	BehindWarn int
	// ScanWarnHours: WARN when the last scan finished longer ago. 0 = off.
	ScanWarnHours int
}

// DefaultThresholds are the spec 9 defaults plus the plan's additions
// (docs/plans/milestone-3.md 4.6).
func DefaultThresholds() Thresholds {
	return Thresholds{
		StaleFactor: 3, DefaultInterval: 5 * time.Minute,
		DailyWarnHours: 24, DailyCritHours: 72,
		BehindWarn: 2, ScanWarnHours: 48,
	}
}

// Input is everything Evaluate needs about one host.
type Input struct {
	// Now is the injected clock; StartedAt is when this server process (its
	// evaluator) started.
	Now, StartedAt time.Time
	// CreatedAt is when the host was registered.
	CreatedAt time.Time
	// LastSeen is the server time of the last accepted report, nil if none.
	LastSeen *time.Time
	// Report is the newest report, nil before the first one.
	Report *proto.Report
	// ReportUnreadable: a report is stored but could not be decoded (Report is
	// nil). The host did report, so it is judged from LastSeen, not as new.
	ReportUnreadable bool
	// FleetNewestDaily is the highest daily version among hosts with a token
	// (0 if none): the yardstick of daily_behind.
	FleetNewestDaily int
}

// Reason says why a host is not OK. Msg is for humans; agent-supplied text in
// it (clamd.error, a unit state) is untrusted and must be escaped on output.
type Reason struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"` // WARN, CRIT or STALE
	Msg      string `json:"msg"`
}

// Result is the outcome of Evaluate. State is StatePending (empty) only for a
// host that has not reported and is still inside its STALE window; Reasons is
// then empty. An OK host has no reasons.
type Result struct {
	State   string
	Reasons []Reason
}

func severityRank(s string) int {
	switch s {
	case StateStale:
		return 3
	case StateCrit:
		return 2
	case StateWarn:
		return 1
	}
	return 0
}

// Interval returns the report interval the STALE rule uses for this input:
// the agent's own interval_seconds clamped to 10 s .. 24 h (it is
// agent-supplied: 0 would make every host instantly STALE, a huge value would
// make a dead host look alive for years), else th.DefaultInterval.
func Interval(in Input, th Thresholds) time.Duration {
	if in.Report != nil && in.Report.IntervalSeconds != nil && *in.Report.IntervalSeconds > 0 {
		// Compare in seconds first: converting a huge int to Duration could overflow.
		s := int64(*in.Report.IntervalSeconds)
		d := maxAgentInterval
		if s < int64(maxAgentInterval/time.Second) {
			d = time.Duration(s) * time.Second
		}
		return max(d, minAgentInterval)
	}
	return th.DefaultInterval
}

// Evaluate applies every rule of spec 9 (thresholds from th) and returns the
// state with all matching reasons, ordered by severity (highest first), then
// by rule code, so the output is deterministic.
//
// Rule: STALE outranks CRIT outranks WARN, but STALE does not hide the other
// reasons: they are computed from the last report and listed, so the operator
// sees what the host looked like when it went silent.
//
// Rule: staleness is measured from max(last_seen, StartedAt) (restart grace).
// A server that was down for an hour must not mark the whole fleet STALE the
// moment it starts: agents could not report to it, and in M4 that would be an
// alert storm caused by our own downtime.
func Evaluate(in Input, th Thresholds) Result {
	var rs []Reason
	add := func(rule, sev, format string, args ...any) {
		rs = append(rs, Reason{Rule: rule, Severity: sev, Msg: fmt.Sprintf(format, args...)})
	}

	window := time.Duration(th.StaleFactor) * Interval(in, th)
	if in.Report == nil && in.ReportUnreadable && in.LastSeen != nil {
		// The host reports but its stored report is corrupt. Calling it
		// never_reported (measured from registration) would be false: judge
		// staleness from last_seen like any host, and say what is wrong.
		add(RuleReportUnreadable, StateWarn, "the stored report of this host cannot be read; its other rules are not evaluated")
		if age := in.Now.Sub(latest(*in.LastSeen, in.StartedAt)); age > window {
			add(RuleStale, StateStale, "no report for %s (limit %s)", age.Truncate(time.Second), window)
		}
		state := StateWarn
		if len(rs) > 1 {
			state = StateStale
			rs[0], rs[1] = rs[1], rs[0] // STALE first, as everywhere
		}
		return Result{State: state, Reasons: rs}
	}
	if in.Report == nil {
		// Never reported. Pending until the window has passed since the later of
		// registration and server start; then STALE, so a host whose agent was
		// never installed does not stay "pending" forever.
		ref := latest(in.CreatedAt, in.StartedAt)
		if in.Now.Sub(ref) > window {
			add(RuleNeverReported, StateStale, "no report received since the host was registered (%s)", window)
			return Result{State: StateStale, Reasons: rs}
		}
		return Result{State: StatePending}
	}

	ref := in.StartedAt
	if in.LastSeen != nil {
		ref = latest(*in.LastSeen, in.StartedAt)
	}
	if age := in.Now.Sub(ref); age > window {
		add(RuleStale, StateStale, "no report for %s (limit %s)", age.Truncate(time.Second), window)
	}

	r := in.Report
	if !r.Clamd.Up {
		if r.Clamd.Error != nil && *r.Clamd.Error != "" {
			add(RuleClamdDown, StateCrit, "clamd is not answering: %s", truncate(*r.Clamd.Error, maxClamdErrorInReason))
		} else {
			add(RuleClamdDown, StateCrit, "clamd is not answering")
		}
	}

	if d := r.Sigs.Daily; d == nil {
		add(RuleDailyMissing, StateCrit, "the daily signature database is missing or unreadable")
	} else {
		age := in.Now.Sub(d.Built)
		switch {
		case age > time.Duration(th.DailyCritHours)*time.Hour:
			add(RuleDailyOldCrit, StateCrit, "daily signatures are %s old (limit %dh)", age.Truncate(time.Minute), th.DailyCritHours)
		case age > time.Duration(th.DailyWarnHours)*time.Hour:
			add(RuleDailyOld, StateWarn, "daily signatures are %s old (limit %dh)", age.Truncate(time.Minute), th.DailyWarnHours)
		}
		if in.FleetNewestDaily-d.Version > th.BehindWarn {
			add(RuleDailyBehind, StateWarn, "daily version %d is %d behind the fleet's newest (%d)", d.Version, in.FleetNewestDaily-d.Version, in.FleetNewestDaily)
		}
	}

	if fc := r.Freshclam; fc.LastError != nil && (fc.LastOK == nil || fc.LastError.After(*fc.LastOK)) {
		add(RuleFreshclamFailed, StateWarn, "the last signature update failed")
	}
	if r.Services.Freshclam != "active" {
		// not-found and unknown count: a freshclam that is not running is why
		// signatures go old, whichever way it is missing (decision 6).
		state := r.Services.Freshclam
		if state == "" {
			state = proto.ServiceUnknown
		}
		add(RuleFreshclamOff, StateWarn, "the freshclam service is %s", truncate(state, 64))
	}

	if ls := r.LastScan; ls != nil {
		// Exit 1 means "virus found": detections are tracked as events, not as a
		// failed scan. 2 and above is clamscan's own error.
		if ls.Exit >= 2 {
			add(RuleScanFailed, StateWarn, "the last scan failed (exit %d)", ls.Exit)
		}
		if th.ScanWarnHours > 0 && in.Now.Sub(ls.Finished) > time.Duration(th.ScanWarnHours)*time.Hour {
			add(RuleScanMissed, StateWarn, "no scan finished in the last %dh", th.ScanWarnHours)
		}
	}

	state := StateOK
	for _, x := range rs {
		if severityRank(x.Severity) > severityRank(state) {
			state = x.Severity
		}
	}
	sort.SliceStable(rs, func(i, j int) bool {
		if a, b := severityRank(rs[i].Severity), severityRank(rs[j].Severity); a != b {
			return a > b
		}
		return rs[i].Rule < rs[j].Rule
	})
	return Result{State: state, Reasons: rs}
}

func latest(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// truncate cleans agent-supplied text for a reason and shortens it to at most
// n bytes on a rune boundary. Control and Unicode format characters (an ESC
// sequence in clamd.error, a right-to-left override) become spaces: the CLI prints reasons to a terminal, and the
// agent is not a trusted author.
func truncate(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		// Cf (format) includes the bidi overrides (U+202E) that make text
		// display in a different order than it is written.
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 { // do not cut inside a multi-byte rune
		n--
	}
	return s[:n] + "..."
}
