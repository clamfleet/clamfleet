// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// collect.go: builds one proto.Report from the local ClamAV installation.
//
// Responsibilities: the Collector, which runs every source in a fixed order,
// turns each failure into a Problem plus a null or degraded field (only a
// hostname failure aborts), and enforces decision Q4: the clamd socket is
// probed only when that cannot start clamd.
// Dependencies: the other collectors in this package, and the proto package.
// All outside effects (clock, zone, exec, hostname) are injected.

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// collectDeadline bounds one whole collection (spec 13: negligible CPU).
const collectDeadline = 20 * time.Second

// Problem is a non-fatal failure of one data source. The report still goes
// out with that part null or degraded; problems are logged, not sent
// (decision Q9: the payload has no "problems" field).
type Problem struct {
	Source string
	Err    error
}

func (p Problem) Error() string { return fmt.Sprintf("%s: %v", p.Source, p.Err) }

// Collector builds a proto.Report from the local ClamAV installation. All
// outside effects are injectable, so tests use no real clock, zone, systemctl
// or hostname.
type Collector struct {
	Cfg     Config
	Version string // agent version for the report
	// Now is the only clock: report ts must never come from time.Now().
	Now func() time.Time
	// Loc is the host's zone, for freshclam's zone-less log timestamps.
	Loc            *time.Location
	Exec           ExecFunc
	Hostname       func() (string, error)
	OSReleasePaths []string
	// ClamdTimeout is the per-connection socket deadline; 0 means 3 s.
	ClamdTimeout time.Duration
}

// Collect gathers every source in turn. No source can abort the report: each
// failure becomes a Problem and a null or degraded field. The only error is a
// hostname failure, since the host name is the report's identity.
func (c *Collector) Collect(ctx context.Context) (proto.Report, []Problem, error) {
	ctx, cancel := context.WithTimeout(ctx, collectDeadline)
	defer cancel()

	host, err := c.Hostname()
	if err != nil {
		return proto.Report{}, nil, fmt.Errorf("hostname: %w", err)
	}
	tags := append([]string{}, c.Cfg.Tags...)
	r := proto.Report{
		Schema:       proto.SchemaVersion,
		Host:         host,
		AgentVersion: c.Version,
		Tags:         tags,
		TS:           proto.UTC(c.Now()),
	}
	var problems []Problem
	add := func(p ...Problem) { problems = append(problems, p...) }

	osr, err := readOSRelease(c.OSReleasePaths)
	if err != nil {
		add(Problem{"os", err})
	}
	r.OS = osr

	// Services first: the clamd unit state decides whether the socket may be touched.
	var svp []Problem
	r.Services, svp = c.collectServices(ctx)
	add(svp...)

	r.Clamd = c.collectClamdGuarded(ctx, r.Services.Clamd, &problems)

	var sp []Problem
	r.Sigs, sp = collectSigs(c.Cfg.DBDir)
	add(sp...)

	var fp []Problem
	r.Freshclam, fp = c.collectFreshclam(ctx)
	add(fp...)

	ls, lp := readLastScan(c.Cfg.Scan.Summary)
	r.LastScan = ls
	if lp != nil {
		add(*lp)
	}
	return r, problems, nil
}

// collectClamdGuarded probes the clamd socket only when that cannot start clamd.
//
// Rule (decision Q4): the agent never starts clamd. On Debian, and wherever
// clamd is socket-activated, connecting to the socket of a stopped clamd makes
// systemd start it, which would hide the very outage the report exists to
// show and change the host. So the socket is touched only when the clamd unit
// is "active" (or "reloading"), or when units.clamd is configured EMPTY (clamd
// run by hand or by another supervisor: the operator states there is nothing
// for systemd to activate). A configured unit that systemd reports as
// not-found is NOT treated that way: it is more likely a typo or a wrong
// distro default, and the socket may still be activated by a .socket unit.
// Any other state, including "unknown" (we cannot tell), skips the connection
// and reports up=false with the reason.
func (c *Collector) collectClamdGuarded(ctx context.Context, unitState string, problems *[]Problem) proto.Clamd {
	switch {
	case unitState == "active", unitState == "reloading":
	case unitState == proto.ServiceNotFound && c.Cfg.Units.Clamd == "":
	case unitState == proto.ServiceNotFound:
		msg := fmt.Sprintf("clamd unit %s not found; set units.clamd to \"\" if clamd is not managed by systemd", c.Cfg.Units.Clamd)
		return proto.Clamd{Error: &msg}
	default:
		msg := fmt.Sprintf("clamd unit %q is %s: not connecting to the socket", c.Cfg.Units.Clamd, unitState)
		return proto.Clamd{Error: &msg}
	}
	conf, err := readFileLimited(c.Cfg.ClamdConf)
	if err != nil {
		msg := "clamd.conf: " + describeFileErr(err)
		*problems = append(*problems, Problem{"clamd", err})
		return proto.Clamd{Error: &msg}
	}
	socket, err := ParseLocalSocket(conf)
	if err != nil {
		msg := err.Error()
		*problems = append(*problems, Problem{"clamd", err})
		return proto.Clamd{Error: &msg}
	}
	timeout := c.ClamdTimeout
	if timeout == 0 {
		timeout = defaultClamdTimeout
	}
	res := collectClamd(ctx, socket, timeout)
	if res.Error != nil {
		*problems = append(*problems, Problem{"clamd", fmt.Errorf("%s", *res.Error)})
	}
	return res
}

// maxConfBytes caps clamd.conf reads; real files are a few KB.
const maxConfBytes = 1 << 20

func readFileLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxConfBytes))
}

func describeFileErr(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "not found"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	}
	return err.Error()
}
