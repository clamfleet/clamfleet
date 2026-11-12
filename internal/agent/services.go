// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// services.go: asks systemd for the state of the clamd, freshclam and
// clamonacc units, and holds the injectable command runner.
//
// Responsibilities: ExecFunc/RealExec (bounded, LANG=C command execution),
// parsing "systemctl show" output, and mapping each unit to a state string
// of proto.Services ("not-found" and "unknown" included).
// Dependencies: the systemctl binary (through ExecFunc, so tests need none)
// and the proto package.

package agent

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// systemctlTimeout bounds each systemctl call.
const systemctlTimeout = 5 * time.Second

// ExecFunc runs a command and returns its stdout. Injected so tests need no
// real systemctl or journalctl.
type ExecFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// execMaxOutput caps the stdout RealExec keeps, as clamdMaxReply caps the
// socket reply (spec 13: 30 MB RSS). The largest legitimate output is the
// freshclam journal (1000 lines, about 100 KB).
const execMaxOutput = 1 << 20

// cappedBuffer keeps at most max bytes and counts the rest as overflow. It
// keeps draining instead of returning an error: a failing writer would leave
// the child blocked on a full pipe until the context deadline.
type cappedBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := c.max - c.buf.Len(); n > room {
		c.overflow = true
		p = p[:room]
	}
	c.buf.Write(p)
	// Report the full length: a short count makes io.Copy stop with
	// ErrShortWrite and close the pipe under the child (SIGPIPE).
	return n, nil
}

// RealExec runs the command with LANG=C (stable output) and returns stdout.
// stderr is included in the error text on failure. Output beyond execMaxOutput
// is an error rather than a silently truncated result: journalctl prints the
// oldest lines first, so a cut would drop the newest runs without a trace.
func RealExec(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	var stderr bytes.Buffer
	stdout := &cappedBuffer{max: execMaxOutput}
	cmd.Stderr, cmd.Stdout = &stderr, stdout
	if err := cmd.Run(); err != nil {
		return stdout.buf.Bytes(), fmt.Errorf("%s: %w: %s", name, err, truncate(strings.TrimSpace(stderr.String()), 200))
	}
	if stdout.overflow {
		return nil, fmt.Errorf("%s: output larger than %d bytes", name, execMaxOutput)
	}
	return stdout.buf.Bytes(), nil
}

// ParseSystemctlShow turns the KEY=VALUE lines of "systemctl show" into the
// service state for the report: "not-found" when LoadState says so, else the
// ActiveState. ok is false when either property is missing.
func ParseSystemctlShow(out []byte) (state string, ok bool) {
	props := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if k, v, found := strings.Cut(sc.Text(), "="); found {
			props[k] = strings.TrimSpace(v)
		}
	}
	load, active := props["LoadState"], props["ActiveState"]
	if load == "" || active == "" {
		return "", false
	}
	if load == "not-found" {
		return proto.ServiceNotFound, true
	}
	return active, true
}

// unitState asks systemd for one unit. "systemctl show" is used instead of
// the spec's "is-active" (assumption A12): is-active prints "inactive" for a
// unit that does not exist, so "clamonacc if present" could not be detected.
// An empty unit name means the host has no such unit.
func (c *Collector) unitState(ctx context.Context, unit string) (string, *Problem) {
	if unit == "" {
		return proto.ServiceNotFound, nil
	}
	ctx, cancel := context.WithTimeout(ctx, systemctlTimeout)
	defer cancel()
	// "--" so a configured unit name can never be read as an option.
	out, err := c.Exec(ctx, "systemctl", "show", "--property=LoadState,ActiveState", "--", unit)
	if err != nil {
		return proto.ServiceUnknown, &Problem{"services", fmt.Errorf("unit %s: %w", unit, err)}
	}
	state, ok := ParseSystemctlShow(out)
	if !ok {
		return proto.ServiceUnknown, &Problem{"services", fmt.Errorf("unit %s: unexpected systemctl output", unit)}
	}
	return state, nil
}

// collectServices returns the state of the three units.
func (c *Collector) collectServices(ctx context.Context) (proto.Services, []Problem) {
	var s proto.Services
	var problems []Problem
	for _, it := range []struct {
		unit string
		dst  *string
	}{{c.Cfg.Units.Clamd, &s.Clamd}, {c.Cfg.Units.Freshclam, &s.Freshclam}, {c.Cfg.Units.Clamonacc, &s.Clamonacc}} {
		st, p := c.unitState(ctx, it.unit)
		*it.dst = st
		if p != nil {
			problems = append(problems, *p)
		}
	}
	return s, problems
}
