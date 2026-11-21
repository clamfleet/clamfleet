// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// run.go: the agent's service loop (`run`) and its single pass (`run --once`).
//
// The service loop collects a report immediately and then once per interval,
// driven by an injected tick channel so tests do not wait for real time, and
// writes it to the spool; the Drainer (drain.go) sends from there, so a server
// outage loses nothing within the spool's limits. The loop never exits on a
// collect, spool or send error; only cancelling the context stops it.
// `run --once` is unchanged: it sends one report directly and never touches the
// spool.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// reportPath is the ingest endpoint, relative to the server URL.
const reportPath = "v1/report"

// Runner collects and sends reports.
type Runner struct {
	// Collect builds one report (Collector.Collect).
	Collect func(ctx context.Context) (proto.Report, []Problem, error)
	// Send posts a body to a path and returns the response (Sender.Send).
	Send func(ctx context.Context, path string, body []byte) ([]byte, error)
	// Interval between reports; used only when Tick is nil.
	Interval time.Duration
	// Tick, when set, replaces the real ticker (tests).
	Tick <-chan time.Time
	Log  *slog.Logger
	// Queue and Drain are used by Loop only: reports are written to Queue and
	// Drain sends them (and the events the event command spooled).
	Queue *Queue
	Drain *Drainer
	// Now is the clock for the hourly "spool full" warning.
	Now        func() time.Time
	lastFullAt time.Time
}

// Once collects and sends one report. It returns the send error (a *SendError
// for anything that went wrong on the wire), so `run --once` can exit 1.
func (r *Runner) Once(ctx context.Context) error {
	report, problems, err := r.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collect: %w", err)
	}
	for _, p := range problems {
		r.Log.Warn("collection problem", "source", p.Source, "error", p.Err.Error())
	}
	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	if _, err := r.Send(ctx, reportPath, body); err != nil {
		return err
	}
	return nil
}

// LogFailure logs a failed pass with its class (and the server's text for a
// rejection) so an operator can tell a revoked token from a down server.
func (r *Runner) LogFailure(err error) {
	var se *SendError
	if errors.As(err, &se) {
		r.Log.Error("report not sent", "class", string(se.Class), "status", se.Status, "error", err.Error())
		return
	}
	r.Log.Error("report not sent", "class", "collect", "error", err.Error())
}

// Loop collects a report now and then on every tick, writing each to the
// spool, while the Drainer's two lanes send. It returns nil on cancellation,
// after the lanes have stopped.
func (r *Runner) Loop(ctx context.Context) error {
	tick := r.Tick
	if tick == nil {
		t := time.NewTicker(r.Interval)
		defer t.Stop()
		tick = t.C
	}
	lanes, stopLanes := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { r.Drain.Run(lanes); close(done) }()
	defer func() { stopLanes(); <-done }()
	for {
		r.spoolReport(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-tick:
		}
	}
}

// spoolReport collects one report and puts it in the spool. A collection or
// spool failure is logged and the loop carries on: the next tick tries again.
func (r *Runner) spoolReport(ctx context.Context) {
	report, problems, err := r.Collect(ctx)
	if err != nil {
		if ctx.Err() == nil {
			r.LogFailure(err)
		}
		return
	}
	for _, p := range problems {
		r.Log.Warn("collection problem", "source", p.Source, "error", p.Err.Error())
	}
	switch err := r.Queue.PutReport(report); {
	case err == nil:
		r.Drain.WakeReports()
	case errors.Is(err, ErrSpoolFull):
		// Events fill the cap. Say so once an hour: the heartbeat is dropped,
		// the host will look STALE, and that is the signal to look at the spool.
		if now := r.Now(); now.Sub(r.lastFullAt) >= time.Hour {
			r.lastFullAt = now
			r.Log.Error("spool full: heartbeat not spooled (events fill the cap; raise spool.max_mb or check the server)")
		}
	default:
		r.Log.Error("cannot spool the report", "error", err.Error())
	}
}
