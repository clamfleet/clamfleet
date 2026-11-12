// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// run.go: the agent's service loop (`run`) and its single pass (`run --once`).
//
// There is no spool yet (Milestone 5): a failed send is logged with its class
// and the next tick tries again, so one heartbeat is lost, never the loop.
// The loop never exits on a send error; only cancelling the context stops it.
// The loop sends one report immediately and then one per interval, driven by
// an injected tick channel so tests do not wait for real time.
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

// Loop runs Once immediately and then on every tick until ctx is cancelled.
// It returns nil on cancellation.
func (r *Runner) Loop(ctx context.Context) error {
	tick := r.Tick
	if tick == nil {
		t := time.NewTicker(r.Interval)
		defer t.Stop()
		tick = t.C
	}
	for {
		if err := r.Once(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			r.LogFailure(err)
		} else {
			r.Log.Debug("report sent")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick:
		}
	}
}
