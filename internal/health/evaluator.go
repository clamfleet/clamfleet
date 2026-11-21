// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// evaluator.go: runs Evaluate against the store, after every accepted report
// and on a timer.
//
// Why a timer as well as the per-report call: STALE is the absence of a
// report, so nothing happens that could trigger it. The loop is what notices
// a host that went silent (spec 9: every 60 s).
//
// Dependencies: internal/store (HealthStore) and rules.go. The clock is
// injected; nothing here reads the wall clock.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

// Evaluator evaluates hosts and records the result through the store.
type Evaluator struct {
	Store      store.HealthStore
	Now        func() time.Time
	Thresholds Thresholds
	// StartedAt is when this server process started; staleness is measured from
	// max(last_seen, StartedAt) (restart grace, see Evaluate). New sets it from Now.
	StartedAt time.Time
	Log       *slog.Logger

	// mu serialises evaluations inside this process. SQLite's single write
	// connection already does, but the store contract only promises atomicity per
	// call, and a PostgreSQL store would not get this for free.
	mu sync.Mutex
}

// New returns an Evaluator whose restart-grace reference is now().
func New(st store.HealthStore, now func() time.Time, th Thresholds, log *slog.Logger) *Evaluator {
	return &Evaluator{Store: st, Now: now, Thresholds: th, StartedAt: now(), Log: log}
}

// Host evaluates one host. It is called after every accepted report,
// duplicates included (a retry is still proof of life). A host that is revoked
// or unknown is skipped without error.
// Side effects: writes hosts.state* and state_changes through the store.
func (e *Evaluator) Host(ctx context.Context, id int64) error {
	return e.run(ctx, []int64{id})
}

// All evaluates every host with a token.
func (e *Evaluator) All(ctx context.Context) error {
	return e.run(ctx, nil)
}

func (e *Evaluator) run(ctx context.Context, ids []int64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.Now()
	trs, err := e.Store.EvaluateHosts(ctx, now, ids, func(in store.HealthInput) store.HealthOutcome {
		if in.ReportUnreadable {
			e.Log.Warn("stored report of a host cannot be decoded; judging it from last_seen only", "host_id", in.HostID, "host", in.Name)
		}
		res := Evaluate(Input{
			Now: now, StartedAt: e.StartedAt, CreatedAt: in.CreatedAt, LastSeen: in.LastSeen,
			Report: in.Report, ReportUnreadable: in.ReportUnreadable, FleetNewestDaily: in.FleetNewestDaily,
		}, e.Thresholds)
		rs := res.Reasons
		if rs == nil {
			rs = []Reason{} // "[]", never "null": the column holds a JSON array
		}
		// Marshalling plain strings cannot fail.
		raw, _ := json.Marshal(rs)
		return store.HealthOutcome{State: res.State, Reasons: raw}
	})
	if err != nil {
		return fmt.Errorf("evaluate health: %w", err)
	}
	for _, t := range trs {
		from := "none"
		if t.From != nil {
			from = *t.From
		}
		e.Log.Info("host state changed", "host", t.Host, "from", from, "to", t.To)
	}
	return nil
}

// Run evaluates every host immediately and then on every tick, until ctx is
// cancelled. A failed pass is logged and the loop carries on: the next tick
// tries again. The caller owns the ticker (tests pass a channel they feed).
func (e *Evaluator) Run(ctx context.Context, tick <-chan time.Time) {
	for {
		if err := e.All(ctx); err != nil && ctx.Err() == nil {
			e.Log.Error("health evaluation failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}
