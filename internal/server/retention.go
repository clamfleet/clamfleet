// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// retention.go: the daily prune of every table (milestone 5 section 4.13,
// extended in milestone 6 section 4.3).
//
// Responsibilities: RunRetention deletes, per the retention.* keys, events,
// state changes, reports, the closed detection windows and the audit log, in
// batches so no write transaction runs long, then runs PRAGMA optimize. Alert
// deliveries and log rows of an event or state change go with it by cascade.
// Rows whose alert is unfinished are kept by the store (see its prune queries).
//
// Concurrency: one goroutine runs the passes in sequence, so two passes never
// overlap. A tick that arrives during a long pass is dropped by the caller's
// ticker (its channel holds one), and the next pass starts only when 24 h have
// passed on the injected clock.
//
// Logging: counts only. An event's path is personal data and never goes in a log.
// Dependencies: store.EventStore and store.RetentionStore, an injected clock;
// nothing reads the wall clock.

package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/clamfleet/clamfleet/internal/alert"
	"github.com/clamfleet/clamfleet/internal/store"
)

const (
	// retentionEvery is how often (on the injected clock) a prune may run.
	retentionEvery = 24 * time.Hour
	// retentionBatch is the rows per transaction.
	retentionBatch = 5000
)

// RetentionStore is what the runner prunes through.
type RetentionStore interface {
	store.EventStore
	store.RetentionStore
}

// RunRetention prunes at once and then whenever a tick finds the last prune
// older than 24 h, until ctx is cancelled. A failed prune is logged and retried
// at the next tick. The caller owns the ticker; now is the injected clock.
func RunRetention(ctx context.Context, st RetentionStore, now func() time.Time, r Retention, log *slog.Logger, tick <-chan time.Time) {
	var last time.Time
	for {
		if t := now(); last.IsZero() || t.Sub(last) >= retentionEvery {
			if pruneOnce(ctx, st, t, r, log) {
				last = t
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

// pruneOnce runs every prune in order (events, state changes, reports, windows,
// audit) and then Optimize. It reports whether all of them ran without error.
func pruneOnce(ctx context.Context, st RetentionStore, now time.Time, r Retention, log *slog.Logger) bool {
	ok := true
	step := func(what, msg string, n int64, err error) {
		switch {
		case err != nil && ctx.Err() == nil:
			log.Error("pruning "+what+" failed", "error", err.Error())
			ok = false
		case n > 0:
			log.Info(msg, "count", n)
		}
	}
	n, err := st.PruneEvents(ctx, now.Add(-days(r.EventsDays)), retentionBatch)
	step("events", "old events pruned", n, err)
	n, err = st.PruneStateChanges(ctx, now.Add(-days(r.StateChangesDays)), retentionBatch)
	step("state changes", "old state changes pruned", n, err)
	n, err = st.PruneReports(ctx, now.Add(-days(r.ReportsDays)), retentionBatch)
	step("reports", "old reports pruned", n, err)
	n, err = st.PruneAlertWindows(ctx, now.Add(-alert.Retention), retentionBatch)
	step("detection windows", "old detection windows pruned", n, err)
	n, err = st.PruneAudit(ctx, now.Add(-days(r.AuditDays)), retentionBatch)
	step("audit rows", "old audit rows pruned", n, err)
	if ctx.Err() != nil {
		return false
	}
	// PRAGMA optimize is a performance courtesy: a failure is logged, never retried.
	if err := st.Optimize(ctx); err != nil {
		log.Warn("pragma optimize failed", "error", err.Error())
	}
	return ok
}
