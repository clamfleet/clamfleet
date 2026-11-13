// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// retention.go: the daily prune of detection events (milestone 5, section 4.13).
//
// Responsibilities: RunRetention deletes events older than retention.events_days
// (counted from arrival) and the closed detection windows older than the alert
// history's 90 days, in batches so no write transaction runs long. Alert
// deliveries and log rows of an event go with it by cascade; summary payloads
// and closed windows follow the 90-day alert history.
//
// Logging: counts only. An event's path is personal data and never goes in a log.
// Dependencies: store.EventStore, an injected clock; nothing reads the wall clock.

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

// RunRetention prunes at once and then whenever a tick finds the last prune
// older than 24 h, until ctx is cancelled. A failed prune is logged and retried
// at the next tick. The caller owns the ticker; now is the injected clock.
func RunRetention(ctx context.Context, st store.EventStore, now func() time.Time, eventsDays int, log *slog.Logger, tick <-chan time.Time) {
	var last time.Time
	for {
		if t := now(); last.IsZero() || t.Sub(last) >= retentionEvery {
			if pruneOnce(ctx, st, t, eventsDays, log) {
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

// pruneOnce reports whether both prunes ran without error.
func pruneOnce(ctx context.Context, st store.EventStore, now time.Time, eventsDays int, log *slog.Logger) bool {
	ok := true
	n, err := st.PruneEvents(ctx, now.Add(-time.Duration(eventsDays)*24*time.Hour), retentionBatch)
	switch {
	case err != nil && ctx.Err() == nil:
		log.Error("pruning events failed", "error", err.Error())
		ok = false
	case n > 0:
		log.Info("old events pruned", "count", n, "events_days", eventsDays)
	}
	w, err := st.PruneAlertWindows(ctx, now.Add(-alert.Retention), retentionBatch)
	switch {
	case err != nil && ctx.Err() == nil:
		log.Error("pruning detection windows failed", "error", err.Error())
		ok = false
	case w > 0:
		log.Info("old detection windows pruned", "count", w)
	}
	return ok && ctx.Err() == nil
}
