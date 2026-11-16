// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package store

import (
	"context"
	"time"
)

// RetentionStore is what the daily retention runner needs besides EventStore's
// prunes and AlertStore.PruneAlertHistory (milestone 6, plan 4.2). Every Prune*
// deletes in batches of `batch` rows, one transaction per batch, until a batch
// deletes fewer rows than that; it returns the total.
type RetentionStore interface {
	// PruneReports deletes heartbeat reports received before `before` (server
	// clock, received_at). hosts.last_report and hosts.state are never touched.
	PruneReports(ctx context.Context, before time.Time, batch int) (int64, error)
	// PruneStateChanges deletes state changes with ts before `before`; their
	// deliveries and alert_log rows go by cascade. Rule: a state change whose
	// alert is still pending (not yet planned, or with an unfinished delivery) is kept.
	PruneStateChanges(ctx context.Context, before time.Time, batch int) (int64, error)
	// PruneAudit deletes audit rows with ts before `before`.
	PruneAudit(ctx context.Context, before time.Time, batch int) (int64, error)
	// Optimize runs PRAGMA optimize on the writer (spec 8.3). The caller logs and
	// ignores its error: stale statistics are a performance matter, never fatal.
	Optimize(ctx context.Context) error
}
