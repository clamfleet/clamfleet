// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// retention.go: the batched prunes of reports, state changes and the audit log,
// and PRAGMA optimize. PruneEvents, PruneAlertWindows and
// PruneAlertHistory sit beside their own tables.
package sqlite

import (
	"context"
	"fmt"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite/sqlcdb"
)

var _ store.RetentionStore = (*Store)(nil)

// PruneReports implements store.RetentionStore.
func (s *Store) PruneReports(ctx context.Context, before time.Time, batch int) (int64, error) {
	return s.pruneBatches(ctx, batch, func(q *sqlcdb.Queries) (int64, error) {
		return q.PruneReports(ctx, sqlcdb.PruneReportsParams{Before: unix(before), Batch: int64(batch)})
	})
}

// PruneStateChanges implements store.RetentionStore.
func (s *Store) PruneStateChanges(ctx context.Context, before time.Time, batch int) (int64, error) {
	return s.pruneBatches(ctx, batch, func(q *sqlcdb.Queries) (int64, error) {
		return q.PruneStateChanges(ctx, sqlcdb.PruneStateChangesParams{Before: unix(before), Batch: int64(batch)})
	})
}

// PruneAudit implements store.RetentionStore.
func (s *Store) PruneAudit(ctx context.Context, before time.Time, batch int) (int64, error) {
	return s.pruneBatches(ctx, batch, func(q *sqlcdb.Queries) (int64, error) {
		return q.PruneAudit(ctx, sqlcdb.PruneAuditParams{Before: unix(before), Batch: int64(batch)})
	})
}

// Optimize implements store.RetentionStore. It runs on the writer because that
// is the connection that has seen the data change; PRAGMA optimize is cheap and
// only analyses tables whose statistics are stale.
func (s *Store) Optimize(ctx context.Context) error {
	if _, err := s.w.ExecContext(ctx, `PRAGMA optimize`); err != nil {
		return fmt.Errorf("pragma optimize: %w", err)
	}
	return nil
}
