// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// cleanup.go: removes expired session, login-challenge and OIDC login-state rows. Expired ones
// are already refused by the lookups; this only keeps the tables from growing.
package webauth

import (
	"context"
	"log/slog"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

// CleanupStore is what RunCleanup needs from the store.
type CleanupStore interface {
	store.SessionStore
	DeleteExpiredChallenges(ctx context.Context, now time.Time) (int64, error)
	DeleteExpiredOIDCStates(ctx context.Context, now time.Time) (int64, error)
}

// RunCleanup deletes expired sessions and login challenges at once and then on
// every tick, until ctx is cancelled. A failure is logged and the loop carries
// on. The caller owns the ticker (tests feed a channel), now is the injected clock.
func RunCleanup(ctx context.Context, st CleanupStore, now func() time.Time, idle time.Duration, log *slog.Logger, tick <-chan time.Time) {
	for {
		n, err := st.DeleteExpiredSessions(ctx, now(), idle)
		switch {
		case err != nil && ctx.Err() == nil:
			log.Error("cannot delete expired sessions", "error", err.Error())
		case n > 0:
			log.Info("expired sessions removed", "count", n)
		}
		c, err := st.DeleteExpiredChallenges(ctx, now())
		switch {
		case err != nil && ctx.Err() == nil:
			log.Error("cannot delete expired login challenges", "error", err.Error())
		case c > 0:
			log.Info("expired login challenges removed", "count", c)
		}
		o, err := st.DeleteExpiredOIDCStates(ctx, now())
		switch {
		case err != nil && ctx.Err() == nil:
			log.Error("cannot delete expired OIDC login states", "error", err.Error())
		case o > 0:
			log.Info("expired OIDC login states removed", "count", o)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}
