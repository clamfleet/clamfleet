// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// cleanup.go: removes expired session rows. Expired sessions are already
// refused by the lookup; this only keeps the table from growing.
package webauth

import (
	"context"
	"log/slog"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

// RunCleanup deletes expired sessions at once and then on every tick, until
// ctx is cancelled. A failure is logged and the loop carries on. The caller
// owns the ticker (tests feed a channel), now is the injected clock.
func RunCleanup(ctx context.Context, st store.SessionStore, now func() time.Time, idle time.Duration, log *slog.Logger, tick <-chan time.Time) {
	for {
		n, err := st.DeleteExpiredSessions(ctx, now(), idle)
		switch {
		case err != nil && ctx.Err() == nil:
			log.Error("cannot delete expired sessions", "error", err.Error())
		case n > 0:
			log.Info("expired sessions removed", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}
