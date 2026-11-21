// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite/sqlcdb"
)

var _ store.MetricsStore = (*Store)(nil)

// MetricsSnapshot implements store.MetricsStore. Three small reads on the read
// pool; at 100 hosts that is a few milliseconds, so there is no cache.
func (s *Store) MetricsSnapshot(ctx context.Context, failedSince time.Time) (store.MetricsSnapshot, error) {
	var out store.MetricsSnapshot
	q := sqlcdb.New(s.r)
	hosts, err := q.MetricsHosts(ctx)
	if err != nil {
		return out, fmt.Errorf("metrics hosts: %w", err)
	}
	for _, h := range hosts {
		mh := store.MetricsHost{Name: h.Name, State: nullString(h.State), LastSeen: nullTime(h.LastSeen)}
		if h.LastReport.Valid {
			// Only the build times are read from the stored report: nothing else of it leaves.
			var r struct {
				Sigs map[string]*struct {
					Built time.Time `json:"built"`
				} `json:"sigs"`
			}
			if json.Unmarshal([]byte(h.LastReport.String), &r) == nil {
				for db, v := range r.Sigs {
					if v != nil && !v.Built.IsZero() {
						if mh.SigBuilt == nil {
							mh.SigBuilt = map[string]time.Time{}
						}
						mh.SigBuilt[db] = v.Built
					}
				}
			}
		}
		out.Hosts = append(out.Hosts, mh)
	}
	if out.OpenEvents, err = q.MetricsOpenEvents(ctx); err != nil {
		return out, fmt.Errorf("metrics events: %w", err)
	}
	d, err := q.MetricsDeliveries(ctx, nullInt(failedSince))
	if err != nil {
		return out, fmt.Errorf("metrics deliveries: %w", err)
	}
	out.DeliveriesPending, out.DeliveriesRetrying, out.DeliveriesFailed = d.Pending, d.Retrying, d.Failed
	return out, nil
}
