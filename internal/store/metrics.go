// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package store

import (
	"context"
	"time"
)

// MetricsHost is what /metrics knows about one registered host (revoked hosts
// are excluded). It carries no tag, path or signature name: tags are free text
// that may hold names, and a path is personal data.
type MetricsHost struct {
	Name     string
	State    *string    // nil: never evaluated ("pending")
	LastSeen *time.Time // nil: never reported
	// SigBuilt is the build time of each signature database in the last report,
	// keyed "daily", "main" and "bytecode". A database the host does not have is absent.
	SigBuilt map[string]time.Time
}

// MetricsSnapshot is the input of the /metrics exposition, read in one query pass.
type MetricsSnapshot struct {
	Hosts      []MetricsHost
	OpenEvents int64
	// Alert deliveries: Pending have not been tried, Retrying failed an attempt
	// and wait for the next one, Failed gave up since the `failedSince` argument.
	DeliveriesPending, DeliveriesRetrying, DeliveriesFailed int64
}

// MetricsStore reads the numbers /metrics exports (milestone 6, plan 4.6).
type MetricsStore interface {
	// MetricsSnapshot reads on the read pool. failedSince bounds the failed
	// deliveries that are counted (alert_log_days).
	MetricsSnapshot(ctx context.Context, failedSince time.Time) (MetricsSnapshot, error)
}
