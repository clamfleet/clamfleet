// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// alerts.go: the persistence types of alerting (Milestone 4) and, further
// down, the AlertStore interface.
//
// The store never imports internal/alert. The planner (internal/alert.Planner)
// is pure and works on the types declared here; the store owns the transaction
// around it, the same pattern as EvaluateHosts with its eval callback.
package store

import (
	"encoding/json"
	"time"
)

// MaxAlertAttempts is the number of attempts a delivery gets, crashes included
// (an interrupted attempt counts). The store needs it for the crash path
// (ExpireLeases ends a delivery on its last attempt) and internal/alert for
// the backoff schedule; one constant so the two paths cannot disagree.
const MaxAlertAttempts = 5

// Types of an alert target. Validated in Go, not by a CHECK constraint.
const (
	TargetTypeEmail   = "email"
	TargetTypeWebhook = "webhook"
)

// Kinds of a delivery.
const (
	DeliveryStateChange = "state_change"
	DeliveryDetection   = "detection"
)

// AlertTarget is a configured alert destination.
type AlertTarget struct {
	ID   int64
	Name string
	Type string
	// Config is the non-secret JSON of the target (email recipients, webhook
	// url_display); internal/alert owns its shape.
	Config []byte
	// Sealed is the sealed webhook secret (purpose alert-target, AAD = ID);
	// nil for email.
	Sealed []byte
	// MinSeverity is WARN, CRIT or STALE; it applies to state changes only.
	MinSeverity      string
	TagFilter        []string // any-of; empty = every host
	SendStateChanges bool
	SendDetections   bool
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// PlanHost is what the planner needs to know about a host.
type PlanHost struct {
	ID   int64
	Name string
	Tags []string
	// State is the host's current state, nil while pending.
	State *string
	// Reason is the current reason JSON (health.Reason array).
	Reason json.RawMessage
	// LatestChangeID is the id of the host's newest state change, 0 if none
	// (history pruned).
	LatestChangeID int64
	LatestChangeTS time.Time
}

// PlanStateChange is a state_changes row flagged alert_pending.
type PlanStateChange struct {
	ID     int64
	HostID int64
	TS     time.Time
	From   *string // nil on the host's first evaluation
	To     string
	Reason json.RawMessage
}

// PlanEvent is an events row flagged alert_pending.
type PlanEvent struct {
	ID         int64
	HostID     int64
	TS         time.Time
	ReceivedAt time.Time
	Path       string
	Signature  string
	Source     string
}

// NotifyState is what one target was last told about one host.
type NotifyState struct {
	TargetID  int64
	HostID    int64
	LastState string    // the "to" of the last state alert planned for the pair
	LastAt    time.Time // when it was planned: the cooldown starts here
	// HeldCount > 0: changes arrived inside the cooldown and are waiting for
	// the re-check at LastAt + cooldown.
	HeldCount int
}

// AlertPlanInput is everything the pure planner reads.
type AlertPlanInput struct {
	Now      time.Time
	Cooldown time.Duration
	// Targets are all targets, disabled ones included: a hold of a target that
	// was disabled must be seen to be cleared.
	Targets []AlertTarget
	// Changes and Events are the flagged rows in id order.
	Changes []PlanStateChange
	Events  []PlanEvent
	// Hosts holds every host named by a flagged row or a pending hold.
	Hosts map[int64]PlanHost
	// Notify holds the rows of those hosts (all targets).
	Notify []NotifyState
}

// NewDelivery is a delivery the planner wants written.
type NewDelivery struct {
	AlertID  string
	TargetID int64
	HostID   int64
	// Recipient is one address for an email target, "" for a webhook.
	Recipient     string
	StateChangeID *int64
	EventID       *int64
	Kind          string // DeliveryStateChange or DeliveryDetection
	// Payload is the JSON body, fixed here: every retry sends the same bytes.
	Payload []byte
}

// PlanLog is a log row the planner wants written for a decision that made no
// delivery (held, skipped).
type PlanLog struct {
	TargetID      int64
	TargetName    string
	HostName      string
	StateChangeID *int64
	EventID       *int64
	Status        string // AlertLogHeld or AlertLogSkipped
	Error         string // our own text
}

// AlertPlanOutput is what the planner decided.
type AlertPlanOutput struct {
	Deliveries []NewDelivery
	// Notify are upserts of the (target, host) state, in a stable order.
	Notify []NotifyState
	Logs   []PlanLog
	// Unrouted are the ids of the events that no target matched.
	Unrouted []int64
}

// Statuses of alert_log rows.
const (
	AlertLogAttempting  = "attempting"
	AlertLogSent        = "sent"
	AlertLogRetrying    = "retrying"
	AlertLogFailed      = "failed"
	AlertLogInterrupted = "interrupted"
	AlertLogHeld        = "held"
	AlertLogSkipped     = "skipped"
	AlertLogCancelled   = "cancelled"
	AlertLogTestSent    = "test_sent"
	AlertLogTestFailed  = "test_failed"
)
