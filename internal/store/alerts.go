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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
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
	// DeliveryDetectionSummary is the one alert that reports the detections a
	// target held back in a burst window. It is a detection for every rule that
	// distinguishes state alerts from detections (claim order, the reserved
	// worker, the cooldown), but its own kind for delivery order and the log.
	DeliveryDetectionSummary = "detection_summary"
)

// DetectionWindow is the length W of a burst window: per (target, host) the
// first DetectionBurst detections in W are sent one by one, the rest in W are
// held and sent as one summary when W ends (milestone 5, decision 10b).
const DetectionWindow = 10 * time.Minute

// DefaultDetectionBurst is the burst limit of a new alert target; 0 means every
// detection is sent on its own.
const DefaultDetectionBurst = 10

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
	// DetectionBurst is how many detections per host and DetectionWindow are sent
	// one by one before the rest are summarised; 0 = every detection alone.
	DetectionBurst int
	Enabled        bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ClaimLimits bound one claim: the dispatcher's capacity rules (milestone 5,
// section 4.12).
type ClaimLimits struct {
	// Total is the number of idle workers: no more than this is claimed.
	Total int
	// Detections is how many of them may be detections or summaries. The
	// dispatcher keeps one worker for state alerts by passing workers-1 minus
	// the detections already in flight.
	Detections int
	// PerTarget caps detection-class deliveries in flight (claimed) per target,
	// those already claimed included; 0 means no cap.
	PerTarget int
}

// Claim returns limits with n slots, all usable by any kind and no per-target
// cap (tests and callers that have no reserve).
func Claim(n int) ClaimLimits { return ClaimLimits{Total: n, Detections: n} }

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
	// Windows are all open detection windows, with their held members.
	Windows []PlanWindow
}

// PlanWindowMember is a detection held in an open window; the summary needs
// only its signature and the agent's time, never the path.
type PlanWindowMember struct {
	EventID   int64
	TS        time.Time
	Signature string
}

// PlanWindow is an open detection window of one (target, host).
type PlanWindow struct {
	ID       int64
	TargetID int64
	HostID   int64
	// Start is the server-clock received_at of the event that opened it.
	Start time.Time
	// Sent counts the individual alerts already sent in this window.
	Sent    int
	Members []PlanWindowMember
}

// Window outcomes.
const (
	WindowSummarised = "summarised"
	WindowEmpty      = "empty"
	WindowDiscarded  = "discarded"
)

// WindowWrite is the planner's final state of one window it touched, written
// by the store in order (a window that closes comes before the one that
// replaces it: one open window per (target, host) at all times).
type WindowWrite struct {
	// ID is the existing window's id; 0 for a window the plan opens.
	ID       int64
	TargetID int64
	HostID   int64
	// Start is used for a new window only.
	Start time.Time
	// Sent is the new count of individual alerts.
	Sent int
	// AddMembers are the event ids held by this plan.
	AddMembers []int64
	// Outcome is "" while the window stays open, else a Window* value: the
	// window is closed in the same transaction as the summary delivery.
	Outcome string
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
	Kind          string // DeliveryStateChange, DeliveryDetection or DeliveryDetectionSummary
	// WindowRef, for a summary, is 1 + the index in AlertPlanOutput.Windows of
	// the window it consumes; 0 for every other delivery.
	WindowRef int
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
	// Windows are the windows the plan opened, changed or closed.
	Windows []WindowWrite
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

var (
	// ErrTargetExists: an alert target with that name exists.
	ErrTargetExists = errors.New("alert target already exists")
	// ErrChangedMeanwhile: the target's stored configuration or secret is no longer
	// what the caller read (another admin edited or rotated it). Nothing was written.
	ErrChangedMeanwhile = errors.New("alert target changed meanwhile")
	// ErrLeaseLost: the delivery is no longer claimed by the caller (its lease
	// expired and it was claimed again, or it was cancelled). Nothing about the
	// delivery was written.
	ErrLeaseLost = errors.New("delivery lease lost")
)

// Audit actions and target kind of alert target changes.
const (
	ActionAlertTargetAdd    = "alert_target.add"
	ActionAlertTargetUpdate = "alert_target.update"
	ActionAlertTargetDelete = "alert_target.delete"
	ActionAlertTargetRotate = "alert_target.secret.rotate"
	ActionAlertTargetTest   = "alert_target.test"

	TargetAlertTarget = "alert_target"
)

// Rule: alert target names are lowercase, 1-64 characters of [a-z0-9._-],
// starting with a letter or digit; "new" is reserved because it is a route
// (GET /admin/alerts/new). The name is immutable: it is the audit target and the
// URL of the target's page.
var alertTargetNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// NormalizeAlertTargetName lowercases and validates a target name.
func NormalizeAlertTargetName(name string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if !alertTargetNameRE.MatchString(n) || n == "new" {
		return "", fmt.Errorf("invalid target name: use 1-64 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit (\"new\" is reserved)")
	}
	return n, nil
}

// NewAlertTarget is a target to create.
type NewAlertTarget struct {
	Name             string
	Type             string
	Config           []byte
	MinSeverity      string
	TagFilter        []string
	SendStateChanges bool
	SendDetections   bool
	// DetectionBurst is the burst limit; the zero value means every detection
	// alone, so callers that want the default set DefaultDetectionBurst.
	DetectionBurst int
	Enabled        bool
}

// TargetSnapshot is the part of a target a read-modify-write must still find
// unchanged: the stored config and the sealed secret. Updates and key rotations
// compare it inside their transaction (compare-and-swap, as the re-seal does).
type TargetSnapshot struct {
	Config []byte
	Sealed []byte
}

// AlertTargetUpdate is the full desired non-secret state of a target.
type AlertTargetUpdate struct {
	Config           []byte
	MinSeverity      string
	TagFilter        []string
	SendStateChanges bool
	SendDetections   bool
	// DetectionBurst, when set, replaces the burst limit; nil keeps it.
	DetectionBurst *int
	Enabled        bool
	// Expect, when set, makes the update conditional on the stored config and
	// secret still being these (ErrChangedMeanwhile otherwise).
	Expect *TargetSnapshot
}

// Cancelled reports what an update switched off.
type Cancelled struct {
	// Deliveries is how many pending deliveries became 'cancelled'.
	Deliveries int
	// HeldDetections is how many detections were held in burst windows that were
	// discarded because detections were switched off or the target disabled:
	// no summary will be sent for them (M5 decision 15).
	HeldDetections int
}

// AlertTargetSummary is a target with the last result recorded for it.
type AlertTargetSummary struct {
	AlertTarget
	LastStatus string // "" when nothing was recorded yet
	LastAt     *time.Time
	LastCode   string
}

// ClaimedDelivery is a delivery a worker now owns until its lease ends.
type ClaimedDelivery struct {
	ID            int64
	AlertID       string
	Target        AlertTarget // with Sealed
	HostID        int64
	HostName      string
	Recipient     string
	StateChangeID *int64
	EventID       *int64
	Kind          string
	Payload       []byte
	Attempt       int    // 1-based number of THIS attempt
	Token         []byte // the lease token FinishAttempt must present
	LogID         int64  // the 'attempting' log row
	ClaimedAt     time.Time
}

// AttemptResult is what a sender reports to the store.
type AttemptResult struct {
	// Status is AlertLogSent, AlertLogRetrying or AlertLogFailed (for a test
	// send AlertLogTestSent or AlertLogTestFailed).
	Status string
	Code   string
	Error  string // our own text, never a response body or a URL path
	// Duration of the attempt.
	Duration time.Duration
	// RetryAt is when a retrying delivery is due again.
	RetryAt time.Time
}

// TestSendRecord is the outcome of a test send to one recipient ("" for a webhook).
type TestSendRecord struct {
	Recipient string
	Result    AttemptResult
}

// AlertLogFilter selects log rows, newest first.
type AlertLogFilter struct {
	TargetName string // "" = every target
	Limit      int
}

// AlertLogEntry is a row of alert_log.
type AlertLogEntry struct {
	ID         int64
	TS         time.Time
	TargetName string
	Recipient  string
	Host       string
	Kind       string // "state change", "detection", "detection summary" or "test"
	Attempt    int
	Status     string
	Code       string
	Error      string
	DurationMS int64
}

// SealedTargetSecret is a stored webhook secret, for the start-up check and key rotation.
type SealedTargetSecret struct {
	ID     int64
	Name   string
	Sealed []byte
}

// AlertReseal replaces one sealed target secret by another, only if it is still Old.
type AlertReseal struct {
	TargetID int64
	Old      []byte
	New      []byte
}

// ResealResult is what ResealSecrets did. Conflicts are the ids (user ids for
// TOTP, target ids for alert targets) whose blob changed between the caller's
// read and the write: they were left alone.
type ResealResult struct {
	TOTP, AlertTargets            int
	TOTPConflicts, AlertConflicts []int64
}

// UnroutedEvent is a detection that no target matched.
type UnroutedEvent struct {
	EventID int64
	Host    string
}

// PlanResult is what PlanAlerts wrote.
type PlanResult struct {
	Deliveries []NewDelivery
	Held       int
	Unrouted   []UnroutedEvent
	// Hosts maps host id to name, for the log lines of the caller.
	Hosts map[int64]string
}

// AlertStore persists alert targets and the delivery queue.
type AlertStore interface {
	// CreateAlertTarget inserts the target and writes its audit row. seal is
	// called inside the transaction with the new id (the AAD of the sealed
	// secret) and may be nil for email. ErrTargetExists for a taken name.
	CreateAlertTarget(ctx context.Context, t NewAlertTarget, seal func(id int64) ([]byte, error), now time.Time, a Audit) (AlertTarget, error)
	// UpdateAlertTarget replaces the non-secret settings; seal, when not nil,
	// replaces the secret (a changed webhook URL). In the SAME transaction it
	// applies the switch-off rules: pending deliveries of a kind turned off (or
	// all when disabled, or of a removed recipient) become 'cancelled' with a
	// log row, and the notify state goes when state changes are turned off or
	// the target is disabled. The audit detail names the changed fields only.
	UpdateAlertTarget(ctx context.Context, name string, u AlertTargetUpdate, seal func(id int64) ([]byte, error), now time.Time, a Audit) (Cancelled, error)
	// RotateAlertSecret replaces the sealed secret only (a new signing key), only
	// while the stored config and secret still equal expect (ErrChangedMeanwhile), and
	// audits alert_target.secret.rotate. ErrNotFound for an unknown target.
	RotateAlertSecret(ctx context.Context, name string, expect TargetSnapshot, seal func(id int64) ([]byte, error), now time.Time, a Audit) error
	// DeleteAlertTarget cascades the target's deliveries and notify state; its
	// log rows stay (target id NULL, name snapshot).
	DeleteAlertTarget(ctx context.Context, name string, now time.Time, a Audit) error
	// AlertTarget returns the target with its sealed secret (read pool).
	AlertTarget(ctx context.Context, name string) (AlertTarget, error)
	ListAlertTargets(ctx context.Context) ([]AlertTargetSummary, error)
	// CountPendingAlerts counts the target's pending deliveries.
	CountPendingAlerts(ctx context.Context, name string) (int, error)

	// HasAlertWork is cheap (read pool): is anything flagged, any hold due, any
	// detection window due to close, any delivery due or any lease expired? It keeps the 5 s loop from opening a
	// write transaction for nothing.
	HasAlertWork(ctx context.Context, now time.Time, cooldown time.Duration) (bool, error)
	// PlanAlerts runs in ONE immediate write transaction: it reads the flagged
	// state changes and events, the targets, the notify state and the due holds,
	// calls plan (pure; it must not call the store), writes the deliveries, the
	// notify-state upserts and the held/skipped log rows, and clears the flags.
	// A failure anywhere leaves the flags set and nothing written.
	PlanAlerts(ctx context.Context, now time.Time, cooldown time.Duration, plan func(AlertPlanInput) AlertPlanOutput) (PlanResult, error)
	// ExpireLeases, one transaction, handles every claimed pending delivery
	// whose lease ended (all=true: every claim, used at start, when every claim
	// belongs to a dead process): its 'attempting' log row becomes
	// 'interrupted' and the claim is released. At MaxAlertAttempts attempts the
	// delivery becomes 'failed' with a 'failed' log row in the same transaction;
	// otherwise it is due at once.
	ExpireLeases(ctx context.Context, now time.Time, all bool) (expired, exhausted int, err error)
	// ClaimDeliveries, one transaction, claims due deliveries within lim and
	// returns them: state-change deliveries FIRST (up to lim.Total), then
	// detections and summaries (up to lim.Detections and what is left of
	// lim.Total), at most lim.PerTarget of them in flight per target. A delivery
	// of a disabled target or of a kind switched off is not claimed, nor one with
	// an older pending delivery of the same kind for the same (target, host,
	// recipient).
	ClaimDeliveries(ctx context.Context, now time.Time, lease time.Duration, lim ClaimLimits) ([]ClaimedDelivery, error)
	// FinishAttempt records the outcome of a claimed attempt, conditional on the
	// claim token. ErrLeaseLost: the delivery was not written (the attempt's log
	// row still is, while it is 'attempting').
	FinishAttempt(ctx context.Context, c ClaimedDelivery, r AttemptResult, now time.Time) error
	// RecordTestSend writes a log row per recipient and the audit row
	// alert_target.test. ErrNotFound for an unknown target.
	RecordTestSend(ctx context.Context, targetName string, rs []TestSendRecord, now time.Time, a Audit) error

	AlertLog(ctx context.Context, f AlertLogFilter) ([]AlertLogEntry, error)
	// UnroutedDetections counts detections received since `since` that have no
	// delivery at all.
	UnroutedDetections(ctx context.Context, since time.Time) (int64, error)
	// PruneAlertHistory deletes log rows older than before and FINISHED
	// deliveries older than before, in batches. Pending deliveries are never pruned.
	PruneAlertHistory(ctx context.Context, before time.Time, batch int) (int64, error)

	// SealedAlertSecrets lists every stored webhook secret.
	SealedAlertSecrets(ctx context.Context) ([]SealedTargetSecret, error)
	// ResealSecrets re-seals TOTP secrets and alert-target secrets in ONE
	// transaction, each row a compare-and-swap on its old blob. A database error
	// rolls everything back (nothing is re-sealed); a row whose blob changed
	// meanwhile is a conflict, the other rows commit. It audits secrets.reencrypt
	// with the counts when something was applied.
	ResealSecrets(ctx context.Context, totp []Reseal, alerts []AlertReseal, now time.Time, a Audit) (ResealResult, error)
	// ResealAlertSecrets is ResealSecrets for alert targets only.
	ResealAlertSecrets(ctx context.Context, rs []AlertReseal, now time.Time, a Audit) (applied int, conflicts []int64, err error)
}
