// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// events.go: the persistence types of detection events (Milestone 5) and the
// EventStore interface: the events page, acknowledgement and retention.
//
// Paths in events are personal data (they can name a user's files). The store
// returns them to the console, which escapes them, and never into an audit
// row or a log line: audit details here hold ids, signatures and counts only.
package store

import (
	"context"
	"fmt"
	"time"
)

// Audit actions and target kind of event acknowledgement.
const (
	ActionEventAck     = "event.ack"
	ActionEventAckBulk = "event.ack.bulk"

	TargetEvent = "event"
)

// Values of EventFilter.Ack.
const (
	AckOpen  = "open"
	AckAcked = "acked"
	AckAll   = "all"
)

// MaxEventPage is the largest page ListEvents returns.
const MaxEventPage = 200

// EventFilter selects events. The zero value means: every host, any signature,
// open events only, newest first, the default page size.
type EventFilter struct {
	// Host is a registered host name; "" = all hosts.
	Host string
	// Signature is a case-insensitive substring. % _ and \ in it match
	// themselves: the query uses instr(), not LIKE.
	Signature string
	// Ack is AckOpen (the default, also for ""), AckAcked or AckAll.
	Ack string
	// Before is a keyset cursor: only ids below it; 0 = from the newest.
	Before int64
	// UpTo bounds the ids from above (id <= UpTo); 0 = no bound. Bulk
	// acknowledgement uses it to act on exactly the set the admin was shown.
	UpTo int64
	// Limit is the page size, 1 to MaxEventPage; 0 means 50.
	Limit int
}

// Normalised returns the filter with defaults applied, or an error for a value
// that is not allowed.
func (f EventFilter) Normalised() (EventFilter, error) {
	switch f.Ack {
	case "":
		f.Ack = AckOpen
	case AckOpen, AckAcked, AckAll:
	default:
		return f, fmt.Errorf("invalid acknowledgement filter %q", TruncateForAudit(f.Ack))
	}
	if f.Limit == 0 {
		f.Limit = 50
	}
	if f.Limit < 1 || f.Limit > MaxEventPage {
		return f, fmt.Errorf("event page size must be between 1 and %d", MaxEventPage)
	}
	if f.Before < 0 || f.UpTo < 0 {
		return f, fmt.Errorf("event id bounds must not be negative")
	}
	return f, nil
}

// EventRow is one detection as the console shows it.
type EventRow struct {
	ID         int64     `json:"id"`
	HostID     int64     `json:"host_id"`
	Host       string    `json:"host"`
	TS         time.Time `json:"ts"`          // the agent's detection time
	ReceivedAt time.Time `json:"received_at"` // the server's arrival time
	// Path is stored as the agent encoded it (a backslash doubled, a non-UTF-8
	// byte as \xNN): untrusted text, shown only through the console's escaping.
	Path      string `json:"path"`
	Signature string `json:"signature"`
	Source    string `json:"source"`
	// Occurrences counts distinct detections merged on (host, second, path,
	// signature): 1 normally, more when two collided.
	Occurrences int64      `json:"occurrences"`
	AckBy       string     `json:"ack_by"` // display snapshot of the acknowledging user
	AckAt       *time.Time `json:"ack_at"`
}

// Acked reports whether the event has been acknowledged.
func (e EventRow) Acked() bool { return e.AckAt != nil }

// EventStore persists detection events beyond ingest (RecordEvent is on Store).
type EventStore interface {
	// ListEvents returns a page, newest id first, by keyset (f.Before). Read pool.
	ListEvents(ctx context.Context, f EventFilter) ([]EventRow, error)
	// CountEvents counts the events matching f, ignoring Before and Limit.
	CountEvents(ctx context.Context, f EventFilter) (int64, error)
	// MaxEventID is the highest id matching f (Before ignored), 0 if none: the
	// boundary a bulk acknowledgement is rendered with.
	MaxEventID(ctx context.Context, f EventFilter) (int64, error)
	// CountOpenEvents counts unacknowledged events (the nav badge).
	CountOpenEvents(ctx context.Context) (int64, error)
	// AckEvent acknowledges one event and writes the audit row in the same
	// transaction. acked is false when it was already acknowledged (nothing is
	// written; row shows who). ErrNotFound for an unknown id.
	AckEvent(ctx context.Context, id int64, now time.Time, a Audit) (row EventRow, acked bool, err error)
	// AckEvents acknowledges, in ONE transaction, exactly the open events
	// matching f (Host and Signature) with id <= upto, and writes one
	// event.ack.bulk audit row (when anything changed). upto must be > 0. It
	// returns the number acknowledged; expected is only recorded in the audit
	// row, so an investigator sees what the admin was shown.
	AckEvents(ctx context.Context, f EventFilter, upto, expected int64, now time.Time, a Audit) (int64, error)
	// PruneEvents deletes events received before `before`, `batch` rows per
	// transaction, and returns how many. Receipts, window membership and the
	// events' alert rows go with them by cascade. Rule: an event whose alert is
	// unfinished (alert_pending, or a delivery not finished) or that is a member
	// of an open detection window is kept until that is over.
	PruneEvents(ctx context.Context, before time.Time, batch int) (int64, error)
	// PruneAlertWindows deletes closed detection windows closed before `before`
	// (their membership cascades), in batches.
	PruneAlertWindows(ctx context.Context, before time.Time, batch int) (int64, error)
}
