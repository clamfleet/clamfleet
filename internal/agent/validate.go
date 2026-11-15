// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// validate.go: the trust-boundary checks for spooled items.
//
// Anything in spool/events may have been written by clamd's group, or planted
// by someone who got that far, so the agent never sends the bytes it read. It
// decodes them into the proto struct, checks every bound the server will
// check (and a few it will not), and the request body is json.Marshal of the
// validated struct: unknown fields and odd encodings do not survive the trip.
//
// Error texts never contain the path: they end up in the agent's log.
// Dependencies: the proto package and the standard library.

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// Bounds of a spooled event (milestone 5, section 4.3).
const (
	maxEventPathBytes      = 4096
	maxEventSignatureBytes = 256
	maxEventHostBytes      = 253
	// eventFutureSlack is how far ahead of the agent clock a ts may be: clock
	// skew between clamd's host time and ours is zero (same host), so ten
	// minutes only absorbs a clock step.
	eventFutureSlack = 10 * time.Minute
)

// minEventTime is the earliest plausible detection time.
var minEventTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// errExpired marks an event older than spool.max_event_days. It is not an
// invalid item: the caller deletes it (with a log line) instead of quarantining.
var errExpired = errors.New("event older than spool.max_event_days")

// invalidError says why an item failed validation. The reason is static text
// or a number, never item content.
type invalidError struct{ Reason string }

func (e *invalidError) Error() string { return e.Reason }

func invalid(format string, a ...any) error {
	return &invalidError{Reason: fmt.Sprintf(format, a...)}
}

// isLowerHex32 reports whether s is exactly 32 lowercase hex characters.
func isLowerHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ValidateEvent decodes and checks a spooled event. nameID is the id taken
// from the item's file name: it must match the id inside, so a renamed or
// swapped file is rejected. maxAge is spool.max_event_days. It returns the
// event to re-encode, errExpired for an event past its age limit, or an
// *invalidError.
func ValidateEvent(raw []byte, nameID string, now time.Time, maxAge time.Duration) (proto.Event, error) {
	var ev proto.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return ev, invalid("not a JSON event")
	}
	switch {
	case ev.Schema != proto.SchemaVersion:
		return ev, invalid("schema %d is not %d", ev.Schema, proto.SchemaVersion)
	case ev.ID == nil || !isLowerHex32(*ev.ID):
		return ev, invalid("id is not 32 lowercase hex characters")
	case *ev.ID != nameID:
		return ev, invalid("id does not match the file name")
	case len(ev.Host) == 0 || len(ev.Host) > maxEventHostBytes || strings.IndexFunc(ev.Host, isControl) >= 0:
		return ev, invalid("host is empty, too long or has control characters")
	case ev.TS.IsZero() || ev.TS.Before(minEventTime):
		return ev, invalid("ts is zero or before 2000")
	case ev.TS.After(now.Add(eventFutureSlack)):
		return ev, invalid("ts is more than 10 minutes in the future")
	case len(ev.Path) == 0 || len(ev.Path) > maxEventPathBytes:
		return ev, invalid("path length %d is outside 1-%d bytes", len(ev.Path), maxEventPathBytes)
	case !utf8.ValidString(ev.Path) || strings.IndexByte(ev.Path, 0) >= 0:
		return ev, invalid("path is not valid UTF-8 or contains NUL")
	case len(ev.Signature) == 0 || len(ev.Signature) > maxEventSignatureBytes || !printableASCII(ev.Signature):
		return ev, invalid("signature is empty, too long or not printable ASCII")
	case ev.Source != "clamd":
		return ev, invalid("source is not clamd")
	}
	// After the shape checks, so a malformed item is quarantined, not expired.
	if maxAge > 0 && ev.TS.Before(now.Add(-maxAge)) {
		return ev, errExpired
	}
	return ev, nil
}

// ValidateReport decodes and checks a spooled heartbeat. Its owner was checked
// by the reader. The replay flag in the file is ignored: the agent sets it at
// send time (drain.go).
func ValidateReport(raw []byte) (proto.Report, error) {
	var r proto.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, invalid("not a JSON report")
	}
	switch {
	case r.Schema != proto.SchemaVersion:
		return r, invalid("schema %d is not %d", r.Schema, proto.SchemaVersion)
	case r.TS.IsZero():
		return r, invalid("ts is zero")
	}
	r.Replay = false
	return r, nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) }

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
