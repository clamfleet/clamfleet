// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// timefmt.go: human time text for the pages. Every function takes the
// current time as an argument (the injected clock): none reads the wall clock.
package web

import (
	"fmt"
	"time"
)

// ago renders how long before now t was: "just now", "3m ago", "2h ago",
// "5d ago". A time in the future (clock skew between a host and the server
// cannot cause it, since last_seen is the server's own clock, but a clock step
// can) reads "just now" rather than a negative duration.
func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d/time.Hour))
	default:
		return fmt.Sprintf("%dd ago", int(d/(24*time.Hour)))
	}
}

// age renders a duration without "ago": "3h", "2d 4h".
func age(d time.Duration) string {
	switch {
	case d < 0:
		return "0m"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	default:
		days := int(d / (24 * time.Hour))
		return fmt.Sprintf("%dd %dh", days, int((d%(24*time.Hour))/time.Hour))
	}
}

// abs renders a time as UTC text for title attributes and tables. UTC on
// purpose: the server and its operators span time zones, and a fleet console
// that shows local time is a source of 2 a.m. misreadings.
func abs(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }
