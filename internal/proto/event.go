// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// event.go: the detection payload the agent sends to POST /v1/event (spec 7.4).
//
// Responsibilities: the Event struct. A public interface (see doc.go): do not
// rename keys or change types without a schema bump.
// Dependencies: the standard library only.

package proto

import "time"

// Event is a single detection, sent to POST /v1/event (spec 7.4).
//
// Path convention of the agent (the type does not change): a backslash is sent
// as two backslashes and each byte that is not part of valid UTF-8 as \xNN, so
// two distinct file names can never become the same string. A client that
// sends raw backslashes is shown as it sent them.
type Event struct {
	Schema int `json:"schema"`
	// ID is the agent's idempotency key: 32 lowercase hex characters, or null
	// for a client that has none. A retry carries the same ID, so the server can
	// tell a retry from a second, genuine detection with the same host, second,
	// path and signature. Added after the spec example of section 7.4 (decision
	// 16 of milestone 5); compatible, so Schema stays 1.
	ID        *string   `json:"id"`
	Host      string    `json:"host"`
	TS        time.Time `json:"ts"`
	Path      string    `json:"path"`
	Signature string    `json:"signature"`
	Source    string    `json:"source"`
}
