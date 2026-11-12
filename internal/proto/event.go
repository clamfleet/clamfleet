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
type Event struct {
	Schema    int       `json:"schema"`
	Host      string    `json:"host"`
	TS        time.Time `json:"ts"`
	Path      string    `json:"path"`
	Signature string    `json:"signature"`
	Source    string    `json:"source"`
}
