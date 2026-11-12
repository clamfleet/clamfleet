// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package proto defines the JSON payloads exchanged between the agent and the
// server (spec sections 7.3 and 7.4).
//
// These structs are a PUBLIC INTERFACE (spec 15a, 16): other agents and
// servers are written against them. Do not rename a key or change a type
// without bumping SchemaVersion and keeping the server accepting the old one.
//
// Conventions:
//   - No omitempty anywhere. Every key in the spec is always present; a value
//     that is unknown is an explicit JSON null (pointer fields), never a
//     missing key and never a misleading zero.
//   - All timestamps are UTC, whole seconds (see UTC).
package proto

import "time"

// SchemaVersion is the value of the "schema" key in every payload.
const SchemaVersion = 1

// UTC normalises a timestamp for the wire: UTC, truncated to whole seconds,
// so the same instant always encodes to the same text.
func UTC(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }
