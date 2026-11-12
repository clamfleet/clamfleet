// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// report.go: the heartbeat payload the agent sends to POST /v1/report
// (spec 7.3).
//
// Responsibilities: the Report struct and its parts, plus the service state
// constants. These types are a public interface (see
// doc.go): do not rename keys or change types without a schema bump.
// Dependencies: the standard library only.

package proto

import "time"

// Service state values besides systemd's own ActiveState strings
// ("active", "inactive", "failed", "activating", "deactivating", "reloading").
const (
	// ServiceNotFound: the unit does not exist on this host (or none is configured).
	ServiceNotFound = "not-found"
	// ServiceUnknown: the state could not be determined (systemctl failed).
	ServiceUnknown = "unknown"
)

// Report is the heartbeat sent to POST /v1/report (spec 7.3).
type Report struct {
	Schema       int    `json:"schema"`
	Host         string `json:"host"`
	AgentVersion string `json:"agent_version"`
	// Tags is never nil: an empty list encodes as [] (assumption A3).
	Tags      []string  `json:"tags"`
	TS        time.Time `json:"ts"`
	OS        OS        `json:"os"`
	Clamd     Clamd     `json:"clamd"`
	Sigs      Sigs      `json:"sigs"`
	Freshclam Freshclam `json:"freshclam"`
	Services  Services  `json:"services"`
	// LastScan is null when no scan summary file exists (no scan configured).
	LastScan *LastScan `json:"last_scan"`
}

// OS identifies the distribution, from os-release(5) ID and VERSION_ID.
// Either is "" when the host does not provide it (e.g. Debian sid has no VERSION_ID).
type OS struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// Clamd is the result of probing the clamd socket.
type Clamd struct {
	// Up is true only if zPING was answered with PONG.
	Up bool `json:"up"`
	// Version is the clamd version, null when unknown.
	Version *string `json:"version"`
	// Queue is the number of queued items, null when unknown: 0 would claim an empty queue.
	Queue *int `json:"queue"`
	// Error is a short human-readable reason when something failed, else null.
	Error *string `json:"error"`
}

// Sigs holds the three official signature databases. Each is null when the
// file is missing or its header is invalid.
type Sigs struct {
	Daily    *SigDB `json:"daily"`
	Main     *SigDB `json:"main"`
	Bytecode *SigDB `json:"bytecode"`
}

// SigDB is the parsed header of one .cvd or .cld file.
type SigDB struct {
	Version int       `json:"version"`
	Built   time.Time `json:"built"`
	Sigs    int64     `json:"sigs"`
}

// Values of Freshclam.Source.
const (
	SourceJournal    = "journal"
	SourceLog        = "log"
	SourceJournalLog = "journal+log"
	SourceMtime      = "mtime"
)

// Freshclam is the outcome of the signature updater. Every field is null when unknown.
//
// Source says where the values came from, so an operator can tell a measured
// failure state from a guess: "journal" (freshclam unit journal), "log" (the
// freshclam log file), "journal+log" (update runs were found in both, and the
// newest of each kind wins), "mtime" (last resort: modification time of the
// daily database, which can never show a failed update), or null when nothing
// is known. Source has no omitempty: null is an answer, a missing key is not.
// It was added after the spec example of section 7.3; the addition is
// compatible, so Schema stays 1 (servers ignore unknown fields, spec 7.2).
type Freshclam struct {
	LastOK       *time.Time `json:"last_ok"`
	LastError    *time.Time `json:"last_error"`
	LastErrorMsg *string    `json:"last_error_msg"`
	Source       *string    `json:"source"`
}

// Services holds one state per unit: a systemd ActiveState, ServiceNotFound or ServiceUnknown.
type Services struct {
	Clamd     string `json:"clamd"`
	Freshclam string `json:"freshclam"`
	Clamonacc string `json:"clamonacc"`
}

// LastScan is the summary of the last scheduled scan. It is also the on-disk
// format of last_scan.json, which the scan wrapper writes in a later milestone.
type LastScan struct {
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Exit     int       `json:"exit"`
	Scanned  int64     `json:"scanned"`
	Infected int64     `json:"infected"`
	Errors   int64     `json:"errors"`
}
