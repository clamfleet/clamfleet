// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package store defines the persistence interface of the ClamFleet server
// (spec 8.1) and the record types that cross it.
//
// The interface is written so a PostgreSQL implementation can sit beside the
// SQLite one later (internal/store/sqlite) without touching callers: it speaks
// in domain types and time.Time, never in SQL, rows or driver types. Every
// time the store needs comes in as an argument (the caller's injected clock);
// the store never reads the wall clock.
//
// The agent must never import this package (nor its implementation): the agent
// stays free of SQLite to keep inside its memory budget. A test pins that.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

var (
	// ErrNotFound: the host (or token) does not exist.
	ErrNotFound = errors.New("not found")
	// ErrHostExists: a host with that name is already registered.
	ErrHostExists = errors.New("host already exists")
)

// Actor kinds of an audit row. Only the CLI exists in Milestone 2.
const ActorCLI = "cli"

// Audit says who performed an administrative change. The store writes the
// audit row in the same transaction as the change, so a change without its
// audit row cannot happen. Actor is a text snapshot, never a foreign key: an
// audit row must outlive the user it names.
type Audit struct {
	Kind  string // ActorCLI
	Actor string // OS user for the CLI
}

// Audit actions written by the store.
const (
	ActionHostAdd     = "host.add"
	ActionTokenRotate = "host.token.rotate"
	ActionTokenRevoke = "host.token.revoke"
	ActionHostDelete  = "host.delete"
)

// Rule: host names are lowercase, 1-253 characters of [a-z0-9._-], starting
// with a letter or digit. Names are lowercased in Go, not in SQL, because
// COLLATE NOCASE is not portable to PostgreSQL.
var hostNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,252}$`)

// NormalizeHostName lowercases and validates a host name.
func NormalizeHostName(name string) (string, error) {
	n := strings.ToLower(name)
	if !hostNameRE.MatchString(n) {
		return "", fmt.Errorf("invalid host name %q: use 1-253 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit", name)
	}
	return n, nil
}

// Host is a freshly registered host.
type Host struct {
	ID        int64
	Name      string
	CreatedAt time.Time
}

// HostRef is what authentication yields: the registered identity behind a token.
type HostRef struct {
	ID   int64
	Name string
}

// ReportRecord is one accepted heartbeat.
type ReportRecord struct {
	HostID int64
	// Report is stored as its canonical re-encoding: unknown fields are
	// dropped and the timestamp is normalised by proto.UTC. Raw bytes are not
	// kept, so the stored size stays bounded and the UI only ever meets keys
	// the server understands.
	Report     proto.Report
	ReceivedAt time.Time
}

// ReportResult describes what RecordReport did.
type ReportResult struct {
	// Stored is false when this (host, ts) was already stored (a retry).
	Stored bool
	// Newest is true when this report became the host's last_report.
	Newest bool
	// PreviousReportedName is the payload host name of the previous accepted
	// report ("" if none), for the host-mismatch warning.
	PreviousReportedName string
}

// EventRecord is one detection.
type EventRecord struct {
	HostID     int64
	Event      proto.Event
	ReceivedAt time.Time
}

// HostSummary is a row of the host list.
type HostSummary struct {
	ID           int64      `json:"id"`
	Name         string     `json:"name"`
	Tags         []string   `json:"tags"`
	HasToken     bool       `json:"has_token"` // false: the token is revoked
	CreatedAt    time.Time  `json:"created_at"`
	FirstSeen    *time.Time `json:"first_seen"`
	LastSeen     *time.Time `json:"last_seen"`
	ReportedName string     `json:"reported_name"`
	AgentVersion string     `json:"agent_version"`
	// State is OK, WARN, CRIT or STALE; nil while the host is pending (never
	// evaluated). StateReason is the JSON array of the current reasons (null
	// while pending) and StateSince the time of the last transition.
	State       *string         `json:"state"`
	StateReason json.RawMessage `json:"state_reason"`
	StateSince  *time.Time      `json:"state_since"`
}

// AuditEntry is a row of the audit log.
type AuditEntry struct {
	TS         time.Time `json:"ts"`
	ActorKind  string    `json:"actor_kind"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	TargetKind string    `json:"target_kind"`
	Target     string    `json:"target"`
	Detail     string    `json:"detail"`
}

// HostDetail is HostSummary plus the newest report and counters.
type HostDetail struct {
	HostSummary               // embedded: its fields are flattened into the JSON object
	TokenCreatedAt *time.Time `json:"token_created_at"`
	// LastReport is the canonical JSON of the newest report, nil before the first.
	LastReport  json.RawMessage `json:"last_report"`
	ReportCount int64           `json:"report_count"`
	EventCount  int64           `json:"event_count"`
	Audit       []AuditEntry    `json:"audit"` // newest first, at most 50
	// StateChanges is the state history, newest first, at most 50.
	StateChanges []StateChange `json:"state_changes"`
}

// StateChange is one transition of a host's state.
type StateChange struct {
	TS time.Time `json:"ts"`
	// From is nil on the host's first evaluation.
	From   *string         `json:"from_state"`
	To     string          `json:"to_state"`
	Reason json.RawMessage `json:"reason"` // the reasons at the time of the transition
}

// HealthInput is what the evaluator callback of EvaluateHosts gets for one
// host. The store owns these types so it never imports internal/health.
type HealthInput struct {
	HostID    int64
	Name      string
	CreatedAt time.Time
	// LastSeen is the server time of the last accepted report, nil if none.
	LastSeen *time.Time
	// Report is the newest stored report, nil before the first one.
	Report *proto.Report
	// FleetNewestDaily is the highest daily version among hosts with a token, 0 if none.
	FleetNewestDaily int
}

// HealthOutcome is the callback's answer. State "" means pending: nothing is
// written. Reasons is the JSON array stored in state_reason.
type HealthOutcome struct {
	State   string
	Reasons json.RawMessage
}

// Transition describes one state change EvaluateHosts wrote.
type Transition struct {
	HostID  int64
	Host    string
	TS      time.Time
	From    *string // nil on the first evaluation
	To      string
	Reasons json.RawMessage
}

// HealthStore persists host health (Milestone 3).
type HealthStore interface {
	// EvaluateHosts runs in ONE immediate write transaction: it reads the
	// inputs of the given hosts (nil = every host with a token) and the fleet's
	// newest daily version, calls eval for each, and writes the result.
	//
	// Reading and writing under one write lock is the point: an evaluation
	// that read its inputs before a report arrived must not overwrite the
	// state that report's own evaluation wrote (two spurious transitions,
	// which become alert spam in M4).
	//
	// When the new state differs from the stored one (NULL counts as
	// different) it writes state, state_reason, state_since and one
	// state_changes row. A change of reasons alone updates state_reason and
	// writes no row. A pending outcome writes nothing. Revoked or unknown hosts
	// are skipped. eval must not call the store (it runs inside the transaction).
	EvaluateHosts(ctx context.Context, now time.Time, ids []int64, eval func(HealthInput) HealthOutcome) ([]Transition, error)
}

// Store is the persistence interface. All methods are safe for concurrent use.
type Store interface {
	HealthStore
	// CreateHost registers a host with its token hash and writes the audit
	// row. ErrHostExists if the name is taken. The name is normalised.
	CreateHost(ctx context.Context, name string, tokenHash []byte, now time.Time, a Audit) (Host, error)
	// HostByTokenHash is the authentication lookup (read pool). ErrNotFound
	// for an unknown or revoked token. Other errors mean the store is unwell.
	HostByTokenHash(ctx context.Context, hash []byte) (HostRef, error)
	// SetToken replaces the host's token hash (rotate), or revokes the token
	// when hash is nil. The old token stops working immediately. ErrNotFound
	// for an unknown host.
	SetToken(ctx context.Context, name string, hash []byte, now time.Time, a Audit) error
	// DeleteHost removes the host and, by cascade, its reports, events, tags and
	// state history (M2 decision 2), and writes the audit row in the same
	// transaction. The audit row keeps the host name as text, so it outlives the
	// host. ErrNotFound for an unknown host.
	DeleteHost(ctx context.Context, name string, now time.Time, a Audit) error
	// RecordReport stores a heartbeat idempotently and updates the host.
	RecordReport(ctx context.Context, r ReportRecord) (ReportResult, error)
	// RecordEvent stores a detection idempotently; stored is false for a duplicate.
	RecordEvent(ctx context.Context, e EventRecord) (stored bool, err error)
	ListHosts(ctx context.Context) ([]HostSummary, error)
	// HostByName returns ErrNotFound for an unknown host.
	HostByName(ctx context.Context, name string) (HostDetail, error)
	// Ping checks the read pool answers.
	Ping(ctx context.Context) error
	Close() error
}
