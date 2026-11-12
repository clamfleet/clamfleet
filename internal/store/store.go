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
	ID           int64
	Name         string
	Tags         []string
	HasToken     bool // false: the token is revoked
	CreatedAt    time.Time
	FirstSeen    *time.Time
	LastSeen     *time.Time
	ReportedName string
	AgentVersion string
}

// AuditEntry is a row of the audit log.
type AuditEntry struct {
	TS         time.Time
	ActorKind  string
	Actor      string
	Action     string
	TargetKind string
	Target     string
	Detail     string
}

// HostDetail is HostSummary plus the newest report and counters.
type HostDetail struct {
	HostSummary
	TokenCreatedAt *time.Time
	// LastReport is the canonical JSON of the newest report, nil before the first.
	LastReport  json.RawMessage
	ReportCount int64
	EventCount  int64
	Audit       []AuditEntry // newest first, at most 50
}

// Store is the persistence interface. All methods are safe for concurrent use.
type Store interface {
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
