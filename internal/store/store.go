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
	"unicode/utf8"

	"github.com/clamfleet/clamfleet/internal/proto"
)

var (
	// ErrNotFound: the host (or token) does not exist.
	ErrNotFound = errors.New("not found")
	// ErrHostExists: a host with that name is already registered.
	ErrHostExists = errors.New("host already exists")
	// ErrUserExists: a user with that email already exists.
	ErrUserExists = errors.New("user already exists")
	// ErrCredentialChanged: the user's password changed or the user was disabled
	// (or disabled and enabled again) after the caller verified the credential. A login gets no session; a
	// self-service password change is refused. Nothing was written.
	ErrCredentialChanged = errors.New("credential changed")
)

// Actor kinds of an audit row: the admin CLI, or a signed-in console user.
const (
	ActorCLI  = "cli"
	ActorUser = "user" // Actor is then the user's email, a text snapshot
)

// Audit says who performed an administrative change. The store writes the
// audit row in the same transaction as the change, so a change without its
// audit row cannot happen. Actor is a text snapshot, never a foreign key: an
// audit row must outlive the user it names.
type Audit struct {
	Kind  string // ActorCLI or ActorUser
	Actor string // OS user for the CLI, the email for a console user
}

// Audit actions written by the store.
const (
	ActionHostAdd     = "host.add"
	ActionTokenRotate = "host.token.rotate"
	ActionTokenRevoke = "host.token.revoke"
	ActionHostDelete  = "host.delete"

	ActionUserAdd           = "user.add"
	ActionUserRole          = "user.role"
	ActionUserDisable       = "user.disable"
	ActionUserEnable        = "user.enable"
	ActionUserPasswordReset = "user.password.reset"  // set by an admin through the CLI
	ActionUserPasswordSet   = "user.password.change" // changed by the user themselves
	ActionUserLogin         = "user.login"
	ActionUserLoginFailed   = "user.login.failed"
	ActionUserLogout        = "user.logout"
)

// Target kinds of an audit row.
const (
	TargetHost = "host"
	TargetUser = "user"
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
	// OpenEvents counts the host's unacknowledged events. RecentEvents (its 10
	// newest, any state) is for the console only: it holds paths, which the
	// admin CLI's JSON must not print.
	OpenEvents   int64        `json:"open_events"`
	RecentEvents []EventRow   `json:"-"`
	Audit        []AuditEntry `json:"audit"` // newest first, at most 50
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
	// ReportUnreadable is true when the host has a stored last_report that
	// could not be decoded (corruption). Report is nil then, but the host did
	// report: LastSeen is set.
	ReportUnreadable bool
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

// FleetRow is one line of the fleet overview.
type FleetRow struct {
	ID   int64
	Name string
	Tags []string
	// State is nil while the host is pending (never evaluated).
	State        *string
	StateReason  json.RawMessage // JSON array of reasons; nil while pending
	StateSince   *time.Time
	LastSeen     *time.Time
	ClamdVersion string
	// DailyVersion and DailyBuilt are nil when the host has no daily database
	// (or has not reported).
	DailyVersion *int
	DailyBuilt   *time.Time
	// OpenEvents counts the host's unacknowledged detections.
	OpenEvents int64
}

// HealthStore persists host health (Milestone 3).
type HealthStore interface {
	// ListFleet returns the hosts that have a token (revoked hosts are left out),
	// ordered by name, with their tags: the overview page. Read pool.
	ListFleet(ctx context.Context) ([]FleetRow, error)

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

// Roles of a console user. Validated here, not by a CHECK constraint, so a new
// role is never a table rebuild.
const (
	RoleViewer = "viewer"
	RoleAdmin  = "admin"
)

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { return r == RoleViewer || r == RoleAdmin }

// AuthLocal is the auth_source of password users.
const AuthLocal = "local"

// NormalizeEmail lowercases and trims an email and does the sanity check a
// login name needs: one '@' with text on both sides, at most 254 bytes, no
// whitespace or control characters. It is not RFC 5322 validation: the address
// is an account name here, nothing is ever sent to it.
func NormalizeEmail(e string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(e))
	at := strings.Index(n, "@")
	if len(n) > 254 || at < 1 || at != strings.LastIndex(n, "@") || at == len(n)-1 {
		return "", fmt.Errorf("invalid email %q", TruncateForAudit(e))
	}
	for _, r := range n {
		if r <= ' ' || r == 0x7f {
			return "", fmt.Errorf("invalid email %q", TruncateForAudit(e))
		}
	}
	return n, nil
}

// TruncateForAudit cuts text typed by an untrusted client (a login email) to
// 254 bytes on a rune boundary before it goes into the audit log or an error.
func TruncateForAudit(s string) string {
	if len(s) <= 254 {
		return s
	}
	s = s[:254]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// User is a console account.
type User struct {
	ID          int64      `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	Role        string     `json:"role"`
	AuthSource  string     `json:"auth_source"`
	Disabled    bool       `json:"disabled"`
	MustChange  bool       `json:"password_must_change"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
	// PasswordHash is the PHC string; it is never serialised and empty for
	// accounts without a local password.
	PasswordHash string `json:"-"`
	// AuthVersion counts the changes that must invalidate a login in flight
	// (password set or reset, disable, enable). A login reads it with the user
	// and the store creates a session only if it is unchanged. Internal.
	AuthVersion int64 `json:"-"`
	// TOTPEnabled and TOTPFailures describe the second factor (the secret itself
	// is never loaded here). Failures at SecondFactorLockLimit means locked.
	TOTPEnabled  bool `json:"totp_enabled"`
	TOTPFailures int  `json:"totp_failures"`
}

// NewUser is a user to create. PasswordHash is a PHC string.
type NewUser struct {
	Email        string
	DisplayName  string
	Role         string
	PasswordHash string
	MustChange   bool
}

// PasswordChange describes SetPassword.
type PasswordChange struct {
	Hash       string
	MustChange bool
	// ExpectedHash, when set, makes the change a compare-and-swap: it applies only
	// while the stored hash is still this one (the hash the caller verified as
	// the current password). Otherwise ErrCredentialChanged and nothing is written.
	// A self-service change must set it, so it can never overwrite an admin reset
	// that committed in between. The CLI reset leaves it empty (unconditional).
	ExpectedHash string
	// Self is true when the user changes their own password (audit action
	// user.password.change); false for an admin reset (user.password.reset).
	Self bool
	// KeepSession, when set, is the token hash of the session that survives
	// (the one the user is changing the password from).
	KeepSession []byte
}

// Session is a new console session. Only the hash of the cookie token is stored.
type Session struct {
	TokenHash []byte
	UserID    int64
	CSRF      []byte
	CreatedAt time.Time
	ExpiresAt time.Time
	// PasswordHash is the hash of the credential the login verified. CreateSession
	// stores the session only if the user still has exactly this hash and is not
	// disabled (ErrCredentialChanged otherwise).
	PasswordHash string
	// AuthVersion is the user's auth_version the login read. The session is
	// stored only if it is still current: a disable followed by an enable
	// changes it twice while leaving the password hash alone.
	AuthVersion int64
}

// SessionPrincipal is a valid session joined with its user, read fresh on
// every request so a disable or role change applies at once.
type SessionPrincipal struct {
	SessionID  int64
	UserID     int64
	Email      string
	Name       string
	Role       string
	CSRF       []byte
	MustChange bool
	LastSeen   time.Time
	// AuthSource is the user's identity source ("local"); TOTPEnabled is read
	// fresh on every request so a forced-enrolment gate applies at once.
	AuthSource  string
	TOTPEnabled bool
}

// UserStore persists console users. Every change that matters writes its audit
// row in the same transaction. Emails are normalised by the store.
type UserStore interface {
	// CreateUser: ErrUserExists for a taken email; an invalid email or role is an error.
	CreateUser(ctx context.Context, u NewUser, now time.Time, a Audit) (User, error)
	// UserByEmail: ErrNotFound when there is none (read pool).
	UserByEmail(ctx context.Context, email string) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
	CountUsers(ctx context.Context) (int64, error)
	// SetPassword replaces the hash and deletes the user's sessions (all, or all
	// but KeepSession). ErrNotFound for an unknown id.
	SetPassword(ctx context.Context, id int64, c PasswordChange, now time.Time, a Audit) error
	// RehashPassword stores an upgraded hash of the SAME password after a login:
	// no audit row, no session change. It is a compare-and-swap: it only applies
	// while the stored hash is still oldHash (the one that was verified), so a
	// reset or change that committed in between is never overwritten. A lost
	// race is not an error (nil); the newer password simply stays.
	// applied reports whether the new hash was stored.
	RehashPassword(ctx context.Context, id int64, oldHash, newHash string, now time.Time) (applied bool, err error)
	// SetRole and SetDisabled (disable AND enable) delete the user's sessions in
	// the same transaction. Enable matters too: a login that was verifying while
	// the user was disabled must not turn into a live session on re-enable.
	SetRole(ctx context.Context, id int64, role string, now time.Time, a Audit) error
	SetDisabled(ctx context.Context, id int64, disabled bool, now time.Time, a Audit) error
	// RecordLogin sets last_login_at and writes the user.login audit row.
	RecordLogin(ctx context.Context, id int64, now time.Time, a Audit, detail map[string]string) error
	// RecordAudit writes one audit row on its own (failed logins, logout).
	// detail must never hold a secret.
	RecordAudit(ctx context.Context, now time.Time, a Audit, action, targetKind, target string, detail map[string]string) error
}

// SessionStore persists console sessions.
type SessionStore interface {
	// CreateSession is conditional on Session.PasswordHash, see there.
	CreateSession(ctx context.Context, s Session) error
	// SessionByTokenHash returns ErrNotFound when the session is missing,
	// absolutely expired (expires_at <= now), idle-expired (last seen at or
	// before now-idle) or its user is disabled.
	SessionByTokenHash(ctx context.Context, hash []byte, now time.Time, idle time.Duration) (SessionPrincipal, error)
	// TouchSession records activity, at most once a minute per session.
	TouchSession(ctx context.Context, id int64, now time.Time) error
	DeleteSession(ctx context.Context, hash []byte) error
	// DeleteExpiredSessions removes absolutely and idle-expired rows.
	DeleteExpiredSessions(ctx context.Context, now time.Time, idle time.Duration) (int64, error)
}

// Store is the persistence interface. All methods are safe for concurrent use.
type Store interface {
	HealthStore
	UserStore
	SessionStore
	TOTPStore
	AlertStore
	EventStore
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
	// RecordEvent stores a detection idempotently (one transaction). With an
	// event id (agent idempotency key): a retry of an id already received is
	// stored=false and changes nothing; a DIFFERENT id that collides on (host,
	// second, path, signature) merges into the existing row (occurrences + 1)
	// and is stored=false, so it raises no second alert but is never lost.
	// Without an id the natural key alone dedups, as before.
	RecordEvent(ctx context.Context, e EventRecord) (stored bool, err error)
	ListHosts(ctx context.Context) ([]HostSummary, error)
	// HostByName returns ErrNotFound for an unknown host.
	HostByName(ctx context.Context, name string) (HostDetail, error)
	// Ping checks the read pool answers.
	Ping(ctx context.Context) error
	Close() error
}
