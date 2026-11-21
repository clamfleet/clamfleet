// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// totp.go: the persistence interface of the TOTP second factor (Milestone 3b)
// and the types that cross it.
//
// The store never sees a plain secret and never verifies a code: it holds the
// SEALED secret (internal/secrets) and decides only what is a database
// decision, as a compare-and-swap inside one transaction: the single use of a
// login challenge, of a time step and of a recovery code, the user's
// auth_version, the failure counter and its lock.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrReplay: the time step was already used (it is not above the user's last accepted step).
	ErrReplay = errors.New("one-time code already used")
	// ErrBadRecovery: the recovery code is unknown, or was already used.
	ErrBadRecovery = errors.New("recovery code not valid")
	// ErrSecondFactorLocked: the user reached the limit of consecutive wrong codes.
	ErrSecondFactorLocked = errors.New("second factor locked")
)

// Audit actions of the TOTP feature.
const (
	ActionTOTPEnable    = "user.totp.enable"
	ActionTOTPReplace   = "user.totp.replace"
	ActionTOTPDisable   = "user.totp.disable" // by the user
	ActionTOTPReset     = "user.totp.reset"   // by an admin through the CLI
	ActionTOTPRecovery  = "user.totp.recovery.regenerate"
	ActionTOTPLocked    = "user.totp.locked"
	ActionSecretsReseal = "secrets.reencrypt"
)

// TargetServer is the audit target kind (and name) of server-wide actions.
const TargetServer = "server"

// SecondFactorLockLimit is the number of consecutive wrong second-factor
// attempts that locks it until an admin resets the password or the TOTP. 100 is
// the ceiling of NIST SP 800-63B for failed attempts per account.
const SecondFactorLockLimit = 100

// TOTPState is what the login and the account page need about a user's second factor.
type TOTPState struct {
	UserID      int64
	Email       string
	Enabled     bool
	Disabled    bool   // the account is disabled
	Sealed      []byte // the sealed shared secret; nil without TOTP
	LastStep    *int64 // highest accepted time step; nil before the first
	Failures    int    // consecutive wrong codes
	AuthVersion int64
}

// LoginChallenge is a verified password waiting for its second factor. It is
// NOT a session: a separate table, token prefix and cookie.
type LoginChallenge struct {
	TokenHash []byte
	UserID    int64
	// AuthVersion and PasswordHash are what the password step saw; CreateLoginChallenge
	// stores the challenge only while they are still current.
	AuthVersion  int64
	PasswordHash string
	Next         string // sanitised redirect target
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// CompleteLogin describes the one transaction that turns a challenge into a session.
type CompleteLogin struct {
	ChallengeHash []byte
	// Session is the new session; its UserID is taken from the challenge, never from the caller.
	Session Session
	// Exactly one of Step and RecoveryHash is set.
	Step         *int64 // the matched time step
	RecoveryHash []byte // SHA-256 of the normalised recovery code
	// Limit is the failure count at which the second factor is locked.
	Limit int
}

// EnableTOTP describes (re)enrolment.
type EnableTOTP struct {
	UserID int64
	// ExpectedVersion is the auth_version read just before; the change applies only while it is current.
	ExpectedVersion int64
	Sealed          []byte // the secret sealed for purpose "totp"
	Step            int64  // the time step of the confirming code: it cannot be replayed
	RecoveryHashes  [][]byte
	// SessionID is the session the enrolment ran in (its pending secret is cleared);
	// KeepSession is its token hash, the one session that survives.
	SessionID   int64
	KeepSession []byte
}

// SealedSecret is a stored TOTP secret, for the start-up check and re-encryption.
type SealedSecret struct {
	UserID int64
	Email  string
	Sealed []byte
}

// Reseal replaces one sealed secret by another, only if it is still Old.
type Reseal struct {
	UserID int64
	Old    []byte
	New    []byte
}

// TOTPStore persists the second factor. Times come from the caller's clock.
type TOTPStore interface {
	// UserTOTP reads a user's second-factor state (read pool). ErrNotFound for an unknown id.
	UserTOTP(ctx context.Context, userID int64) (TOTPState, error)

	// CreateLoginChallenge inserts only if the user still has c.AuthVersion and
	// c.PasswordHash and is active (else ErrCredentialChanged). It keeps at most
	// 5 open challenges per user (the oldest go) and drops the user's expired ones.
	CreateLoginChallenge(ctx context.Context, c LoginChallenge, now time.Time) error
	// LoginChallenge returns ErrNotFound for a missing or expired (expires_at <= now) challenge.
	LoginChallenge(ctx context.Context, tokenHash []byte, now time.Time) (LoginChallenge, error)
	// CompleteLogin runs in ONE transaction, in this order: delete the challenge
	// (ErrNotFound if it is gone or expired, so it is used once); check the user's
	// auth_version, disabled flag and failure count (ErrCredentialChanged,
	// ErrSecondFactorLocked); consume the time step (ErrReplay) or the recovery
	// code (ErrBadRecovery) by compare-and-swap; reset the failure counter; insert
	// the session; set last_login_at; write the user.login audit row (detail is
	// the caller's, e.g. {ip, mfa}). Any error rolls everything back, so a refused
	// attempt leaves the challenge usable.
	CompleteLogin(ctx context.Context, c CompleteLogin, now time.Time, detail map[string]string) error
	// RecordSecondFactorFailure adds one to the failure counter in SQL, writes a
	// user.login.failed audit row (detail has the reason) and, when the counter
	// reaches limit, a user.totp.locked row. It returns the new count.
	RecordSecondFactorFailure(ctx context.Context, userID int64, limit int, now time.Time, a Audit, detail map[string]string) (int, error)

	// SetPendingTOTP stores the sealed secret of an enrolment in the session it
	// was started in, replacing an earlier one. ErrNotFound if the session is gone.
	SetPendingTOTP(ctx context.Context, sessionID int64, sealed []byte, now time.Time) error
	// PendingTOTP returns that session's pending secret; ErrNotFound if there is none.
	PendingTOTP(ctx context.Context, sessionID int64) (sealed []byte, at time.Time, err error)
	// EnableTOTP, one transaction: compare-and-swap on auth_version (else
	// ErrCredentialChanged); set the secret and enrolment time and the step; reset
	// the failures; bump auth_version; replace the recovery codes; clear the
	// session's pending secret; delete the user's other sessions and all their
	// login challenges; audit user.totp.enable (user.totp.replace if they had TOTP).
	EnableTOTP(ctx context.Context, e EnableTOTP, now time.Time, a Audit) error
	// DisableTOTP removes the secret, step and recovery codes, zeroes the failures,
	// bumps auth_version, deletes the user's sessions (all but keep, when set) and
	// challenges, and audits action (ActionTOTPDisable or ActionTOTPReset).
	// ErrNotFound for an unknown user.
	DisableTOTP(ctx context.Context, userID int64, keep []byte, action string, now time.Time, a Audit) error
	// ReplaceRecoveryCodes replaces all codes of a user who has TOTP (else
	// ErrCredentialChanged) and audits user.totp.recovery.regenerate.
	ReplaceRecoveryCodes(ctx context.Context, userID int64, hashes [][]byte, now time.Time, a Audit) error
	// RecoveryCodesLeft counts the unused codes.
	RecoveryCodesLeft(ctx context.Context, userID int64) (int, error)

	// SealedTOTPSecrets lists every stored sealed secret (start-up check, key rotation).
	SealedTOTPSecrets(ctx context.Context) ([]SealedSecret, error)
	// ResealTOTPSecrets applies each replacement only while the stored blob is
	// still Old (compare-and-swap), and audits secrets.reencrypt. It returns how
	// many were applied and the user ids whose blob changed meanwhile (conflicts).
	// Key rotation uses ResealSecrets (AlertStore), which does TOTP and alert
	// targets in one transaction.
	ResealTOTPSecrets(ctx context.Context, rs []Reseal, now time.Time, a Audit) (applied int, conflicts []int64, err error)

	// DeleteExpiredChallenges removes challenges with expires_at <= now.
	DeleteExpiredChallenges(ctx context.Context, now time.Time) (int64, error)
}
