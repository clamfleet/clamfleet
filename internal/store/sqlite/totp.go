// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// totp.go: store.TOTPStore on SQLite.
//
// Every decision here is a conditional UPDATE or DELETE inside the single
// immediate write transaction (s.inTx), and the Go code reads its row count:
// the single use of a challenge, of a time step and of a recovery code, the
// auth_version check and the failure count are never "read, decide in Go,
// write". The writer connection serialises transactions, so two parallel
// completions of one challenge cannot both win.
//
// The store handles only SEALED secrets (blobs made by internal/secrets); it
// never decrypts and never sees a plain secret or a submitted code.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite/sqlcdb"
)

var _ store.TOTPStore = (*Store)(nil)

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

// UserTOTP implements store.TOTPStore.
func (s *Store) UserTOTP(ctx context.Context, userID int64) (store.TOTPState, error) {
	r, err := sqlcdb.New(s.r).UserTOTP(ctx, userID)
	if err != nil {
		return store.TOTPState{}, notFound(err)
	}
	st := store.TOTPState{
		UserID: r.ID, Email: r.Email.String, Enabled: r.TotpEnabledAt.Valid, Disabled: r.DisabledAt.Valid,
		Sealed: r.TotpSecret, Failures: int(r.TotpFailures), AuthVersion: r.AuthVersion,
	}
	if r.TotpLastStep.Valid {
		v := r.TotpLastStep.Int64
		st.LastStep = &v
	}
	return st, nil
}

// CreateLoginChallenge implements store.TOTPStore.
func (s *Store) CreateLoginChallenge(ctx context.Context, c store.LoginChallenge, now time.Time) error {
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		n, err := q.CreateLoginChallenge(ctx, sqlcdb.CreateLoginChallengeParams{
			TokenHash: c.TokenHash, Next: c.Next, Now: unix(c.CreatedAt), ExpiresAt: unix(c.ExpiresAt),
			UserID: c.UserID, ExpectedHash: nullStr(c.PasswordHash), ExpectedVersion: c.AuthVersion,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return store.ErrCredentialChanged
		}
		// Each challenge costs a correct password and an argon2 hash, so this is
		// bounded already; the cap keeps a password holder from filling the table.
		return q.PruneLoginChallenges(ctx, sqlcdb.PruneLoginChallengesParams{UserID: c.UserID, Now: unix(now)})
	})
}

// LoginChallenge implements store.TOTPStore.
func (s *Store) LoginChallenge(ctx context.Context, tokenHash []byte, now time.Time) (store.LoginChallenge, error) {
	if len(tokenHash) == 0 {
		return store.LoginChallenge{}, store.ErrNotFound
	}
	r, err := sqlcdb.New(s.r).LoginChallengeByHash(ctx, sqlcdb.LoginChallengeByHashParams{TokenHash: tokenHash, Now: unix(now)})
	if err != nil {
		return store.LoginChallenge{}, notFound(err)
	}
	return store.LoginChallenge{
		TokenHash: tokenHash, UserID: r.UserID, AuthVersion: r.AuthVersion, Next: r.Next,
		CreatedAt: time.Unix(r.CreatedAt, 0).UTC(), ExpiresAt: time.Unix(r.ExpiresAt, 0).UTC(),
	}, nil
}

// CompleteLogin implements store.TOTPStore.
func (s *Store) CompleteLogin(ctx context.Context, c store.CompleteLogin, now time.Time, detail map[string]string) error {
	if (c.Step == nil) == (c.RecoveryHash == nil) {
		return errors.New("complete login: exactly one of a time step and a recovery code is required")
	}
	if c.Limit < 1 {
		return errors.New("complete login: the lock limit must be positive")
	}
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		// First: delete the challenge. It is the ticket for this transaction, and
		// whatever fails below rolls the delete back with everything else.
		ch, err := q.ConsumeLoginChallenge(ctx, sqlcdb.ConsumeLoginChallengeParams{TokenHash: c.ChallengeHash, Now: unix(now)})
		if err != nil {
			return notFound(err)
		}
		u, err := q.UserTOTP(ctx, ch.UserID)
		if err != nil {
			return notFound(err)
		}
		// The user must be exactly as the password step saw them, still active and
		// still enrolled: a reset, a disable (and enable), a new password or a new
		// authenticator in between all bumped the version.
		if u.AuthVersion != ch.AuthVersion || u.DisabledAt.Valid || !u.TotpEnabledAt.Valid {
			return store.ErrCredentialChanged
		}
		if int(u.TotpFailures) >= c.Limit {
			return store.ErrSecondFactorLocked
		}
		if c.Step != nil {
			n, err := q.ConsumeTOTPStep(ctx, sqlcdb.ConsumeTOTPStepParams{Step: sql.NullInt64{Int64: *c.Step, Valid: true}, ID: ch.UserID})
			if err != nil {
				return err
			}
			if n == 0 {
				return store.ErrReplay
			}
		} else {
			n, err := q.ConsumeRecoveryCode(ctx, sqlcdb.ConsumeRecoveryCodeParams{Now: nullInt(now), UserID: ch.UserID, CodeHash: c.RecoveryHash})
			if err != nil {
				return err
			}
			if n == 0 {
				return store.ErrBadRecovery
			}
		}
		if err := q.CompleteLoginUser(ctx, sqlcdb.CompleteLoginUserParams{Now: nullInt(now), ID: ch.UserID}); err != nil {
			return err
		}
		if err := q.InsertSession(ctx, sqlcdb.InsertSessionParams{
			TokenHash: c.Session.TokenHash, UserID: ch.UserID, CsrfToken: c.Session.CSRF,
			Now: unix(now), ExpiresAt: unix(c.Session.ExpiresAt),
		}); err != nil {
			return err
		}
		return writeAuditKind(ctx, q, now, store.Audit{Kind: store.ActorUser, Actor: u.Email.String},
			store.ActionUserLogin, store.TargetUser, u.Email.String, detail)
	})
}

// RecordSecondFactorFailure implements store.TOTPStore.
func (s *Store) RecordSecondFactorFailure(ctx context.Context, userID int64, limit int, now time.Time, a store.Audit, detail map[string]string) (int, error) {
	var count int64
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		email, err := userEmail(ctx, q, userID)
		if err != nil {
			return err
		}
		if count, err = q.AddTOTPFailure(ctx, userID); err != nil {
			return err
		}
		if err := writeAuditKind(ctx, q, now, a, store.ActionUserLoginFailed, store.TargetUser, email, detail); err != nil {
			return err
		}
		if int(count) == limit {
			return writeAuditKind(ctx, q, now, a, store.ActionTOTPLocked, store.TargetUser, email,
				map[string]string{"failures": strconv.Itoa(limit)})
		}
		return nil
	})
	return int(count), err
}

// SetPendingTOTP implements store.TOTPStore.
func (s *Store) SetPendingTOTP(ctx context.Context, sessionID int64, sealed []byte, now time.Time) error {
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		n, err := q.SetPendingTOTP(ctx, sqlcdb.SetPendingTOTPParams{Sealed: sealed, Now: nullInt(now), ID: sessionID})
		if err != nil {
			return err
		}
		if n == 0 {
			return store.ErrNotFound
		}
		return nil
	})
}

// PendingTOTP implements store.TOTPStore.
func (s *Store) PendingTOTP(ctx context.Context, sessionID int64) ([]byte, time.Time, error) {
	r, err := sqlcdb.New(s.r).PendingTOTP(ctx, sessionID)
	if err != nil {
		return nil, time.Time{}, notFound(err)
	}
	if r.TotpPending == nil || !r.TotpPendingAt.Valid {
		return nil, time.Time{}, store.ErrNotFound
	}
	return r.TotpPending, time.Unix(r.TotpPendingAt.Int64, 0).UTC(), nil
}

// dropUserSessions deletes the user's sessions, all but keep when it is set.
func dropUserSessions(ctx context.Context, q *sqlcdb.Queries, userID int64, keep []byte) error {
	if len(keep) > 0 {
		return q.DeleteUserSessionsExcept(ctx, sqlcdb.DeleteUserSessionsExceptParams{UserID: userID, KeepHash: keep})
	}
	return q.DeleteUserSessions(ctx, userID)
}

func replaceCodes(ctx context.Context, q *sqlcdb.Queries, userID int64, hashes [][]byte, now time.Time) error {
	if err := q.DeleteRecoveryCodes(ctx, userID); err != nil {
		return err
	}
	for _, h := range hashes {
		if err := q.InsertRecoveryCode(ctx, sqlcdb.InsertRecoveryCodeParams{UserID: userID, CodeHash: h, Now: unix(now)}); err != nil {
			return err
		}
	}
	return nil
}

// EnableTOTP implements store.TOTPStore.
func (s *Store) EnableTOTP(ctx context.Context, e store.EnableTOTP, now time.Time, a store.Audit) error {
	if len(e.Sealed) == 0 {
		return errors.New("enable totp: no sealed secret")
	}
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		prev, err := q.UserTOTP(ctx, e.UserID)
		if err != nil {
			return notFound(err)
		}
		n, err := q.EnableUserTOTP(ctx, sqlcdb.EnableUserTOTPParams{
			Secret: e.Sealed, Now: nullInt(now), Step: sql.NullInt64{Int64: e.Step, Valid: true},
			ID: e.UserID, ExpectedVersion: e.ExpectedVersion,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return store.ErrCredentialChanged
		}
		if err := replaceCodes(ctx, q, e.UserID, e.RecoveryHashes, now); err != nil {
			return err
		}
		if err := q.ClearPendingTOTP(ctx, e.SessionID); err != nil {
			return err
		}
		// A new authenticator ends every other session and every login in flight:
		// whoever held those did so under the old second-factor state.
		if err := dropUserSessions(ctx, q, e.UserID, e.KeepSession); err != nil {
			return err
		}
		if err := q.DeleteUserChallenges(ctx, e.UserID); err != nil {
			return err
		}
		action := store.ActionTOTPEnable
		if prev.TotpEnabledAt.Valid {
			action = store.ActionTOTPReplace
		}
		return writeAuditKind(ctx, q, now, a, action, store.TargetUser, prev.Email.String, nil)
	})
}

// DisableTOTP implements store.TOTPStore.
func (s *Store) DisableTOTP(ctx context.Context, userID int64, keep []byte, action string, now time.Time, a store.Audit) error {
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		email, err := userEmail(ctx, q, userID)
		if err != nil {
			return err
		}
		if _, err := q.DisableUserTOTP(ctx, sqlcdb.DisableUserTOTPParams{Now: unix(now), ID: userID}); err != nil {
			return err
		}
		if err := q.DeleteRecoveryCodes(ctx, userID); err != nil {
			return err
		}
		if err := q.ClearUserPendingTOTP(ctx, userID); err != nil {
			return err
		}
		if err := dropUserSessions(ctx, q, userID, keep); err != nil {
			return err
		}
		if err := q.DeleteUserChallenges(ctx, userID); err != nil {
			return err
		}
		return writeAuditKind(ctx, q, now, a, action, store.TargetUser, email, nil)
	})
}

// ReplaceRecoveryCodes implements store.TOTPStore.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID int64, hashes [][]byte, now time.Time, a store.Audit) error {
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		u, err := q.UserTOTP(ctx, userID)
		if err != nil {
			return notFound(err)
		}
		if !u.TotpEnabledAt.Valid {
			return store.ErrCredentialChanged // TOTP was turned off meanwhile: there is nothing to recover
		}
		if err := replaceCodes(ctx, q, userID, hashes, now); err != nil {
			return err
		}
		return writeAuditKind(ctx, q, now, a, store.ActionTOTPRecovery, store.TargetUser, u.Email.String, nil)
	})
}

// RecoveryCodesLeft implements store.TOTPStore.
func (s *Store) RecoveryCodesLeft(ctx context.Context, userID int64) (int, error) {
	n, err := sqlcdb.New(s.r).CountRecoveryCodesLeft(ctx, userID)
	return int(n), err
}

// SealedTOTPSecrets implements store.TOTPStore.
func (s *Store) SealedTOTPSecrets(ctx context.Context) ([]store.SealedSecret, error) {
	rows, err := sqlcdb.New(s.r).SealedTOTPSecrets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]store.SealedSecret, 0, len(rows))
	for _, r := range rows {
		out = append(out, store.SealedSecret{UserID: r.ID, Email: r.Email.String, Sealed: r.TotpSecret})
	}
	return out, nil
}

// ResealTOTPSecrets implements store.TOTPStore.
func (s *Store) ResealTOTPSecrets(ctx context.Context, rs []store.Reseal, now time.Time, a store.Audit) (int, []int64, error) {
	res, err := s.ResealSecrets(ctx, rs, nil, now, a)
	return res.TOTP, res.TOTPConflicts, err
}

// DeleteExpiredChallenges implements store.TOTPStore.
func (s *Store) DeleteExpiredChallenges(ctx context.Context, now time.Time) (int64, error) {
	var n int64
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		n, err = q.DeleteExpiredChallenges(ctx, unix(now))
		return err
	})
	return n, err
}
