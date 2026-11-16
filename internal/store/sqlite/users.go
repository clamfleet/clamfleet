// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// users.go: store.UserStore and store.SessionStore on SQLite.
//
// Every change that affects who may sign in (password, role, disable) deletes
// the user's sessions in the same transaction as the change and its audit
// row, so there is no window in which the old privilege still works. Password
// and disable/enable changes also bump users.auth_version, which is what
// refuses a session to a login that was verifying while they happened.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite/sqlcdb"
)

var (
	_ store.UserStore    = (*Store)(nil)
	_ store.SessionStore = (*Store)(nil)
)

// touchEvery throttles last_seen_at writes: a session is updated at most this
// often, so polling tabs do not turn into one write per request.
const touchEvery = time.Minute

type userRow struct {
	ID                 int64
	Email              sql.NullString
	DisplayName        sql.NullString
	Role               string
	AuthSource         string
	PasswordHash       sql.NullString
	PasswordMustChange int64
	PasswordChangedAt  sql.NullInt64
	DisabledAt         sql.NullInt64
	CreatedAt          int64
	LastLoginAt        sql.NullInt64
	AuthVersion        int64
	TotpEnabledAt      sql.NullInt64
	TotpFailures       int64
	ExternalName       sql.NullString
}

func toUser(r userRow) store.User {
	return store.User{
		ID: r.ID, Email: r.Email.String, DisplayName: r.DisplayName.String, Role: r.Role,
		AuthSource: r.AuthSource, Disabled: r.DisabledAt.Valid, MustChange: r.PasswordMustChange != 0,
		CreatedAt: time.Unix(r.CreatedAt, 0).UTC(), LastLoginAt: nullTime(r.LastLoginAt),
		PasswordHash: r.PasswordHash.String, AuthVersion: r.AuthVersion,
		TOTPEnabled: r.TotpEnabledAt.Valid, TOTPFailures: int(r.TotpFailures), ExternalName: r.ExternalName.String,
	}
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// CreateUser implements store.UserStore.
func (s *Store) CreateUser(ctx context.Context, u store.NewUser, now time.Time, a store.Audit) (store.User, error) {
	email, err := store.NormalizeEmail(u.Email)
	if err != nil {
		return store.User{}, err
	}
	if !store.ValidRole(u.Role) {
		return store.User{}, errors.New("invalid role: use viewer or admin")
	}
	var id int64
	err = s.inTx(ctx, func(q *sqlcdb.Queries) error {
		// Checked inside the immediate transaction (as CreateHost does): no race
		// with another writer, and a typed error without parsing driver text.
		if _, err := q.UserByEmail(ctx, nullStr(email)); err == nil {
			return store.ErrUserExists
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		id, err = q.CreateUser(ctx, sqlcdb.CreateUserParams{
			Email: nullStr(email), DisplayName: sql.NullString{String: u.DisplayName, Valid: u.DisplayName != ""},
			Role: u.Role, PasswordHash: nullStr(u.PasswordHash), MustChange: boolInt(u.MustChange), Now: nullInt(now),
		})
		if err != nil {
			return err
		}
		return writeAuditKind(ctx, q, now, a, store.ActionUserAdd, store.TargetUser, email, map[string]string{"role": u.Role})
	})
	if err != nil {
		return store.User{}, err
	}
	return s.userByID(ctx, id)
}

func (s *Store) userByID(ctx context.Context, id int64) (store.User, error) {
	r, err := sqlcdb.New(s.r).UserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return store.User{}, store.ErrNotFound
	}
	if err != nil {
		return store.User{}, err
	}
	return toUser(userRow(r)), nil
}

// UserByEmail implements store.UserStore.
func (s *Store) UserByEmail(ctx context.Context, email string) (store.User, error) {
	n, err := store.NormalizeEmail(email)
	if err != nil {
		return store.User{}, store.ErrNotFound // an impossible address matches no user
	}
	r, err := sqlcdb.New(s.r).UserByEmail(ctx, nullStr(n))
	if errors.Is(err, sql.ErrNoRows) {
		return store.User{}, store.ErrNotFound
	}
	if err != nil {
		return store.User{}, err
	}
	return toUser(userRow(r)), nil
}

// ListUsers implements store.UserStore.
func (s *Store) ListUsers(ctx context.Context) ([]store.User, error) {
	rows, err := sqlcdb.New(s.r).ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]store.User, 0, len(rows))
	for _, r := range rows {
		out = append(out, toUser(userRow(r)))
	}
	return out, nil
}

// UsersByExternalName implements store.UserStore.
func (s *Store) UsersByExternalName(ctx context.Context, source, name string) ([]store.User, error) {
	rows, err := sqlcdb.New(s.r).UsersByExternalName(ctx, sqlcdb.UsersByExternalNameParams{AuthSource: source, ExternalName: nullStr(name)})
	if err != nil {
		return nil, err
	}
	out := make([]store.User, 0, len(rows))
	for _, r := range rows {
		out = append(out, toUser(userRow(r)))
	}
	return out, nil
}

// CountUsers implements store.UserStore.
func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	return sqlcdb.New(s.r).CountUsers(ctx)
}

// userEmail reads the name of the user inside a write transaction, for the audit target: the
// email, or "<source>:<external name>" for an external user without one (an audit row with an empty
// target would say nothing about whom it concerns).
func userEmail(ctx context.Context, q *sqlcdb.Queries, id int64) (string, error) {
	u, err := q.UserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", store.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if u.Email.String == "" {
		return u.AuthSource + ":" + u.ExternalName.String, nil
	}
	return u.Email.String, nil
}

// SetPassword implements store.UserStore.
func (s *Store) SetPassword(ctx context.Context, id int64, c store.PasswordChange, now time.Time, a store.Audit) error {
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		email, err := userEmail(ctx, q, id)
		if err != nil {
			return err
		}
		if c.ExpectedHash != "" {
			n, err := q.SetUserPasswordIf(ctx, sqlcdb.SetUserPasswordIfParams{
				PasswordHash: nullStr(c.Hash), MustChange: boolInt(c.MustChange), Now: nullInt(now), ID: id,
				ExpectedHash: nullStr(c.ExpectedHash),
			})
			if err != nil {
				return err
			}
			if n == 0 {
				return store.ErrCredentialChanged // rolls the transaction back: nothing is written
			}
		} else if _, err := q.SetUserPassword(ctx, sqlcdb.SetUserPasswordParams{
			PasswordHash: nullStr(c.Hash), MustChange: boolInt(c.MustChange), Now: nullInt(now), ID: id,
		}); err != nil {
			return err
		}
		if len(c.KeepSession) > 0 {
			err = q.DeleteUserSessionsExcept(ctx, sqlcdb.DeleteUserSessionsExceptParams{UserID: id, KeepHash: c.KeepSession})
		} else {
			err = q.DeleteUserSessions(ctx, id)
		}
		if err != nil {
			return err
		}
		action := store.ActionUserPasswordReset
		if c.Self {
			action = store.ActionUserPasswordSet
		}
		return writeAuditKind(ctx, q, now, a, action, store.TargetUser, email, nil)
	})
}

// RehashPassword implements store.UserStore.
func (s *Store) RehashPassword(ctx context.Context, id int64, oldHash, newHash string, now time.Time) (bool, error) {
	var n int64
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		n, err = q.RehashUserPassword(ctx, sqlcdb.RehashUserPasswordParams{
			PasswordHash: nullStr(newHash), Now: unix(now), ID: id, ExpectedHash: nullStr(oldHash),
		})
		return err // 0 rows: the password changed meanwhile, which is not an error
	})
	return n == 1, err
}

// SetRole implements store.UserStore.
func (s *Store) SetRole(ctx context.Context, id int64, role string, now time.Time, a store.Audit) error {
	if !store.ValidRole(role) {
		return errors.New("invalid role: use viewer or admin")
	}
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		email, err := userEmail(ctx, q, id)
		if err != nil {
			return err
		}
		if _, err := q.SetUserRole(ctx, sqlcdb.SetUserRoleParams{Role: role, Now: unix(now), ID: id}); err != nil {
			return err
		}
		if err := q.DeleteUserSessions(ctx, id); err != nil {
			return err
		}
		return writeAuditKind(ctx, q, now, a, store.ActionUserRole, store.TargetUser, email, map[string]string{"role": role})
	})
}

// SetDisabled implements store.UserStore.
func (s *Store) SetDisabled(ctx context.Context, id int64, disabled bool, now time.Time, a store.Audit) error {
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		email, err := userEmail(ctx, q, id)
		if err != nil {
			return err
		}
		var at sql.NullInt64
		action := store.ActionUserEnable
		if disabled {
			at, action = nullInt(now), store.ActionUserDisable
		}
		if _, err := q.SetUserDisabled(ctx, sqlcdb.SetUserDisabledParams{DisabledAt: at, Now: unix(now), ID: id}); err != nil {
			return err
		}
		// Both ways: see store.UserStore (enable closes the login-vs-disable race).
		if err := q.DeleteUserSessions(ctx, id); err != nil {
			return err
		}
		return writeAuditKind(ctx, q, now, a, action, store.TargetUser, email, nil)
	})
}

// RecordLogin implements store.UserStore.
func (s *Store) RecordLogin(ctx context.Context, id int64, now time.Time, a store.Audit, detail map[string]string) error {
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		email, err := userEmail(ctx, q, id)
		if err != nil {
			return err
		}
		if err := q.SetUserLastLogin(ctx, sqlcdb.SetUserLastLoginParams{Now: nullInt(now), ID: id}); err != nil {
			return err
		}
		return writeAuditKind(ctx, q, now, a, store.ActionUserLogin, store.TargetUser, email, detail)
	})
}

// RecordAudit implements store.UserStore.
func (s *Store) RecordAudit(ctx context.Context, now time.Time, a store.Audit, action, targetKind, target string, detail map[string]string) error {
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		return writeAuditKind(ctx, q, now, a, action, targetKind, target, detail)
	})
}

// CreateSession implements store.SessionStore.
func (s *Store) CreateSession(ctx context.Context, ss store.Session) error {
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		n, err := q.CreateSession(ctx, sqlcdb.CreateSessionParams{
			TokenHash: ss.TokenHash, CsrfToken: ss.CSRF, Now: unix(ss.CreatedAt), ExpiresAt: unix(ss.ExpiresAt),
			UserID: ss.UserID, ExpectedHash: nullStr(ss.PasswordHash), ExpectedVersion: ss.AuthVersion,
		})
		if err == nil && n == 0 {
			err = store.ErrCredentialChanged
		}
		return err
	})
}

// SessionByTokenHash implements store.SessionStore.
func (s *Store) SessionByTokenHash(ctx context.Context, hash []byte, now time.Time, idle time.Duration) (store.SessionPrincipal, error) {
	if len(hash) == 0 {
		return store.SessionPrincipal{}, store.ErrNotFound
	}
	r, err := sqlcdb.New(s.r).SessionPrincipalByTokenHash(ctx, sqlcdb.SessionPrincipalByTokenHashParams{
		TokenHash: hash, Now: unix(now), IdleCutoff: unix(now.Add(-idle)),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return store.SessionPrincipal{}, store.ErrNotFound
	}
	if err != nil {
		return store.SessionPrincipal{}, err
	}
	return store.SessionPrincipal{
		SessionID: r.ID, UserID: r.UserID, Email: r.Email.String, Name: r.DisplayName.String, Role: r.Role,
		CSRF: r.CsrfToken, MustChange: r.PasswordMustChange != 0, LastSeen: time.Unix(r.LastSeenAt, 0).UTC(),
		AuthSource: r.AuthSource, TOTPEnabled: r.TotpEnabledAt.Valid, ExternalName: r.ExternalName.String,
	}, nil
}

// TouchSession implements store.SessionStore.
func (s *Store) TouchSession(ctx context.Context, id int64, now time.Time) error {
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		return q.TouchSession(ctx, sqlcdb.TouchSessionParams{Now: unix(now), ID: id, TouchBefore: unix(now.Add(-touchEvery))})
	})
}

// DeleteSession implements store.SessionStore.
func (s *Store) DeleteSession(ctx context.Context, hash []byte) error {
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		return q.DeleteSessionByHash(ctx, hash)
	})
}

// DeleteExpiredSessions implements store.SessionStore.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time, idle time.Duration) (int64, error) {
	var n int64
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		n, err = q.DeleteExpiredSessions(ctx, sqlcdb.DeleteExpiredSessionsParams{Now: unix(now), IdleCutoff: unix(now.Add(-idle))})
		return err
	})
	return n, err
}
