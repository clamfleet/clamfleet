// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// external.go: store.ExternalStore on SQLite: users of LDAP and OIDC sign-in, and the one-time
// OIDC login states (docs/plans/milestone-6.md 4.15).
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite/sqlcdb"
)

var _ store.ExternalStore = (*Store)(nil)

// ExternalLogin implements store.ExternalStore.
func (s *Store) ExternalLogin(ctx context.Context, id store.ExternalIdentity, ss store.Session, now time.Time, a store.Audit, detail map[string]string) (store.User, error) {
	if id.Source != store.AuthLDAP && id.Source != store.AuthOIDC {
		return store.User{}, errors.New("external login: unknown source")
	}
	if id.ExternalID == "" || !store.ValidRole(id.Role) {
		return store.User{}, errors.New("external login: an identity needs an external id and a role")
	}
	email := id.Email
	if email != "" {
		var err error
		if email, err = store.NormalizeEmail(email); err != nil {
			return store.User{}, err
		}
	}
	var uid int64
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		existing, err := q.UserByExternalID(ctx, sqlcdb.UserByExternalIDParams{AuthSource: id.Source, ExternalID: nullStr(id.ExternalID)})
		created := errors.Is(err, sql.ErrNoRows)
		if err != nil && !created {
			return err
		}
		if !created && existing.DisabledAt.Valid {
			return store.ErrUserDisabled
		}
		// Rule: an email held by another user refuses the sign-in (decision 19). Checked for a
		// new user and for an existing one whose email changed, before anything is written.
		if email != "" {
			other, err := q.UserByEmail(ctx, nullStr(email))
			switch {
			case err == nil && (created || other.ID != existing.ID):
				return store.ErrEmailInUse
			case err != nil && !errors.Is(err, sql.ErrNoRows):
				return err
			}
		}
		target := email
		if target == "" {
			target = id.Source + ":" + id.ExternalName
		}
		if created {
			uid, err = q.CreateExternalUser(ctx, sqlcdb.CreateExternalUserParams{
				Email: sql.NullString{String: email, Valid: email != ""}, DisplayName: sql.NullString{String: id.DisplayName, Valid: id.DisplayName != ""},
				Role: id.Role, AuthSource: id.Source, ExternalID: nullStr(id.ExternalID), ExternalName: sql.NullString{String: id.ExternalName, Valid: id.ExternalName != ""}, Now: unix(now),
			})
			if err != nil {
				return err
			}
			if err := writeAuditKind(ctx, q, now, a, store.ActionUserAdd, store.TargetUser, target, map[string]string{"role": id.Role, "source": id.Source}); err != nil {
				return err
			}
		} else {
			uid = existing.ID
			if _, err := q.UpdateExternalUser(ctx, sqlcdb.UpdateExternalUserParams{
				Email: sql.NullString{String: email, Valid: email != ""}, DisplayName: sql.NullString{String: id.DisplayName, Valid: id.DisplayName != ""},
				ExternalName: sql.NullString{String: id.ExternalName, Valid: id.ExternalName != ""}, Role: id.Role, Now: unix(now), ID: uid,
			}); err != nil {
				return err
			}
			if existing.Role != id.Role {
				if err := writeAuditKind(ctx, q, now, a, store.ActionUserRoleMapped, store.TargetUser, target,
					map[string]string{"from": existing.Role, "to": id.Role}); err != nil {
					return err
				}
			}
		}
		n, err := q.CreateExternalSession(ctx, sqlcdb.CreateExternalSessionParams{
			TokenHash: ss.TokenHash, CsrfToken: ss.CSRF, Now: unix(ss.CreatedAt), ExpiresAt: unix(ss.ExpiresAt), UserID: uid,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return store.ErrUserDisabled
		}
		if err := q.SetUserLastLogin(ctx, sqlcdb.SetUserLastLoginParams{Now: nullInt(now), ID: uid}); err != nil {
			return err
		}
		return writeAuditKind(ctx, q, now, a, store.ActionUserLogin, store.TargetUser, target, detail)
	})
	if err != nil {
		return store.User{}, err
	}
	return s.userByID(ctx, uid)
}

// CreateOIDCState implements store.ExternalStore.
func (s *Store) CreateOIDCState(ctx context.Context, st store.OIDCState) error {
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		// Rule: starting a sign-in needs no session, so an anonymous caller must not be able to grow
		// this table without bound. Expired rows go first, then the live ones are counted.
		if _, err := q.DeleteExpiredOIDCStates(ctx, unix(st.CreatedAt)); err != nil {
			return err
		}
		if n, err := q.CountOIDCStates(ctx); err != nil {
			return err
		} else if n >= store.MaxOIDCStates {
			return store.ErrTooManyOIDCStates
		}
		return q.CreateOIDCState(ctx, sqlcdb.CreateOIDCStateParams{
			TokenHash: st.TokenHash, State: st.State, Nonce: st.Nonce, CodeVerifier: st.CodeVerifier, NextPath: st.NextPath,
			CreatedAt: unix(st.CreatedAt), ExpiresAt: unix(st.ExpiresAt),
		})
	})
}

// TakeOIDCState implements store.ExternalStore.
func (s *Store) TakeOIDCState(ctx context.Context, tokenHash []byte, now time.Time) (store.OIDCState, error) {
	var out store.OIDCState
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.TakeOIDCState(ctx, sqlcdb.TakeOIDCStateParams{TokenHash: tokenHash, Now: unix(now)})
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		out = store.OIDCState{
			TokenHash: tokenHash, State: r.State, Nonce: r.Nonce, CodeVerifier: r.CodeVerifier, NextPath: r.NextPath,
			CreatedAt: time.Unix(r.CreatedAt, 0).UTC(), ExpiresAt: time.Unix(r.ExpiresAt, 0).UTC(),
		}
		return nil
	})
	return out, err
}

// DeleteExpiredOIDCStates implements store.ExternalStore.
func (s *Store) DeleteExpiredOIDCStates(ctx context.Context, now time.Time) (int64, error) {
	var n int64
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		n, err = q.DeleteExpiredOIDCStates(ctx, unix(now))
		return err
	})
	return n, err
}
