-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- External sign-in (Milestone 6b): users of the ldap and oidc sources, and the one-time
-- OIDC login states. Portable SQL only (DELETE ... RETURNING exists in PostgreSQL).

-- name: UserByExternalID :one
SELECT id, email, display_name, role, auth_source, password_hash, password_must_change,
       password_changed_at, disabled_at, created_at, last_login_at, auth_version,
       totp_enabled_at, totp_failures, external_name
FROM users WHERE auth_source = sqlc.arg(auth_source) AND external_id = sqlc.arg(external_id);

-- name: CreateExternalUser :one
-- No password and no TOTP: the provider owns both.
INSERT INTO users (email, display_name, role, auth_source, external_id, external_name,
                   password_must_change, created_at, updated_at)
VALUES (sqlc.arg(email), sqlc.arg(display_name), sqlc.arg(role), sqlc.arg(auth_source), sqlc.arg(external_id),
        sqlc.arg(external_name), 0, sqlc.arg(now), sqlc.arg(now))
RETURNING id;

-- name: UpdateExternalUser :execrows
UPDATE users SET email = sqlc.arg(email), display_name = sqlc.arg(display_name),
       external_name = sqlc.arg(external_name), role = sqlc.arg(role), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id);

-- name: CreateExternalSession :execrows
-- Conditional on the user not being disabled and on the auth_version read in the same
-- transaction; an external user has no password hash to compare.
INSERT INTO user_sessions (token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at)
SELECT sqlc.arg(token_hash), u.id, sqlc.arg(csrf_token), sqlc.arg(now), sqlc.arg(now), sqlc.arg(expires_at)
FROM users u
WHERE u.id = sqlc.arg(user_id) AND u.disabled_at IS NULL;

-- name: CreateOIDCState :exec
INSERT INTO oidc_login_states (token_hash, state, nonce, code_verifier, next_path, created_at, expires_at)
VALUES (sqlc.arg(token_hash), sqlc.arg(state), sqlc.arg(nonce), sqlc.arg(code_verifier), sqlc.arg(next_path),
        sqlc.arg(created_at), sqlc.arg(expires_at));

-- name: TakeOIDCState :one
-- One-time use: the row is gone whatever the caller decides next. Expiry is in the WHERE clause
-- (an expired row is deleted by the cleanup, never returned).
DELETE FROM oidc_login_states WHERE token_hash = sqlc.arg(token_hash) AND expires_at > sqlc.arg(now)
RETURNING state, nonce, code_verifier, next_path, created_at, expires_at;

-- name: DeleteExpiredOIDCStates :execrows
DELETE FROM oidc_login_states WHERE expires_at <= sqlc.arg(now);

-- name: CountOIDCStates :one
SELECT count(*) FROM oidc_login_states;
