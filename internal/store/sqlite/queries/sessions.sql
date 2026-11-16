-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Web console sessions (Milestone 3). Only the SHA-256 of the cookie token is stored.

-- name: CreateSession :execrows
-- Conditional on the credential that was verified: the row is inserted only if
-- the user still has that password hash and is not disabled. A reset, a
-- password change or a disable that committed while the login was hashing
-- leaves 0 rows, and the login fails instead of producing a session behind it.
-- auth_version closes the one case the hash cannot see: a disable followed by an
-- enable leaves the hash unchanged but bumps the version twice.
-- This does not depend on any clock (timestamps are whole seconds).
INSERT INTO user_sessions (token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at)
SELECT sqlc.arg(token_hash), u.id, sqlc.arg(csrf_token), sqlc.arg(now), sqlc.arg(now), sqlc.arg(expires_at)
FROM users u
WHERE u.id = sqlc.arg(user_id) AND u.password_hash = sqlc.arg(expected_hash) AND u.disabled_at IS NULL
  AND u.auth_version = sqlc.arg(expected_version);

-- name: SessionPrincipalByTokenHash :one
-- One join, so a disabled user, a changed role or a deleted user takes effect
-- on the very next request. The expiry checks live in the WHERE clause, not in
-- Go, so an expired row can never be returned by mistake.
SELECT s.id, s.user_id, s.csrf_token, s.last_seen_at, u.email, u.display_name, u.role,
       u.password_must_change, u.auth_source, u.totp_enabled_at, u.external_name
FROM user_sessions s JOIN users u ON u.id = s.user_id
WHERE s.token_hash = sqlc.arg(token_hash)
  AND s.expires_at > sqlc.arg(now)
  AND s.last_seen_at > sqlc.arg(idle_cutoff)
  AND u.disabled_at IS NULL;

-- name: TouchSession :exec
UPDATE user_sessions SET last_seen_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND last_seen_at < sqlc.arg(touch_before);

-- name: DeleteSessionByHash :exec
DELETE FROM user_sessions WHERE token_hash = sqlc.arg(token_hash);

-- name: DeleteUserSessions :exec
DELETE FROM user_sessions WHERE user_id = sqlc.arg(user_id);

-- name: DeleteUserSessionsExcept :exec
DELETE FROM user_sessions WHERE user_id = sqlc.arg(user_id) AND token_hash <> sqlc.arg(keep_hash);

-- name: DeleteExpiredSessions :execrows
DELETE FROM user_sessions WHERE expires_at <= sqlc.arg(now) OR last_seen_at <= sqlc.arg(idle_cutoff);

-- name: CountSessions :one
SELECT count(*) FROM user_sessions;
