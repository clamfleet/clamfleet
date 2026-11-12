-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Web console sessions (Milestone 3). Only the SHA-256 of the cookie token is stored.

-- name: CreateSession :exec
INSERT INTO user_sessions (token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at)
VALUES (sqlc.arg(token_hash), sqlc.arg(user_id), sqlc.arg(csrf_token), sqlc.arg(now), sqlc.arg(now), sqlc.arg(expires_at));

-- name: SessionPrincipalByTokenHash :one
-- One join, so a disabled user, a changed role or a deleted user takes effect
-- on the very next request. The expiry checks live in the WHERE clause, not in
-- Go, so an expired row can never be returned by mistake.
SELECT s.id, s.user_id, s.csrf_token, s.last_seen_at, u.email, u.display_name, u.role,
       u.password_must_change
FROM user_sessions s JOIN users u ON u.id = s.user_id
WHERE s.token_hash = sqlc.arg(token_hash)
  AND s.expires_at > sqlc.arg(now)
  AND s.last_seen_at > sqlc.arg(idle_cutoff)
  AND u.disabled_at IS NULL
  -- Rule: a session born before the user's last password change is dead. A login
  -- stamps its session with the time it STARTED verifying; if a reset commits
  -- while the hash runs, the session it then creates is older than the change.
  AND s.created_at >= COALESCE(u.password_changed_at, 0);

-- name: TouchSession :exec
UPDATE user_sessions SET last_seen_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND last_seen_at < sqlc.arg(touch_before);

-- name: RenewSessionCreated :exec
-- The session that survives a self-service password change is re-dated to the
-- change, so the rule above does not kill it.
UPDATE user_sessions SET created_at = sqlc.arg(now) WHERE token_hash = sqlc.arg(token_hash) AND user_id = sqlc.arg(user_id);

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
