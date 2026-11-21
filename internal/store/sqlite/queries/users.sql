-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Local users of the web console (Milestone 3). Portable SQL only.

-- name: CreateUser :one
INSERT INTO users (email, display_name, role, auth_source, password_hash, password_must_change,
                   password_changed_at, created_at, updated_at)
VALUES (sqlc.arg(email), sqlc.arg(display_name), sqlc.arg(role), 'local', sqlc.arg(password_hash),
        sqlc.arg(must_change), sqlc.arg(now), sqlc.arg(now), sqlc.arg(now))
RETURNING id;

-- name: UserByEmail :one
SELECT id, email, display_name, role, auth_source, password_hash, password_must_change,
       password_changed_at, disabled_at, created_at, last_login_at, auth_version,
       totp_enabled_at, totp_failures, external_name, external_id
FROM users WHERE email = sqlc.arg(email);

-- name: UserByID :one
SELECT id, email, display_name, role, auth_source, password_hash, password_must_change,
       password_changed_at, disabled_at, created_at, last_login_at, auth_version,
       totp_enabled_at, totp_failures, external_name, external_id
FROM users WHERE id = sqlc.arg(id);

-- name: ListUsers :many
SELECT id, email, display_name, role, auth_source, password_hash, password_must_change,
       password_changed_at, disabled_at, created_at, last_login_at, auth_version,
       totp_enabled_at, totp_failures, external_name, external_id
FROM users ORDER BY email;

-- name: SetUserPassword :execrows
-- The unconditional (admin or CLI) reset also lifts the second-factor lock: a
-- lock means someone had the password, and the reset is the response to that.
UPDATE users SET password_hash = sqlc.arg(password_hash), password_must_change = sqlc.arg(must_change),
       password_changed_at = sqlc.arg(now), updated_at = sqlc.arg(now),
       auth_version = auth_version + 1, totp_failures = 0
WHERE id = sqlc.arg(id);

-- name: SetUserPasswordIf :execrows
-- Compare-and-swap for a self-service change: only while the hash that was
-- verified as "current password" is still the stored one. 0 rows means a reset
-- or another change committed in between, and must not be overwritten.
UPDATE users SET password_hash = sqlc.arg(password_hash), password_must_change = sqlc.arg(must_change),
       password_changed_at = sqlc.arg(now), updated_at = sqlc.arg(now),
       auth_version = auth_version + 1
WHERE id = sqlc.arg(id) AND password_hash = sqlc.arg(expected_hash);

-- name: RehashUserPassword :execrows
-- Parameter upgrade after a successful login: same password, so it is not a
-- password change (password_changed_at, must_change and sessions stay).
-- Compare-and-swap on the hash that was verified: if a reset or a password
-- change committed while the login was hashing, 0 rows match and the newer
-- password is not overwritten by a hash of the old one.
UPDATE users SET password_hash = sqlc.arg(password_hash), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND password_hash = sqlc.arg(expected_hash);

-- name: SetUserRole :execrows
UPDATE users SET role = sqlc.arg(role), updated_at = sqlc.arg(now) WHERE id = sqlc.arg(id);

-- name: SetUserDisabled :execrows
-- Disable AND enable both bump auth_version: a login that read the user before a
-- disable-then-enable has a stale version and gets no session, although the
-- password hash is unchanged (closes the M3 "known limit").
UPDATE users SET disabled_at = sqlc.arg(disabled_at), updated_at = sqlc.arg(now),
       auth_version = auth_version + 1
WHERE id = sqlc.arg(id);

-- name: SetUserLastLogin :exec
UPDATE users SET last_login_at = sqlc.arg(now) WHERE id = sqlc.arg(id);

-- name: CountUsers :one
SELECT count(*) FROM users;
