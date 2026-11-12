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
       password_changed_at, disabled_at, created_at, last_login_at
FROM users WHERE email = sqlc.arg(email);

-- name: UserByID :one
SELECT id, email, display_name, role, auth_source, password_hash, password_must_change,
       password_changed_at, disabled_at, created_at, last_login_at
FROM users WHERE id = sqlc.arg(id);

-- name: ListUsers :many
SELECT id, email, display_name, role, auth_source, password_hash, password_must_change,
       password_changed_at, disabled_at, created_at, last_login_at
FROM users ORDER BY email;

-- name: SetUserPassword :execrows
UPDATE users SET password_hash = sqlc.arg(password_hash), password_must_change = sqlc.arg(must_change),
       password_changed_at = sqlc.arg(now), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id);

-- name: RehashUserPassword :execrows
-- Parameter upgrade after a successful login: same password, so it is not a
-- password change (password_changed_at, must_change and sessions stay).
UPDATE users SET password_hash = sqlc.arg(password_hash), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id);

-- name: SetUserRole :execrows
UPDATE users SET role = sqlc.arg(role), updated_at = sqlc.arg(now) WHERE id = sqlc.arg(id);

-- name: SetUserDisabled :execrows
UPDATE users SET disabled_at = sqlc.arg(disabled_at), updated_at = sqlc.arg(now) WHERE id = sqlc.arg(id);

-- name: SetUserLastLogin :exec
UPDATE users SET last_login_at = sqlc.arg(now) WHERE id = sqlc.arg(id);

-- name: CountUsers :one
SELECT count(*) FROM users;
