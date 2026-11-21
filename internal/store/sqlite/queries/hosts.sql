-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Portable on purpose (spec 8.1): ON CONFLICT and RETURNING only, no
-- INSERT OR REPLACE, no two-argument MAX(), no COLLATE NOCASE.

-- name: CreateHost :one
INSERT INTO hosts (name, token_hash, token_created_at, created_at)
VALUES (sqlc.arg(name), sqlc.arg(token_hash), sqlc.arg(now), sqlc.arg(now))
RETURNING id;

-- name: HostRefByTokenHash :one
SELECT id, name FROM hosts WHERE token_hash = sqlc.arg(token_hash);

-- name: HostIDByName :one
SELECT id FROM hosts WHERE name = sqlc.arg(name);

-- name: SetHostToken :execrows
UPDATE hosts SET token_hash = sqlc.arg(token_hash), token_created_at = sqlc.arg(now)
WHERE id = sqlc.arg(id);

-- name: HostForReport :one
SELECT reported_name FROM hosts WHERE id = sqlc.arg(id);

-- name: TouchHostSeen :exec
UPDATE hosts
SET last_seen = sqlc.arg(now), first_seen = COALESCE(first_seen, CAST(sqlc.arg(now) AS INTEGER))
WHERE id = sqlc.arg(id);

-- name: SetHostLastReport :execrows
UPDATE hosts
SET last_report = sqlc.arg(payload), last_report_order = sqlc.arg(ord),
    reported_name = sqlc.arg(reported_name), agent_version = sqlc.arg(agent_version),
    daily_version = sqlc.arg(daily_version), daily_built = sqlc.arg(daily_built),
    clamd_version = sqlc.arg(clamd_version)
WHERE id = sqlc.arg(id) AND (last_report_order IS NULL OR last_report_order <= sqlc.arg(ord));

-- name: DeleteHostTags :exec
DELETE FROM host_tags WHERE host_id = sqlc.arg(host_id);

-- name: InsertHostTag :exec
INSERT INTO host_tags (host_id, tag) VALUES (sqlc.arg(host_id), sqlc.arg(tag))
ON CONFLICT (host_id, tag) DO NOTHING;

-- name: ListHosts :many
SELECT id, name, token_hash IS NOT NULL AS has_token, created_at, first_seen, last_seen,
       reported_name, agent_version, state, state_reason, state_since
FROM hosts ORDER BY name;

-- name: ListAllHostTags :many
SELECT host_id, tag FROM host_tags ORDER BY host_id, tag;

-- name: HostByName :one
SELECT id, name, token_hash IS NOT NULL AS has_token, token_created_at, created_at, first_seen,
       last_seen, reported_name, agent_version, last_report, state, state_reason, state_since
FROM hosts WHERE name = sqlc.arg(name);

-- name: ListHostTags :many
SELECT tag FROM host_tags WHERE host_id = sqlc.arg(host_id) ORDER BY tag;

-- name: CountHostReports :one
SELECT count(*) FROM reports WHERE host_id = sqlc.arg(host_id);

-- name: CountHostEvents :one
SELECT count(*) FROM events WHERE host_id = sqlc.arg(host_id);

-- name: DeleteHost :execrows
DELETE FROM hosts WHERE id = sqlc.arg(id);

-- name: RevokeHostToken :execrows
-- A literal NULL, not a nil []byte parameter: how a driver binds a nil slice
-- (NULL or an empty blob) is not something a revocation may depend on.
UPDATE hosts SET token_hash = NULL, token_created_at = sqlc.arg(now) WHERE id = sqlc.arg(id);
