-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Health evaluation (Milestone 3). Portable SQL only. Revoked hosts
-- (token_hash IS NULL) are never evaluated and never count for the fleet.

-- name: FleetNewestDaily :one
-- The yardstick of the daily_behind rule. CAST: sqlc types MAX() as unknown.
SELECT CAST(COALESCE(MAX(daily_version), 0) AS INTEGER) AS newest
FROM hosts WHERE token_hash IS NOT NULL;

-- name: HealthInputs :many
SELECT id, name, created_at, last_seen, last_report, state, state_reason
FROM hosts WHERE token_hash IS NOT NULL ORDER BY id;

-- name: HealthInputByID :one
SELECT id, name, created_at, last_seen, last_report, state, state_reason
FROM hosts WHERE id = sqlc.arg(id) AND token_hash IS NOT NULL;

-- name: SetHostState :exec
UPDATE hosts SET state = sqlc.arg(state), state_reason = sqlc.arg(reason), state_since = sqlc.arg(since)
WHERE id = sqlc.arg(id);

-- name: SetHostStateReason :exec
UPDATE hosts SET state_reason = sqlc.arg(reason) WHERE id = sqlc.arg(id);

-- name: InsertStateChange :exec
-- alert_pending = 1: the alert planner (M4) picks the row up. It is set in this
-- insert, in EvaluateHosts's own transaction, so a transition and its pending
-- alert exist together or not at all.
INSERT INTO state_changes (host_id, ts, from_state, to_state, reason, alert_pending)
VALUES (sqlc.arg(host_id), sqlc.arg(ts), sqlc.arg(from_state), sqlc.arg(to_state), sqlc.arg(reason), 1);

-- name: ListStateChanges :many
SELECT ts, from_state, to_state, reason FROM state_changes
WHERE host_id = sqlc.arg(host_id) ORDER BY ts DESC, id DESC LIMIT sqlc.arg(max_rows);

-- name: ListFleet :many
-- The fleet page: hosts with a token only (a revoked host's state is frozen and
-- it is hidden from the overview; the hosts admin page lists every host).
SELECT id, name, last_seen, state, state_reason, state_since, daily_version, daily_built, clamd_version
FROM hosts WHERE token_hash IS NOT NULL ORDER BY name;
