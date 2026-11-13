-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Alerting (Milestone 4). Portable SQL only (no RETURNING on UPDATE, no
-- SQLite-only functions), so a PostgreSQL implementation can copy it.

-- ---------------------------------------------------------------- targets

-- name: AlertTargetIDByName :one
SELECT id FROM alert_targets WHERE name = sqlc.arg(name);

-- name: InsertAlertTarget :one
INSERT INTO alert_targets (name, type, config, min_severity, tag_filter, send_state_changes, send_detections, enabled, created_at, updated_at)
VALUES (sqlc.arg(name), sqlc.arg(type), sqlc.arg(config), sqlc.arg(min_severity), sqlc.arg(tag_filter),
        sqlc.arg(send_state_changes), sqlc.arg(send_detections), sqlc.arg(enabled), sqlc.arg(now), sqlc.arg(now))
RETURNING id;

-- name: SetAlertTargetSecret :exec
UPDATE alert_targets SET secret = sqlc.arg(secret), updated_at = sqlc.arg(now) WHERE id = sqlc.arg(id);

-- name: AlertTargetByID :one
SELECT id, name, type, config, secret, min_severity, tag_filter, send_state_changes, send_detections, enabled, created_at, updated_at, detection_burst
FROM alert_targets WHERE id = sqlc.arg(id);

-- name: AlertTargetByName :one
SELECT id, name, type, config, secret, min_severity, tag_filter, send_state_changes, send_detections, enabled, created_at, updated_at, detection_burst
FROM alert_targets WHERE name = sqlc.arg(name);

-- name: ListAlertTargets :many
-- The last log row that says something about a delivery or a test (held and
-- skipped rows are decisions, not results).
SELECT t.id, t.name, t.type, t.config, t.secret, t.min_severity, t.tag_filter, t.send_state_changes, t.send_detections,
       t.enabled, t.created_at, t.updated_at,
       CAST(COALESCE((SELECT l.status FROM alert_log l WHERE l.target_id = t.id AND l.status IN ('sent','retrying','failed','test_sent','test_failed')
         ORDER BY l.id DESC LIMIT 1), '') AS TEXT) AS last_status,
       CAST(COALESCE((SELECT l.ts FROM alert_log l WHERE l.target_id = t.id AND l.status IN ('sent','retrying','failed','test_sent','test_failed')
         ORDER BY l.id DESC LIMIT 1), 0) AS INTEGER) AS last_ts,
       CAST(COALESCE((SELECT l.code FROM alert_log l WHERE l.target_id = t.id AND l.status IN ('sent','retrying','failed','test_sent','test_failed')
         ORDER BY l.id DESC LIMIT 1), '') AS TEXT) AS last_code
FROM alert_targets t ORDER BY t.name;

-- name: ListAllAlertTargets :many
SELECT id, name, type, config, secret, min_severity, tag_filter, send_state_changes, send_detections, enabled, created_at, updated_at, detection_burst
FROM alert_targets ORDER BY id;

-- name: UpdateAlertTarget :exec
UPDATE alert_targets SET config = sqlc.arg(config), min_severity = sqlc.arg(min_severity), tag_filter = sqlc.arg(tag_filter),
  send_state_changes = sqlc.arg(send_state_changes), send_detections = sqlc.arg(send_detections), enabled = sqlc.arg(enabled),
  updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id);

-- name: DeleteAlertTarget :execrows
DELETE FROM alert_targets WHERE id = sqlc.arg(id);

-- name: DeleteNotifyStateOfTarget :exec
DELETE FROM alert_notify_state WHERE target_id = sqlc.arg(target_id);

-- ------------------------------------------------- switching off (cancel)

-- name: PendingDeliveriesOfTarget :many
-- Pending deliveries of a target, optionally of one kind ('' = every kind).
SELECT d.id, d.recipient, d.kind, d.host_id, d.state_change_id, d.event_id, d.attempts, h.name AS host_name
FROM alert_deliveries d JOIN hosts h ON h.id = d.host_id
WHERE d.target_id = sqlc.arg(target_id) AND d.status = 'pending'
  AND (CAST(sqlc.arg(kind) AS TEXT) = '' OR d.kind = CAST(sqlc.arg(kind) AS TEXT));

-- name: CancelDelivery :execrows
-- The claim token stays: an attempt in flight keeps its token and its FinishAttempt
-- then finds the status no longer pending (ErrLeaseLost).
UPDATE alert_deliveries SET status = 'cancelled', next_attempt_at = NULL, finished_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND status = 'pending';

-- ------------------------------------------------------------------ planning

-- name: FlaggedStateChanges :many
SELECT id, host_id, ts, from_state, to_state, reason FROM state_changes WHERE alert_pending = 1 ORDER BY id LIMIT sqlc.arg(max_rows);

-- name: FlaggedEvents :many
SELECT id, host_id, ts, received_at, path, signature, source FROM events WHERE alert_pending = 1 ORDER BY id LIMIT sqlc.arg(max_rows);

-- name: ClearStateChangeFlags :exec
-- Every flagged row up to max_id was read (the read is ordered by id), so the
-- range is exactly the set that was planned.
UPDATE state_changes SET alert_pending = 0 WHERE alert_pending = 1 AND id <= sqlc.arg(max_id);

-- name: ClearEventFlags :exec
UPDATE events SET alert_pending = 0 WHERE alert_pending = 1 AND id <= sqlc.arg(max_id);

-- name: HeldNotifyRows :many
SELECT target_id, host_id, last_state, last_at, held_count FROM alert_notify_state WHERE held_count > 0;

-- name: NotifyRowsOfHost :many
SELECT target_id, host_id, last_state, last_at, held_count FROM alert_notify_state WHERE host_id = sqlc.arg(host_id);

-- name: PlanHostByID :one
SELECT h.id, h.name, h.state, h.state_reason,
       CAST(COALESCE((SELECT c.id FROM state_changes c WHERE c.host_id = h.id ORDER BY c.id DESC LIMIT 1), 0) AS INTEGER) AS latest_change_id,
       CAST(COALESCE((SELECT c.ts FROM state_changes c WHERE c.host_id = h.id ORDER BY c.id DESC LIMIT 1), 0) AS INTEGER) AS latest_change_ts
FROM hosts h WHERE h.id = sqlc.arg(id);

-- name: UpsertNotifyState :exec
INSERT INTO alert_notify_state (target_id, host_id, last_state, last_at, held_count)
VALUES (sqlc.arg(target_id), sqlc.arg(host_id), sqlc.arg(last_state), sqlc.arg(last_at), sqlc.arg(held_count))
ON CONFLICT (target_id, host_id) DO UPDATE SET last_state = excluded.last_state, last_at = excluded.last_at, held_count = excluded.held_count;

-- name: InsertDelivery :exec
INSERT INTO alert_deliveries (alert_id, target_id, host_id, recipient, state_change_id, event_id, kind, payload, status, attempts, next_attempt_at, created_at)
VALUES (sqlc.arg(alert_id), sqlc.arg(target_id), sqlc.arg(host_id), sqlc.arg(recipient), sqlc.arg(state_change_id), sqlc.arg(event_id),
        sqlc.arg(kind), sqlc.arg(payload), 'pending', 0, sqlc.arg(now), sqlc.arg(now));

-- name: InsertAlertLog :one
INSERT INTO alert_log (ts, target_id, target_name, delivery_id, recipient, host_name, state_change_id, event_id, attempt, status, code, error, duration_ms)
VALUES (sqlc.arg(ts), sqlc.arg(target_id), sqlc.arg(target_name), sqlc.arg(delivery_id), sqlc.arg(recipient), sqlc.arg(host_name),
        sqlc.arg(state_change_id), sqlc.arg(event_id), sqlc.arg(attempt), sqlc.arg(status), sqlc.arg(code), sqlc.arg(error), sqlc.arg(duration_ms))
RETURNING id;

-- name: HasFlaggedStateChange :one
SELECT EXISTS (SELECT 1 FROM state_changes WHERE alert_pending = 1) AS present;

-- name: HasFlaggedEvent :one
SELECT EXISTS (SELECT 1 FROM events WHERE alert_pending = 1) AS present;

-- name: HasDueHold :one
SELECT EXISTS (SELECT 1 FROM alert_notify_state WHERE held_count > 0 AND (last_at + sqlc.arg(cooldown_secs) <= sqlc.arg(now) OR last_at > sqlc.arg(now))) AS present;

-- name: HasDueDelivery :one
SELECT EXISTS (SELECT 1 FROM alert_deliveries WHERE status = 'pending' AND claim_token IS NULL AND next_attempt_at <= sqlc.arg(now)) AS present;

-- name: HasExpiredLease :one
SELECT EXISTS (SELECT 1 FROM alert_deliveries WHERE status = 'pending' AND claim_token IS NOT NULL AND next_attempt_at <= sqlc.arg(now)) AS present;

-- ---------------------------------------------------------- claim and finish

-- name: DueDeliveries :many
-- Pending, unclaimed and due; the target is enabled and the delivery's kind is
-- still switched on; and no OLDER pending delivery exists for the same
-- (target, host, recipient), so a receiver never gets "OK" before the "CRIT"
-- that is still being retried.
SELECT d.id, d.alert_id, d.target_id, d.host_id, d.recipient, d.state_change_id, d.event_id, d.kind, d.payload, d.attempts, h.name AS host_name
FROM alert_deliveries d
JOIN alert_targets t ON t.id = d.target_id
JOIN hosts h ON h.id = d.host_id
WHERE d.status = 'pending' AND d.claim_token IS NULL AND d.next_attempt_at <= sqlc.arg(now)
  AND t.enabled = 1
  AND ((d.kind = 'state_change' AND t.send_state_changes = 1) OR (d.kind = 'detection' AND t.send_detections = 1))
  AND NOT EXISTS (SELECT 1 FROM alert_deliveries o
                  WHERE o.target_id = d.target_id AND o.host_id = d.host_id AND o.recipient = d.recipient
                    AND o.status = 'pending' AND o.id < d.id)
ORDER BY d.id
LIMIT sqlc.arg(max_rows);

-- name: ClaimDelivery :execrows
UPDATE alert_deliveries SET attempts = attempts + 1, claim_token = sqlc.arg(token), next_attempt_at = sqlc.arg(lease_until)
WHERE id = sqlc.arg(id) AND status = 'pending' AND claim_token IS NULL;

-- name: FinishDelivery :execrows
-- Conditional on the claim token: a late result can never overwrite a newer
-- claim's result or a cancellation.
UPDATE alert_deliveries SET status = sqlc.arg(status), claim_token = NULL, next_attempt_at = sqlc.arg(next_attempt_at), finished_at = sqlc.arg(finished_at)
WHERE id = sqlc.arg(id) AND claim_token = sqlc.arg(token) AND status = 'pending';

-- name: FinishAttemptLog :exec
UPDATE alert_log SET status = sqlc.arg(status), code = sqlc.arg(code), error = sqlc.arg(error), duration_ms = sqlc.arg(duration_ms)
WHERE id = sqlc.arg(id) AND status = 'attempting';

-- name: ExpiredLeases :many
SELECT d.id, d.target_id, d.host_id, d.recipient, d.state_change_id, d.event_id, d.attempts, t.name AS target_name, h.name AS host_name
FROM alert_deliveries d
JOIN alert_targets t ON t.id = d.target_id
JOIN hosts h ON h.id = d.host_id
WHERE d.status = 'pending' AND d.claim_token IS NOT NULL AND (CAST(sqlc.arg(all_claims) AS INTEGER) = 1 OR d.next_attempt_at <= sqlc.arg(now));

-- name: InterruptAttemptLog :exec
UPDATE alert_log SET status = 'interrupted', error = 'the attempt did not finish (lease expired or server stopped)'
WHERE delivery_id = sqlc.arg(delivery_id) AND attempt = sqlc.arg(attempt) AND status = 'attempting';

-- name: InterruptAllAttemptLogs :exec
UPDATE alert_log SET status = 'interrupted', error = 'the attempt did not finish (lease expired or server stopped)' WHERE status = 'attempting';

-- name: ReleaseDelivery :exec
UPDATE alert_deliveries SET claim_token = NULL, next_attempt_at = sqlc.arg(now) WHERE id = sqlc.arg(id);

-- name: FailDelivery :exec
UPDATE alert_deliveries SET status = 'failed', claim_token = NULL, next_attempt_at = NULL, finished_at = sqlc.arg(now) WHERE id = sqlc.arg(id);

-- ------------------------------------------------------------------ reading

-- name: ListAlertLog :many
-- kind is derived: a detection row has an event, a state-change row a state change, a test send neither.
SELECT l.id, l.ts, l.target_id, l.target_name, l.delivery_id, l.recipient, l.host_name, l.attempt, l.status, l.code, l.error, l.duration_ms,
       CAST(CASE WHEN l.event_id IS NOT NULL THEN 'detection' WHEN l.state_change_id IS NOT NULL THEN 'state change' ELSE 'test' END AS TEXT) AS kind
FROM alert_log l
WHERE (CAST(sqlc.arg(target_name) AS TEXT) = '' OR l.target_name = CAST(sqlc.arg(target_name) AS TEXT))
ORDER BY l.id DESC LIMIT sqlc.arg(max_rows);

-- name: CountUnroutedDetections :one
-- Events received since a time that have no delivery at all (no target
-- matched). A flagged event is not planned yet, so it is not counted.
SELECT COUNT(*) FROM events e
WHERE e.received_at >= sqlc.arg(since) AND e.alert_pending = 0
  AND NOT EXISTS (SELECT 1 FROM alert_deliveries d WHERE d.event_id = e.id);

-- name: CountPendingDeliveriesOfTarget :one
SELECT COUNT(*) FROM alert_deliveries WHERE target_id = sqlc.arg(target_id) AND status = 'pending';

-- ------------------------------------------------------------------- pruning

-- name: PruneAlertLog :execrows
DELETE FROM alert_log WHERE id IN (SELECT o.id FROM alert_log o WHERE o.ts < sqlc.arg(before) LIMIT sqlc.arg(batch));

-- name: PruneFinishedDeliveries :execrows
-- finished_at is set for sent, failed and cancelled; a pending delivery has none
-- and is never pruned.
DELETE FROM alert_deliveries WHERE id IN (SELECT o.id FROM alert_deliveries o WHERE o.finished_at IS NOT NULL AND o.finished_at < sqlc.arg(before) LIMIT sqlc.arg(batch));

-- ------------------------------------------------------------ key rotation

-- name: SealedAlertSecrets :many
SELECT id, name, secret FROM alert_targets WHERE secret IS NOT NULL ORDER BY id;

-- name: ResealAlertSecret :execrows
UPDATE alert_targets SET secret = sqlc.arg(new_secret) WHERE id = sqlc.arg(id) AND secret = sqlc.arg(old_secret);
