-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Events queries. Portable SQL (HANDOVER section 8.1) with ONE SQLite-only
-- exception: the signature filter in ListEvents, CountEvents, MaxEventID and
-- AckEventsBulk uses instr(lower(signature), lower(filter)) > 0.
-- Why it stays: a case-insensitive substring match needs either LIKE with an
-- ESCAPE clause (sqlc's SQLite parser rejects LIKE ... ESCAPE) or unescaped LIKE,
-- where the wildcard and escape rules differ between SQLite and PostgreSQL.
-- instr() has no wildcards, so % _ and \ in the filter match themselves.
-- Maintainer decision (Gabriel), recorded as an exception to the portability rule.
-- When a PostgreSQL backend is added, swap it in all four queries for the
-- equivalent form: strpos(lower(signature), lower($n)) > 0.

-- name: InsertEvent :one
-- alert_pending = 1 only ever lands on a NEW row: a conflict on the natural key
-- returns no row (sql.ErrNoRows), leaving the existing row and its flag alone,
-- so a retried or merged detection never alerts twice.
INSERT INTO events (host_id, ts, received_at, path, signature, source, alert_pending)
VALUES (sqlc.arg(host_id), sqlc.arg(ts), sqlc.arg(received_at), sqlc.arg(path), sqlc.arg(signature), sqlc.arg(source), 1)
ON CONFLICT (host_id, ts, path, signature) DO NOTHING
RETURNING id;

-- name: EventIDByKey :one
SELECT id FROM events
WHERE host_id = sqlc.arg(host_id) AND ts = sqlc.arg(ts) AND path = sqlc.arg(path) AND signature = sqlc.arg(signature);

-- name: BumpEventOccurrences :exec
UPDATE events SET occurrences = occurrences + 1 WHERE id = sqlc.arg(id);

-- name: EventReceiptExists :one
SELECT count(*) FROM event_receipts WHERE host_id = sqlc.arg(host_id) AND agent_event_id = sqlc.arg(agent_event_id);

-- name: InsertEventReceipt :exec
INSERT INTO event_receipts (host_id, agent_event_id, event_id, received_at)
VALUES (sqlc.arg(host_id), sqlc.arg(agent_event_id), sqlc.arg(event_id), sqlc.arg(received_at));

-- name: ListEvents :many
-- One filter shape for list, count and bulk boundary. The parameters are CAST so
-- sqlc types them. The signature filter is instr(lower(), lower()), a plain
-- case-insensitive substring: no LIKE wildcards to escape, so % _ and \ in the
-- filter match themselves (sqlc's SQLite parser also rejects LIKE ... ESCAPE).
SELECT e.id, e.host_id, h.name AS host_name, e.ts, e.received_at, e.path, e.signature, e.source,
       e.occurrences, e.ack_by, e.ack_at
FROM events e JOIN hosts h ON h.id = e.host_id
WHERE (CAST(sqlc.arg(host) AS TEXT) = '' OR h.name = sqlc.arg(host))
  AND (CAST(sqlc.arg(sig) AS TEXT) = '' OR instr(lower(e.signature), lower(sqlc.arg(sig))) > 0)
  AND (CAST(sqlc.arg(ack) AS TEXT) = 'all'
       OR (CAST(sqlc.arg(ack) AS TEXT) = 'open' AND e.ack_at IS NULL)
       OR (CAST(sqlc.arg(ack) AS TEXT) = 'acked' AND e.ack_at IS NOT NULL))
  AND (CAST(sqlc.arg(before_id) AS INTEGER) = 0 OR e.id < sqlc.arg(before_id))
  AND (CAST(sqlc.arg(up_to) AS INTEGER) = 0 OR e.id <= sqlc.arg(up_to))
ORDER BY e.id DESC
LIMIT sqlc.arg(max_rows);

-- name: CountEvents :one
SELECT count(*)
FROM events e JOIN hosts h ON h.id = e.host_id
WHERE (CAST(sqlc.arg(host) AS TEXT) = '' OR h.name = sqlc.arg(host))
  AND (CAST(sqlc.arg(sig) AS TEXT) = '' OR instr(lower(e.signature), lower(sqlc.arg(sig))) > 0)
  AND (CAST(sqlc.arg(ack) AS TEXT) = 'all'
       OR (CAST(sqlc.arg(ack) AS TEXT) = 'open' AND e.ack_at IS NULL)
       OR (CAST(sqlc.arg(ack) AS TEXT) = 'acked' AND e.ack_at IS NOT NULL))
  AND (CAST(sqlc.arg(up_to) AS INTEGER) = 0 OR e.id <= sqlc.arg(up_to));

-- name: MaxEventID :one
SELECT CAST(COALESCE(MAX(e.id), 0) AS INTEGER)
FROM events e JOIN hosts h ON h.id = e.host_id
WHERE (CAST(sqlc.arg(host) AS TEXT) = '' OR h.name = sqlc.arg(host))
  AND (CAST(sqlc.arg(sig) AS TEXT) = '' OR instr(lower(e.signature), lower(sqlc.arg(sig))) > 0)
  AND (CAST(sqlc.arg(ack) AS TEXT) = 'all'
       OR (CAST(sqlc.arg(ack) AS TEXT) = 'open' AND e.ack_at IS NULL)
       OR (CAST(sqlc.arg(ack) AS TEXT) = 'acked' AND e.ack_at IS NOT NULL));

-- name: CountOpenEvents :one
SELECT count(*) FROM events WHERE ack_at IS NULL;

-- name: EventRowByID :one
SELECT e.id, e.host_id, h.name AS host_name, e.ts, e.received_at, e.path, e.signature, e.source,
       e.occurrences, e.ack_by, e.ack_at
FROM events e JOIN hosts h ON h.id = e.host_id
WHERE e.id = sqlc.arg(id);

-- name: AckEventByID :execrows
-- ack_at IS NULL: the first writer wins and a second acknowledgement changes nothing.
UPDATE events SET ack_by = sqlc.arg(ack_by), ack_at = sqlc.arg(ack_at)
WHERE id = sqlc.arg(id) AND ack_at IS NULL;

-- name: AckEventsBulk :execrows
-- Exactly the open events matching the filters with id <= up_to. Both bounds in
-- one statement inside one transaction, so the count is what this call changed.
UPDATE events SET ack_by = sqlc.arg(ack_by), ack_at = sqlc.arg(ack_at)
WHERE events.ack_at IS NULL AND events.id <= sqlc.arg(up_to)
  AND (CAST(sqlc.arg(host) AS TEXT) = '' OR events.host_id = (SELECT h2.id FROM hosts h2 WHERE h2.name = sqlc.arg(host)))
  AND (CAST(sqlc.arg(sig) AS TEXT) = '' OR instr(lower(events.signature), lower(sqlc.arg(sig))) > 0);

-- name: PruneEvents :execrows
-- Retention counts from ARRIVAL (received_at), not the agent's ts: a spooled
-- event can be old when it arrives, and must not be pruned the moment it lands.
DELETE FROM events WHERE id IN (
  SELECT e2.id FROM events e2 WHERE e2.received_at < sqlc.arg(before) ORDER BY e2.id LIMIT sqlc.arg(batch)
);

-- name: PruneClosedWindows :execrows
DELETE FROM alert_detection_windows WHERE id IN (
  SELECT w2.id FROM alert_detection_windows w2 WHERE w2.closed_at IS NOT NULL AND w2.closed_at < sqlc.arg(before) ORDER BY w2.id LIMIT sqlc.arg(batch)
);
