-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Retention prunes of milestone 6. Each statement
-- deletes at most `batch` rows; the store runs it in a loop, one transaction per
-- call, so the write lock is released between batches and ingest interleaves.
-- PruneEvents, PruneClosedWindows and the alert-history prunes live beside their tables.

-- name: PruneReports :execrows
-- Counted from ARRIVAL (received_at, server clock), not the agent's ts: a spooled
-- report can be old when it arrives. hosts.last_report and hosts.state are never
-- touched, so the fleet page does not depend on history.
DELETE FROM reports WHERE id IN (
  SELECT r.id FROM reports r WHERE r.received_at < sqlc.arg(before) ORDER BY r.id LIMIT sqlc.arg(batch)
);

-- name: PruneStateChanges :execrows
-- Rule: a state change whose alert is not finished is never pruned. The cascade
-- would delete its pending delivery, and the alert would be lost without a trace.
-- Unfinished means alert_pending = 1 (not yet planned) or a delivery with no finished_at.
DELETE FROM state_changes WHERE id IN (
  SELECT s.id FROM state_changes s
  WHERE s.ts < sqlc.arg(before) AND s.alert_pending = 0
    AND NOT EXISTS (SELECT 1 FROM alert_deliveries d WHERE d.state_change_id = s.id AND d.finished_at IS NULL)
  ORDER BY s.id LIMIT sqlc.arg(batch)
);

-- name: PruneAudit :execrows
DELETE FROM audit_log WHERE id IN (
  SELECT a.id FROM audit_log a WHERE a.ts < sqlc.arg(before) ORDER BY a.id LIMIT sqlc.arg(batch)
);
