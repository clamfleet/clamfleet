-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- /metrics inputs. Portable SQL only. Revoked hosts
-- (token_hash IS NULL) are excluded, as on the fleet page.

-- name: MetricsHosts :many
SELECT name, state, last_seen, last_report FROM hosts WHERE token_hash IS NOT NULL ORDER BY name;

-- name: MetricsOpenEvents :one
SELECT count(*) FROM events WHERE ack_at IS NULL;

-- name: MetricsDeliveries :one
-- pending: never tried; retrying: tried and waiting; failed: gave up since failed_since.
SELECT CAST(COALESCE(SUM(CASE WHEN status = 'pending' AND attempts = 0 THEN 1 ELSE 0 END), 0) AS INTEGER) AS pending,
       CAST(COALESCE(SUM(CASE WHEN status = 'pending' AND attempts > 0 THEN 1 ELSE 0 END), 0) AS INTEGER) AS retrying,
       CAST(COALESCE(SUM(CASE WHEN status = 'failed' AND finished_at >= sqlc.arg(failed_since) THEN 1 ELSE 0 END), 0) AS INTEGER) AS failed
FROM alert_deliveries;
