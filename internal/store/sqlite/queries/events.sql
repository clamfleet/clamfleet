-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- name: InsertEvent :execrows
-- alert_pending = 1 only ever lands on a NEW row: a duplicate retry from the
-- agent hits ON CONFLICT DO NOTHING and leaves the existing row (and its flag)
-- alone, so a retried POST never alerts twice.
INSERT INTO events (host_id, ts, received_at, path, signature, source, alert_pending)
VALUES (sqlc.arg(host_id), sqlc.arg(ts), sqlc.arg(received_at), sqlc.arg(path), sqlc.arg(signature), sqlc.arg(source), 1)
ON CONFLICT (host_id, ts, path, signature) DO NOTHING;
