-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- name: InsertReport :execrows
INSERT INTO reports (host_id, ts, received_at, payload)
VALUES (sqlc.arg(host_id), sqlc.arg(ts), sqlc.arg(received_at), sqlc.arg(payload))
ON CONFLICT (host_id, ts) DO NOTHING;
