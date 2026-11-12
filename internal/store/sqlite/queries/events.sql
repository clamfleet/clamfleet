-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- name: InsertEvent :execrows
INSERT INTO events (host_id, ts, received_at, path, signature, source)
VALUES (sqlc.arg(host_id), sqlc.arg(ts), sqlc.arg(received_at), sqlc.arg(path), sqlc.arg(signature), sqlc.arg(source))
ON CONFLICT (host_id, ts, path, signature) DO NOTHING;
