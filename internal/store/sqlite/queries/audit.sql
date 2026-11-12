-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- name: InsertAudit :exec
INSERT INTO audit_log (ts, actor_kind, actor, action, target_kind, target, detail)
VALUES (sqlc.arg(ts), sqlc.arg(actor_kind), sqlc.arg(actor), sqlc.arg(action),
        sqlc.arg(target_kind), sqlc.arg(target), sqlc.arg(detail));

-- name: ListAuditForTarget :many
SELECT id, ts, actor_kind, actor, action, target_kind, target, detail
FROM audit_log WHERE target_kind = sqlc.arg(target_kind) AND target = sqlc.arg(target)
ORDER BY id DESC LIMIT sqlc.arg(max_rows);
