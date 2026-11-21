-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Milestone 4 schema: email and webhook alerting.
--
-- Additive only: two ADD COLUMNs with a constant default and new tables. There
-- are NO CHECK constraints (M3 decision 11): types and statuses are validated
-- in Go, so a later target type needs no table rebuild.
--
-- Existing rows get alert_pending 0 on purpose: upgrading must not alert on
-- history. Only rows written after the upgrade are flagged (by the store).
--
-- Downgrade safety: an M3b binary would never plan or send the queued alerts.
-- The checkNotNewer guard refuses a database whose schema is newer than the
-- binary, and a test pins that for this version.

-- +goose Up
ALTER TABLE state_changes ADD COLUMN alert_pending INTEGER NOT NULL DEFAULT 0; -- 1 = not yet planned; old rows 0: no alerts for history
ALTER TABLE events        ADD COLUMN alert_pending INTEGER NOT NULL DEFAULT 0;
-- Partial: they only ever hold the few unplanned rows, so they stay tiny.
CREATE INDEX state_changes_alert_pending ON state_changes(id) WHERE alert_pending = 1;
CREATE INDEX events_alert_pending        ON events(id)        WHERE alert_pending = 1;

CREATE TABLE alert_targets (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT, -- AAD of the sealed secret: never reused
  name               TEXT    NOT NULL UNIQUE,  -- [a-z0-9][a-z0-9._-]{0,63}, immutable; "new" is reserved (route)
  type               TEXT    NOT NULL,         -- 'email' | 'webhook'
  config             TEXT    NOT NULL,         -- JSON, non-secret: email {"to":[...]}, webhook {"url_display":"https://hooks.example/...","plaintext":false}
  secret             BLOB,                     -- webhook: sealed JSON {"url","signing_key"} (purpose alert-target, AAD id); email: NULL
  min_severity       TEXT    NOT NULL DEFAULT 'WARN', -- WARN | CRIT | STALE; state changes only
  tag_filter         TEXT    NOT NULL DEFAULT '[]',   -- JSON array; [] = every host; any-of
  send_state_changes INTEGER NOT NULL DEFAULT 1,
  send_detections    INTEGER NOT NULL DEFAULT 1,
  enabled            INTEGER NOT NULL DEFAULT 1,
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL
);

CREATE TABLE alert_notify_state (  -- what each target was last told about each host
  target_id  INTEGER NOT NULL REFERENCES alert_targets(id) ON DELETE CASCADE,
  host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  last_state TEXT    NOT NULL,       -- the "to" of the last state alert planned for this pair
  last_at    INTEGER NOT NULL,       -- when it was planned (cooldown start)
  held_count INTEGER NOT NULL DEFAULT 0, -- > 0: changes arrived inside the cooldown, re-check at last_at + cooldown
  PRIMARY KEY (target_id, host_id)
);

CREATE TABLE alert_deliveries (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id        TEXT    NOT NULL,  -- public id in the payload (128-bit random hex); shared by the alert's targets, recipients and retries
  target_id       INTEGER NOT NULL REFERENCES alert_targets(id) ON DELETE CASCADE,
  host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,       -- M2 decision 2: cascade
  recipient       TEXT    NOT NULL DEFAULT '', -- email: one address per delivery; webhook: ''. NOT NULL so the order query compares with =
  state_change_id INTEGER REFERENCES state_changes(id) ON DELETE CASCADE,
  event_id        INTEGER REFERENCES events(id) ON DELETE CASCADE,
  kind            TEXT    NOT NULL,  -- state_change | detection
  payload         TEXT    NOT NULL,  -- the JSON body, fixed at planning: every retry sends the same bytes
  status          TEXT    NOT NULL,  -- pending | sent | failed | cancelled
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER,           -- due time while pending; while claimed, the lease expiry
  claim_token     BLOB,              -- 16 random bytes of the current claim; NULL = not claimed
  created_at      INTEGER NOT NULL,
  finished_at     INTEGER
);
CREATE INDEX alert_deliveries_due      ON alert_deliveries(status, next_attempt_at);
CREATE INDEX alert_deliveries_order    ON alert_deliveries(target_id, host_id, recipient, status, id);
CREATE INDEX alert_deliveries_finished ON alert_deliveries(finished_at);
CREATE INDEX alert_deliveries_event    ON alert_deliveries(event_id); -- "detections that reached no target"

CREATE TABLE alert_log (           -- spec 8.2: one row per attempt, plus held/skipped/test/cancelled
  id              INTEGER PRIMARY KEY,
  ts              INTEGER NOT NULL,
  target_id       INTEGER REFERENCES alert_targets(id) ON DELETE SET NULL, -- the log outlives a deleted target
  target_name     TEXT    NOT NULL,  -- snapshot
  delivery_id     INTEGER REFERENCES alert_deliveries(id) ON DELETE SET NULL,
  recipient       TEXT,              -- email deliveries only
  host_name       TEXT,              -- snapshot; NULL for a test send
  state_change_id INTEGER REFERENCES state_changes(id) ON DELETE CASCADE,
  event_id        INTEGER REFERENCES events(id) ON DELETE CASCADE,
  attempt         INTEGER,
  status          TEXT    NOT NULL,  -- attempting | sent | retrying | failed | interrupted | held | skipped | cancelled | test_sent | test_failed
  code            TEXT,              -- "HTTP 503", "SMTP 550", "blocked", "timeout", "tls", "dns"...
  error           TEXT,              -- our own text; never a response body, never a URL path or secret
  duration_ms     INTEGER
);
CREATE INDEX alert_log_ts       ON alert_log(ts);
CREATE INDEX alert_log_target   ON alert_log(target_id, id);
CREATE INDEX alert_log_delivery ON alert_log(delivery_id);

-- +goose Down
-- Development only: a production downgrade is refused by the server, not attempted.
DROP TABLE alert_log;
DROP TABLE alert_deliveries;
DROP TABLE alert_notify_state;
DROP TABLE alert_targets;
DROP INDEX events_alert_pending;
DROP INDEX state_changes_alert_pending;
ALTER TABLE events DROP COLUMN alert_pending;
ALTER TABLE state_changes DROP COLUMN alert_pending;
