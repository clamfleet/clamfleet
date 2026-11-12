-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Milestone 2 schema. Only the tables M2 uses: state, state_reason and
-- state_changes arrive with the M3 migration, the alert tables with M4.
-- What is hard to change later (SQLite can only do it by rebuilding the table)
-- is fixed here: column types and the foreign key actions.
--
-- Rule: every timestamp is INTEGER unix seconds, UTC (decision 1). The store
-- layer converts; no time.Time ever reaches the driver.
--
-- Rule: deleting a host cascades to everything that belongs to it (decision 2).
-- Long-term retention of detections is the customer's central logging job.

-- +goose Up
CREATE TABLE hosts (
  id                INTEGER PRIMARY KEY AUTOINCREMENT, -- no id reuse after delete (log and audit lines name ids)
  name              TEXT    NOT NULL UNIQUE,  -- admin-assigned identity, stored lowercased (portable: no COLLATE NOCASE)
  token_hash        BLOB    UNIQUE,           -- SHA-256 of the agent bearer token; NULL = revoked
  token_created_at  INTEGER,                  -- server clock
  created_at        INTEGER NOT NULL,
  first_seen        INTEGER,                  -- server clock, first accepted report
  last_seen         INTEGER,                  -- server clock, last accepted report (events do not count: spec 9 STALE is about reports)
  reported_name     TEXT,                     -- payload "host", display only (identity comes from the token)
  agent_version     TEXT,
  last_report_order INTEGER,                  -- min(agent ts, received_at) of last_report
  last_report       TEXT                      -- canonical JSON of the newest report
);

CREATE TABLE host_tags (
  host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  tag     TEXT    NOT NULL,
  PRIMARY KEY (host_id, tag)
);
CREATE INDEX host_tags_tag ON host_tags(tag);

CREATE TABLE reports (
  id          INTEGER PRIMARY KEY,
  host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  ts          INTEGER NOT NULL,   -- agent clock
  received_at INTEGER NOT NULL,   -- server clock; retention (M6) uses this, not the agent clock
  payload     TEXT    NOT NULL,
  UNIQUE (host_id, ts)            -- a retried POST is stored once; also the host-history index
);
CREATE INDEX reports_received_at ON reports(received_at);

CREATE TABLE events (
  id          INTEGER PRIMARY KEY,
  host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  ts          INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  path        TEXT    NOT NULL,
  signature   TEXT    NOT NULL,
  source      TEXT    NOT NULL,
  ack_by      TEXT,               -- display snapshot of the acting user, never a foreign key
  ack_at      INTEGER,
  UNIQUE (host_id, ts, path, signature)  -- idempotent retries without a payload id
);
CREATE INDEX events_received_at ON events(received_at);

CREATE TABLE audit_log (
  id          INTEGER PRIMARY KEY,
  ts          INTEGER NOT NULL,
  actor_kind  TEXT    NOT NULL,   -- 'cli' now; 'user' and 'system' later
  actor       TEXT    NOT NULL,   -- OS user for cli (SUDO_USER if set); later a user snapshot, no FK so rows outlive users
  action      TEXT    NOT NULL,   -- 'host.add', 'host.token.rotate', 'host.token.revoke', ...
  target_kind TEXT    NOT NULL,   -- 'host'
  target      TEXT    NOT NULL,   -- host name snapshot (survives host deletion)
  detail      TEXT                -- JSON, never secrets
);
CREATE INDEX audit_log_ts ON audit_log(ts);

-- +goose Down
-- Development only: a production downgrade is refused by the server, not attempted.
DROP TABLE audit_log;
DROP TABLE events;
DROP TABLE reports;
DROP TABLE host_tags;
DROP TABLE hosts;
