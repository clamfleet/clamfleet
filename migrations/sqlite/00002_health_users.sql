-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Milestone 3 schema: host health state and its history (Part A), plus the
-- users and sessions tables of the web console (Part B), which the plan
-- (M3 plan 4.1, M3 decision 11) puts in this one migration so
-- the shape that is hard to change later is settled once.
--
-- Only ALTER TABLE ADD COLUMN and new tables, both cheap in SQLite. What is hard
-- to change later (NOT NULL, CHECK, UNIQUE, FK actions) is the reason there are
-- NO CHECK constraints on role, auth_source or state: Go validates them, so a
-- new role or state is never a table rebuild.

-- +goose Up
ALTER TABLE hosts ADD COLUMN state         TEXT;     -- OK | WARN | CRIT | STALE; NULL = never evaluated ("pending")
ALTER TABLE hosts ADD COLUMN state_reason  TEXT;     -- JSON array of the current reasons
ALTER TABLE hosts ADD COLUMN state_since   INTEGER;  -- server clock, time of the last transition
ALTER TABLE hosts ADD COLUMN daily_version INTEGER;  -- copied from last_report: the "newest daily in the fleet" query stays portable (no json_extract)
ALTER TABLE hosts ADD COLUMN daily_built   INTEGER;
ALTER TABLE hosts ADD COLUMN clamd_version TEXT;

-- Backfill from existing last_report rows. SQLite-only SQL is fine in a
-- dialect-specific migration; the queries stay portable.
UPDATE hosts SET
  daily_version = json_extract(last_report, '$.sigs.daily.version'),
  daily_built   = CAST(strftime('%s', json_extract(last_report, '$.sigs.daily.built')) AS INTEGER),
  clamd_version = json_extract(last_report, '$.clamd.version')
WHERE last_report IS NOT NULL;

CREATE TABLE state_changes (
  id         INTEGER PRIMARY KEY,
  host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,  -- M2 decision 2: cascade
  ts         INTEGER NOT NULL,   -- server clock
  from_state TEXT,               -- NULL on a host's first evaluation (M3 decision 5)
  to_state   TEXT    NOT NULL,
  reason     TEXT    NOT NULL    -- JSON snapshot of the reasons at the transition
);
CREATE INDEX state_changes_host_ts ON state_changes(host_id, ts);
CREATE INDEX state_changes_ts ON state_changes(ts);   -- retention (M6), alerting scan (M4)

CREATE TABLE users (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT, -- no id reuse
  email                TEXT UNIQUE,      -- lowercased in Go; required for local users, may be NULL for LDAP
  display_name         TEXT,
  role                 TEXT    NOT NULL, -- 'viewer' | 'admin', validated in Go
  auth_source          TEXT    NOT NULL DEFAULT 'local', -- 'local' now; 'ldap', 'oidc' in M6
  external_id          TEXT,             -- LDAP DN or OIDC iss+sub; NULL for local
  password_hash        TEXT,             -- PHC string (argon2id); NULL for external users
  password_must_change INTEGER NOT NULL DEFAULT 0, -- 1 after a CLI-issued one-time password
  password_changed_at  INTEGER,
  disabled_at          INTEGER,          -- NULL = active
  created_at           INTEGER NOT NULL,
  updated_at           INTEGER NOT NULL,
  last_login_at        INTEGER,
  UNIQUE (auth_source, external_id)      -- NULLs do not collide (SQLite and Postgres)
);

CREATE TABLE user_sessions (
  id           INTEGER PRIMARY KEY,
  token_hash   BLOB    NOT NULL UNIQUE,  -- SHA-256 of the cookie token; the token itself is never stored
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token   BLOB    NOT NULL,         -- 32 random bytes, synchronizer token (not a login credential)
  created_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,         -- updated at most once a minute (write throttling)
  expires_at   INTEGER NOT NULL          -- absolute expiry
);
CREATE INDEX user_sessions_user ON user_sessions(user_id);
CREATE INDEX user_sessions_expires ON user_sessions(expires_at);

-- +goose Down
-- Development only: a production downgrade is refused by the server, not attempted.
-- DROP COLUMN needs SQLite 3.35 or newer; modernc bundles a newer one.
DROP TABLE user_sessions;
DROP TABLE users;
DROP TABLE state_changes;
ALTER TABLE hosts DROP COLUMN clamd_version;
ALTER TABLE hosts DROP COLUMN daily_built;
ALTER TABLE hosts DROP COLUMN daily_version;
ALTER TABLE hosts DROP COLUMN state_since;
ALTER TABLE hosts DROP COLUMN state_reason;
ALTER TABLE hosts DROP COLUMN state;
