-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Milestone 3b schema: TOTP second factor for local console users
-- (docs/plans/milestone-3b.md 4.1).
--
-- Additive only: ADD COLUMN with a constant default and new tables are cheap in
-- SQLite and leave a running M3 binary's queries valid. There are still NO
-- CHECK constraints (M3 decision 11). The invariant "totp_secret and
-- totp_enabled_at are both NULL or both set" is kept by the Go store and
-- covered by a store test.
--
-- Downgrade safety: an M3 binary on this database would ignore TOTP and let a
-- password alone in. The existing checkNotNewer guard refuses to open a database
-- whose schema is newer than the binary, and a test pins that for this version.

-- +goose Up
ALTER TABLE users ADD COLUMN auth_version    INTEGER NOT NULL DEFAULT 0; -- bumped by every change that must kill an in-flight login
ALTER TABLE users ADD COLUMN totp_secret     BLOB;     -- sealed by internal/secrets (purpose "totp", AAD = user id); NULL = no TOTP
ALTER TABLE users ADD COLUMN totp_enabled_at INTEGER;  -- NULL = not enrolled
ALTER TABLE users ADD COLUMN totp_last_step  INTEGER;  -- highest accepted RFC 6238 time step: the replay guard
ALTER TABLE users ADD COLUMN totp_failures   INTEGER NOT NULL DEFAULT 0; -- consecutive second-factor failures (persistent lock)
ALTER TABLE user_sessions ADD COLUMN totp_pending    BLOB;    -- sealed secret of an enrolment started in THIS session
ALTER TABLE user_sessions ADD COLUMN totp_pending_at INTEGER;

CREATE TABLE user_recovery_codes (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  BLOB    NOT NULL,   -- SHA-256 of the normalised code; the code itself is never stored
  created_at INTEGER NOT NULL,
  used_at    INTEGER,            -- NULL = still usable
  UNIQUE (user_id, code_hash)
);

-- A password was verified and the second factor is pending. NOT a session: a
-- different table, cookie and token prefix, so it can never be mistaken for one.
CREATE TABLE user_login_challenges (
  id           INTEGER PRIMARY KEY,
  token_hash   BLOB    NOT NULL UNIQUE, -- SHA-256 of the cfp_ cookie token
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  auth_version INTEGER NOT NULL,        -- what the password step saw
  next         TEXT    NOT NULL,        -- sanitised redirect target
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL
);
CREATE INDEX user_login_challenges_user    ON user_login_challenges(user_id);
CREATE INDEX user_login_challenges_expires ON user_login_challenges(expires_at);

-- +goose Down
-- Development only: a production downgrade is refused by the server, not attempted.
DROP TABLE user_login_challenges;
DROP TABLE user_recovery_codes;
ALTER TABLE user_sessions DROP COLUMN totp_pending_at;
ALTER TABLE user_sessions DROP COLUMN totp_pending;
ALTER TABLE users DROP COLUMN totp_failures;
ALTER TABLE users DROP COLUMN totp_last_step;
ALTER TABLE users DROP COLUMN totp_enabled_at;
ALTER TABLE users DROP COLUMN totp_secret;
ALTER TABLE users DROP COLUMN auth_version;
