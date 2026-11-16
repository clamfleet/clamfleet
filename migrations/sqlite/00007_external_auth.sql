-- SPDX-License-Identifier: AGPL-3.0-only
-- SPDX-FileCopyrightText: The ClamFleet Authors

-- Milestone 6b schema: external sign-in (docs/plans/milestone-6.md 4.14).
--
-- users already has auth_source, external_id with UNIQUE(auth_source, external_id), a nullable
-- unique email and a nullable password_hash (M3 decision 11), so there is no table rebuild:
-- the new sources "ldap" and "oidc" are validated in Go. Two additions only.

-- +goose Up
-- The LDAP user name or OIDC preferred_username: display, and the actor label when email is NULL.
ALTER TABLE users ADD COLUMN external_name TEXT;

-- One row per OIDC sign-in started; deleted when used (one-time) or expired. The row is found by
-- the hash of the cookie token, so a callback replayed from another browser finds nothing.
CREATE TABLE oidc_login_states (
  token_hash    BLOB    PRIMARY KEY, -- SHA-256 of the __Host-clamfleet_oidc cookie token
  state         TEXT    NOT NULL,    -- the URL state parameter (32 random bytes, base64url)
  nonce         TEXT    NOT NULL,
  code_verifier TEXT    NOT NULL,    -- PKCE; short-lived, never logged
  next_path     TEXT    NOT NULL,    -- webauth.SanitizeNext output
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL     -- created_at + 10 minutes
);
CREATE INDEX oidc_login_states_expires ON oidc_login_states(expires_at);

-- +goose Down
-- Development only: a production downgrade is refused by the server, not attempted.
DROP INDEX oidc_login_states_expires;
DROP TABLE oidc_login_states;
ALTER TABLE users DROP COLUMN external_name;
