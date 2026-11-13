<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Changelog

All notable changes are listed here. The format follows Keep a Changelog; versions follow SemVer.

## Unreleased

### Added
- Milestone 4, alerting by email and webhook (see `docs/alerts.md`). A host's state change, recovery included, and a
  detection become alerts for the targets that take them: each target has a minimum severity (a drop below it is
  sent once as "resolved for this target"), an optional any-of tag filter, and switches for state changes and
  detections. `alert.cooldown` (default 15m) holds changes inside the window and sends one summary at its end if
  the host's state differs from what the target was last told, so a recovery is delayed by at most a cooldown and
  never lost. Alerts are queued in the database before anything is sent: 5 attempts over about 81 minutes,
  `Retry-After` honoured, every attempt in the alert log (90-day prune), delivery at least once (receivers
  deduplicate on the alert id), an email per recipient. Webhooks are signed in the Standard Webhooks format with
  a per-target key shown once; the URL and key are encrypted with the secret key file. The destination policy
  blocks loopback (unless allowed), link-local, cloud metadata and other special addresses at connection time,
  with no redirects and no proxy; `http://` and `smtp.tls: none` only reach loopback or private addresses.
  Admins manage targets under Alerts in the console (add, edit, send test, rotate key, delete) or with
  `clamfleet-server alert list|log|add-webhook|add-email|test|delete` (the URL comes from stdin or a protected
  file, never an argument). New config keys `public_url`, `alert.*` and `smtp.*`, and `key check`. No new
  dependency (stdlib `net/smtp`; HANDOVER section 5 no longer lists go-mail).
- Milestone 3b, TOTP two-factor sign-in for local accounts. A user sets up an authenticator app under Account
  (password required for every change; the key is shown as text and an `otpauth://` URI, no QR code), gets 10
  one-time recovery codes, and then signs in in two steps; a pending login is a separate record and cookie,
  never a session. Codes are single use, wrong codes are slowed and, after 100 in a row, locked until
  `user reset-password` or `user reset-totp EMAIL`. `auth.local.totp_required` (env
  `CLAMFLEET_SERVER_AUTH_LOCAL_TOTP_REQUIRED`) makes every local user enrol; trust on first use applies, see
  `docs/web.md`. TOTP secrets are encrypted with a key file, `secret_key_file` (default
  `/etc/clamfleet/server-secret.key`, mode 0640 root:clamfleet-server), made with `clamfleet-server key
  generate`; `key generate --add` and `key reencrypt` rotate it. The server refuses to start when the key file
  is invalid, or missing while TOTP is in use. New migration `00003`, additive: stop the server and copy the
  database first; an older binary refuses the database. No new dependency.
- Milestone 3, web console: local accounts (email and password, argon2id) with the roles `viewer` and
  `admin`, managed with `clamfleet-server user add|list|set-role|disable|enable|reset-password`; cookie
  sessions (12 h absolute, 1 h idle by default) with CSRF protection (SameSite=Lax, cross-origin check and a
  per-session token); a fleet overview that refreshes every 15 s, a page per host with its state history,
  and host administration for admins (register, rotate, revoke, delete). `clamfleet-server host delete NAME --yes`.
  New config keys `auth.local.enabled`, `auth.session_max_age`, `auth.session_idle` and `auth.cookie_secure`
  (one subtree per provider, so LDAP and OIDC can follow). See `docs/web.md`. Users and sessions tables come
  with migration `00002`. TOTP, LDAP and OIDC are not built yet.
- New dependency: `golang.org/x/crypto` v0.59.0 (argon2id; server only). htmx 2.0.11 (0BSD) is vendored as a
  static file with its SHA-256 recorded in `internal/web/static/README.md`.
- Milestone 3, health: the server decides every host's state (OK, WARN, CRIT, STALE) from the newest
  report (spec 9) after each accepted report and every `health.eval_interval`, keeps the reasons
  and one `state_changes` row per transition, and tunes the rules with a `health:` block (see the README).
  A host is pending until its first report, STALE after 3 x its own report interval, and the clock
  counts from the server start (restart grace). Database migration `00002` (stop and copy the
  database first; downgrades are refused) also creates the users and sessions tables for the web console.
- Milestone 2: the server. `clamfleet-server serve` runs the ingest API (`POST /v1/report`,
  `POST /v1/event`, `GET /healthz`; see `docs/api.md`) on SQLite with goose migrations and
  sqlc-generated queries; `migrate` and `host add|list|show|rotate-token|revoke-token` are the admin
  commands. Agents authenticate with one `cfa_` bearer token per host (only its SHA-256 is stored);
  token changes are written to an audit log. Optional mutual TLS (`tls.client_ca` on the server,
  `tls.client_cert`/`tls.client_key` on the agent) is an extra requirement: the token is still needed.
- `clamfleet-agent run` and `run --once` send the report to the server. The token file is re-read on
  every send. There is no spool yet.
- New dependencies: `modernc.org/sqlite` v1.62.0 and `github.com/pressly/goose/v3` v3.30.0 (server
  only; the agent does not link them). sqlc v1.31.1 is a build-time tool.
- Milestone 1: shared payload structs (`internal/proto`), agent collectors (clamd socket, CVD/CLD
  headers, freshclam, systemd units, host, last scan) and `clamfleet-agent collect --dry-run`.
- `interval_seconds` in the report: the agent's configured interval, so the server can judge STALE per agent (3 x interval). Additive, schema stays 1.
- `freshclam.source` in the report (`journal`, `log`, `journal+log`, `mtime`, or null). Additive, schema stays 1.

### Fixed
- A user disabled and re-enabled while their login was verifying no longer gets a session from that login
  (a per-user `auth_version`; this was the known limit of Milestone 3).

### Changed
- **`key reencrypt` exits 1 when it is incomplete** (a row changed between its read and its write: an admin
  rotated a webhook key, a user re-enrolled) and prints `incomplete: N re-sealed, M changed meanwhile; run key
  reencrypt again`. It now covers webhook secrets as well and re-seals everything in one transaction. The
  documented rotation gains a step: `key check` must exit 0 before the old key line is deleted.
- **Upgrade note, migration `00004` (additive).** Stop the server and copy the database first; an M3b binary
  refuses a database at this version. Existing state changes and detections are not alerted on: only changes
  recorded after the upgrade are.
- New server key `trusted_proxies` (env `CLAMFLEET_SERVER_TRUSTED_PROXIES`): the logged client IP comes from `X-Forwarded-For` (rightmost address that is not a trusted proxy) only when the direct peer is a trusted proxy. Default empty.
- The server defaults to plaintext on `127.0.0.1:8443` (reverse-proxy deployment); `tls.cert` and `tls.key` enable direct TLS.
- The server's state directory defaults to `/var/lib/clamfleet-server/` and it runs as its own user
  `clamfleet-server`, not the agent's `clamfleet` (HANDOVER section 12 says `/var/lib/clamfleet/`).
- `make check` also runs `sqlc diff`; `make build` builds both binaries.
- Agent environment variables use the prefix `CLAMFLEET_AGENT_` (config file: `CLAMFLEET_AGENT_CONFIG`),
  leaving `CLAMFLEET_SERVER_` for the server. This differs from HANDOVER section 12.
