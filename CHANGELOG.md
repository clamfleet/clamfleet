<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Changelog

All notable changes are listed here. The format follows Keep a Changelog; versions follow SemVer.

## Unreleased

### Added
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
- `freshclam.source` in the report (`journal`, `log`, `journal+log`, `mtime`, or null). Additive, schema stays 1.

### Changed
- New server key `trusted_proxies` (env `CLAMFLEET_SERVER_TRUSTED_PROXIES`): the logged client IP comes from `X-Forwarded-For` (rightmost address that is not a trusted proxy) only when the direct peer is a trusted proxy. Default empty.
- The server defaults to plaintext on `127.0.0.1:8443` (reverse-proxy deployment); `tls.cert` and `tls.key` enable direct TLS.
- The server's state directory defaults to `/var/lib/clamfleet-server/` and it runs as its own user
  `clamfleet-server`, not the agent's `clamfleet` (HANDOVER section 12 says `/var/lib/clamfleet/`).
- `make check` also runs `sqlc diff`; `make build` builds both binaries.
- Agent environment variables use the prefix `CLAMFLEET_AGENT_` (config file: `CLAMFLEET_AGENT_CONFIG`),
  leaving `CLAMFLEET_SERVER_` for the server. This differs from HANDOVER section 12.
