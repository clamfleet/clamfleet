<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Changelog

All notable changes are listed here. The format follows Keep a Changelog; versions follow SemVer.

## Unreleased

### Added
- Milestone 6c, continuous integration and project files (in progress). **CI** (`.github/workflows/ci.yml`): `make ci` on every pull request
  (vet, staticcheck, sqlc diff, unit and script tests through a test gate that fails on skipped tests, actionlint, module and gofmt
  checks), the Playwright browser tests of the console, and a DCO sign-off check (`hack/ci/dco.sh`); every action is GitHub-owned and pinned
  by commit SHA (`deploy/test/workflows_test.sh`). Dependabot for actions, the CI image and Go security updates. `reset.sh` can reset a
  Docker container as well as an Incus snapshot (`RESET_RUNTIME=docker`), with `deploy/test/ci/Dockerfile` (Debian 13, systemd, ClamAV,
  frozen signatures) and `make e2e-image` and `make e2e-docker`. `make tools` and `make ci`; staticcheck, sqlc and actionlint are pinned in
  the Makefile. Every tracked file is checked for its SPDX header. CONTRIBUTING.md, CODE_OF_CONDUCT.md (Contributor Covenant 2.1),
  SECURITY.md, issue forms and a pull request template.
  **Releases** (`deploy/release`, `.github/workflows/release.yml`, `docs/releasing.md`): a signed tag `vX.Y.Z` or `vX.Y.Z-rc.N` on a
  commit whose full CI passed on `main` builds the tarball, the `.deb` and `.rpm` files, a CycloneDX SBOM per binary (htmx included in the
  server's) and `SHA256SUMS`, then a separate job that holds the only secret signs the rpms and the checksums and a draft release is
  created. `release.sh` checks its own output (versions, revisions, package payloads equal the tarball's, SBOM modules equal
  `go list`); `make release-snapshot` runs it locally and the CI job `release-dry-run` signs with a throwaway key on every ready pull
  request. `docs/install.md` explains "Verifying a download". Replaces the goreleaser plan: it cannot load our nfpm files.
- Milestone 6b, external sign-in (see `docs/auth.md`). **LDAP** (one directory; search, then bind; `ldaps://` or StartTLS, plaintext
  only to loopback; the name escaped into the filter; an empty password refused before any network I/O; the identity is the
  `entryUUID` or `objectGUID`, never the DN; groups from `memberOf` or a search) and **OpenID Connect** (one provider; the
  authorization code flow with PKCE S256, `state`, `nonce`, a one-time state row bound to a `__Host-clamfleet_oidc` SameSite=Lax cookie;
  discovery on the standard library; no JOSE library, the ID token is taken from the token endpoint over TLS as OIDC Core 3.1.3.7
  allows, and every claim is checked) next to local accounts, in any combination. Roles come from groups or a claim at every
  sign-in; a user with no role is refused. External users are created at first sign-in and never linked to a local account: an email
  that belongs to another user refuses the sign-in. The login form takes "Email or user name" (a local account with exactly that
  email is tried first); a "Single sign-on" button starts OIDC. `user list` shows the source; `set-role`, `reset-password` and
  `reset-totp` refuse external users; `disable` and `enable` take `ldap:NAME` or `oidc:NAME`. New server keys `auth.ldap.*` and
  `auth.oidc.*` (both off by default; secrets only in files), routes `POST /login/oidc` and `GET /login/oidc/callback`, migration
  `00007` (`users.external_name`, `oidc_login_states`), `make e2e-idp` (OpenLDAP and Keycloak in a throwaway container) and
  `webfixture --sso`. New dependency: `github.com/go-ldap/ldap/v3` (MIT) with `go-asn1-ber/asn1-ber` and `Azure/go-ntlmssp`.
- Milestone 6a, operations and packaging (see `docs/install.md`, `docs/operations.md`, `docs/configuration.md`).
  **Packages:** `clamfleet-agent` and `clamfleet-server` as `.deb` and `.rpm` (nfpm v2.49.0), with systemd units
  (hardened), sysusers.d and tmpfiles.d files, example configs as conffiles, our own AppArmor profile (Debian) or an
  SELinux module (RHEL family, installed at priority 300, no rule on a stock type). The agent waits for its token;
  the first server install creates the secret key file; a purge never deletes the database or the key file.
  **Retention** for every table (`retention.reports_days` 30, `state_changes_days` 365, `alert_log_days` 90,
  `audit_days` 365, plus `events_days`), one daily pass, `PRAGMA optimize`. **Backup:** `clamfleet-server backup`
  (`--keep`, `--verify`, `VACUUM INTO`, a private directory, a lock), a timer that ships disabled, and an automatic
  backup before every migration. **`GET /metrics`** (Prometheus text format, off by default, bearer token from a file).
  **TLS reload** on SIGHUP, all or nothing. **`clamfleet-agent scan`** and its timer (shipped disabled); new agent
  key `scan.timeout`; `scanned` is always 0 (clamdscan does not report a file count). New server keys: `retention.*`,
  `backup.*`, `metrics.*`, `alert.webhook.nat64_prefixes`. Migration `00006` is additive (three indexes). No new
  runtime dependency.

### Fixed
- A spool test swapped a file for another and expected a different inode, which ext4 does not guarantee (it reuses the freed one); found by
  the first CI run, the test now keeps the old inode allocated.
- Milestone 6b: **the TOTP gate** was "source is local", so any user of another source skipped `auth.local.totp_required`. It now
  exempts only `ldap` and `oidc`; an unknown source is gated, and a session of an unknown source is no session at all.
- Milestone 6a: **event prune** deleted events whose alert was still being delivered, or that were held in an open
  detection window; they are now kept until the alert is finished. **NAT64:** a webhook or SMTP address that carries an
  IPv4 address (`64:ff9b::/96`, your own prefixes in `alert.webhook.nat64_prefixes`) is judged by the IPv4 inside it;
  6to4, Teredo, IPv4-compatible, SIIT and the local-use range of an unlisted translator are blocked.

### Upgrade notes (milestone 6b)
- **Disabling a sign-in method ends its users' sessions.** A session is valid only while its user's source is enabled. That includes
  `auth.local.enabled: false`, which in milestone 3 left existing local sessions working: they now end at the next request.
- **The TOTP requirement exempts only `ldap` and `oidc`**; LDAP sign-ins are password-only (the server warns at start when LDAP and
  `auth.local.totp_required` are both on). Use OIDC where a second factor matters.
- Migration `00007` is additive; an M6a binary refuses a `00007` database (upgrade the server first). The e2e-only overlay migration
  moved from `00007` to `00008`.
- `user list` has a SOURCE column (its first column is now USER: the email, or `source:name`). `--json` is unchanged except for the
  new `external_name` and `external_id` fields.
- `POST /login/oidc` answers with a page, not a redirect (the console's `form-action 'self'` policy would block a redirect), and
  starting a sign-in needs no session: rate limit it in your reverse proxy. The console's Content-Security-Policy is unchanged.
- Active Directory configuration is documented and untested.

### Upgrade notes (milestone 6a)
- **The first retention pass** can delete a large part of `reports` (kept since milestone 2): in batches, logged by count.
  The file does not shrink; `clamfleet-server backup` writes a compact copy.
- **A backup is written before every migration** (`backup.dir`, the newest 3 kept; free space of 1.1 times the database
  is needed). If it fails the server refuses to migrate; `clamfleet-server migrate --no-backup` is the way past it.
- **`/metrics` is off** unless you enable it and give it a token file.
- **Alert addresses are judged on both forms** (the address and the IPv4 inside it): a `deny_networks` entry now also blocks
  its NAT64 form. An operator with a local-use NAT64 translator must list its prefix in `alert.webhook.nat64_prefixes`.
- The alert history prune moved from the dispatcher to the retention runner (`retention.alert_log_days`, default 90).
- Upgrade the server first, then the agents. An M5 binary refuses a `00006` database.

### Added (earlier milestones)
- Milestone 5, detections (see `docs/detections.md`). clamd's `VirusEvent` runs the new `clamfleet-agent event`, which
  writes the detection to a spool in the agent's state directory and never touches the network or the token, so
  a detection survives a server outage. The spool is published with a no-replace `link()` after an `fsync`, has
  a hard cap on real disk use (`spool.max_mb`, heartbeats are evicted before events, events are never evicted),
  expires events after `spool.max_event_days`, and is read as untrusted input: only regular files, inode checks,
  bounded reads, every field validated and re-encoded before sending. The agent sends in two lanes (detections
  younger than a minute first, then the backlog oldest first; heartbeats separately, replayed ones marked `replay`
  and stored by the server as history only). The server stores events with the agent's idempotency key (a
  second genuine detection that collides is counted as "x2", never lost), wakes the alert dispatcher at once,
  and a **Detections** page (filters, keyset paging, file names with bidi or line-separator characters shown
  as visible escapes) with admin acknowledgement, per row or "all matching as of this id", and open counts on
  the fleet, host and menu. A burst of detections per host and target (`detection_burst`, default 10 per 10
  minutes) becomes individual alerts plus one `detection_summary`; state alerts are claimed first, one worker
  is reserved for them and a target has at most 2 detection sends in flight. `retention.events_days`
  (default 365) prunes events daily. New optional payload fields (schema stays 1): `clamd.virus_event`,
  `report.replay`, `event.id`; new WARN rule `virusevent_missing` (`health.require_virus_event`). AppArmor
  files for Debian are in `deploy/apparmor/`, proven by the new `make e2e-apparmor` on a VM. No new dependency.
  **Upgrading from milestone 4:** upgrade the server first, then the agents. Existing alert targets get
  `detection_burst` 10 (burst summaries), existing events show as open, hosts without a `VirusEvent` line get
  the WARN `virusevent_missing` (`health.require_virus_event: false` switches it off), replayed heartbeats no
  longer update `last_seen`, and one dispatcher worker is reserved for state alerts. Migration `00005` is
  additive: stop the server and copy the database first; an older binary refuses the database. Set the
  agent's spool keys in the config file, not the environment (the event command cannot see the environment).
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
