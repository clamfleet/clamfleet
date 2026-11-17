<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# ClamFleet: Specification and Handover

Central management and reporting for ClamAV on Linux servers.

| Field | Value |
| --- | --- |
| Status | Milestones 1 to 6b built; 6c (release engineering: CI, signed releases, project files) in progress |
| Project type | Open source, public repository, community contributions expected |
| Maintainer | The ClamFleet Authors (hi@madalin.me) |
| Target fleet | 50 to 100 Linux servers |
| Languages | Go (server and agent), htmx (UI) |
| Database | SQLite (Postgres possible later behind the same interface) |

## 1. Purpose

ClamAV has no central console. ClamFleet adds one. Each server runs a small agent that reports ClamAV health, signature status and detections to a central server. The server shows a fleet view to administrators and sends alerts on state changes by email or webhook.

Audience: administrators of small to medium Linux fleets who use ClamAV and want one place to see whether it is running, current and detecting. The project is general purpose and not tied to any organisation or compliance framework. Compliance-relevant features (retention, audit trail) are configurable defaults, not assumptions about the user's environment.

## 2. Scope

In scope for v1:

- Agent collecting ClamAV state and pushing it to the server.
- Server with ingest API, SQLite storage, health evaluation, web UI and alerting.
- Detection events delivered in near real time.
- Packaging as .deb and .rpm with systemd units.

Out of scope for v1:

- Remote control of agents (triggering scans, changing config).
- Windows or macOS agents.
- Multi-instance or high-availability server.
- Running a private signature mirror.

## 3. Architecture

```
[host: clamd + freshclam + clamfleet-agent] --HTTPS push--> [clamfleet-server]
                                                               ├─ SQLite (WAL)
                                                               ├─ health evaluator
                                                               ├─ alerter --> email / webhook
                                                               └─ web UI (htmx) + /metrics
```

Design rules:

- Push model. Agents only need outbound HTTPS to one endpoint. The server never connects to agents.
- Both components are single static Go binaries (`CGO_ENABLED=0`).
- The server embeds templates, static assets and migrations via `embed.FS`.
- If the server is unreachable, the agent spools reports and events to disk and retries. Nothing is lost within the spool's limits: heartbeats are evicted first when the spool is full, events are never evicted but are refused once events alone fill it, and spooled events expire after `spool.max_event_days` (default 365).

## 4. Repository layout

```
clamfleet/
├─ cmd/
│  ├─ clamfleet-agent/
│  └─ clamfleet-server/
├─ internal/
│  ├─ proto/      # shared JSON structs for reports and events
│  ├─ agent/      # collectors, spool, sender
│  ├─ store/      # store interface + sqlite implementation (sqlc)
│  ├─ health/     # rule evaluation and state machine
│  ├─ alert/      # email, webhook, cooldown, dedup
│  └─ web/        # handlers, templates, static (htmx vendored)
├─ migrations/    # goose, sqlite dialect
├─ deploy/        # systemd units, nfpm config, example configs
└─ docs/
```

## 5. Libraries

Prefer the standard library. Add a dependency only where listed.

| Need | Library |
| --- | --- |
| HTTP routing | `net/http` with Go 1.22+ route patterns |
| SQLite driver | `modernc.org/sqlite` (pure Go) |
| Query generation | `sqlc` |
| Migrations | `pressly/goose` |
| Templates | `html/template` |
| Front end | htmx, vendored and embedded, no build step |
| Email | `net/smtp` (stdlib) plus a small in-repo client layer (LOGIN auth, MIME). Decision: M4 decision 11. |
| Metrics | A small in-repo text exposition in the Prometheus format (M6 decision 6), no dependency |
| Config | YAML (`go.yaml.in/yaml/v3`, the maintained successor of `gopkg.in/yaml.v3`) with environment variable overrides |
| Logging | `log/slog`, JSON output |
| LDAP | `github.com/go-ldap/ldap/v3` (M6 decision 16) |
| OIDC | Standard library only: authorization code flow with PKCE, no JOSE library (M6 decision 17) |
| Release | `nfpm` (pinned, via `go run`) now, `goreleaser` in 6c |

## 6. Agent

### 6.1 Runtime

- Runs as a systemd service with an internal ticker. Default report interval: 5 minutes.
- Runs as user `clamfleet`, member of group `clamav`. Must not require root.
- Config file: `/etc/clamfleet/agent.yaml`.

### 6.2 Collectors

| Data | Method |
| --- | --- |
| clamd liveness, version, queue | Connect to the clamd unix socket (path from `clamd.conf` `LocalSocket`) and send `zPING`, `zVERSION`, `zSTATS`. Do not exec `clamdscan`. |
| Signature databases | Read the first 512 bytes of each `.cvd` or `.cld` file in the database directory (`daily`, `main`, `bytecode`). The header is colon-separated and contains build time, version and signature count. Do not depend on `sigtool`. |
| freshclam result | Parse the freshclam log for the last successful and last failed update. Fall back to the modification time of the database files. |
| Service state | `systemctl is-active` for `clamav-daemon`/`clamd`, `clamav-freshclam`/`freshclam`, and `clamonacc` if present. Unit names differ between Debian and RHEL families, so they must be configurable. |
| Scheduled scan result | Read a JSON summary file written by the scan wrapper (section 6.4). |
| Host metadata | Hostname, OS release, agent version, tags from config. |

### 6.3 Detection events

- clamd is configured with `VirusEvent /usr/bin/clamfleet-agent event`.
- The `event` subcommand reads `CLAM_VIRUSEVENT_FILENAME` and `CLAM_VIRUSEVENT_VIRUSNAME` from the environment and writes the event to the spool: never the network or the token. clamd waits for this local write (milliseconds normally; longer only on a stalled disk) and never for the server. It exits 0 when the event is spooled, and 1 with one line on stderr (clamd's journal) otherwise; clamd ignores the status. The main agent process sends spooled items. On AppArmor systems a profile ships for it (docs/detections.md).

### 6.4 Scan wrapper

- Subcommand `clamfleet-agent scan` runs `clamdscan` with configured paths and writes a summary (start, finish, exit code, files scanned, infected, errors) to `/var/lib/clamfleet/last_scan.json`.
- Scheduling is a systemd timer shipped disabled. The scan never starts clamd. `scanned` comes from clamdscan's per-file lines.

### 6.5 Spool

- Directory: `/var/lib/clamfleet/spool/`.
- One file per pending item. Two lanes: events (those younger than 1 minute first, then oldest first) and reports (the newest first, then history marked `replay`, paced). An item is published atomically without replacing (write, fsync, `link`, fsync of the directory) and deleted after a 2xx response; the server deduplicates on the event id. Items are untrusted input: the agent validates and re-encodes them before sending, and invalid ones go to a quarantine.
- A hard cap on real disk use (`spool.max_mb`). When full, drop the oldest heartbeats first, never detection events. Events expire by age (`spool.max_event_days`).

### 6.6 CLI

```
clamfleet-agent run            # service mode
clamfleet-agent event          # called by clamd VirusEvent
clamfleet-agent scan           # scan wrapper
clamfleet-agent collect --dry-run   # print report JSON, send nothing
clamfleet-agent version
```

## 7. API (v1)

All endpoints under `/v1/`. JSON over HTTPS.

### 7.1 Authentication

- v1: per-host bearer token. The server stores only a hash. Tokens are created by an administrator in the UI or by a server CLI command.
- Planned: mTLS client certificates from any CA the operator chooses. Code must keep authentication behind an interface so this can be added.

### 7.2 Endpoints

| Method and path | Purpose |
| --- | --- |
| `POST /v1/report` | Heartbeat with full current state |
| `POST /v1/event` | Single detection event |
| `GET /healthz` | Server liveness |
| `GET /metrics` | Prometheus metrics (fleet counts per state, per-host signature age, last seen). Off by default; when on, it needs a bearer token read from a file |

Responses: `202` on success, `400` on invalid payload, `401` on bad token. Unknown fields in payloads are ignored so that newer agents work with older servers.

### 7.3 Report payload

```json
{
  "schema": 1,
  "host": "app01",
  "agent_version": "0.1.0",
  "tags": ["web", "prod"],
  "ts": "2026-11-12T10:00:00Z",
  "os": {"id": "debian", "version": "12"},
  "clamd": {"up": true, "version": "1.4.1", "queue": 0, "error": null, "virus_event": "clamfleet"},
  "sigs": {
    "daily":    {"version": 27450, "built": "2026-11-12T07:21:00Z", "sigs": 2071234},
    "main":     {"version": 62,    "built": "2021-09-16T19:32:00Z", "sigs": 6647427},
    "bytecode": {"version": 335,   "built": "2024-04-01T08:00:00Z", "sigs": 86}
  },
  "freshclam": {"last_ok": "2026-11-12T08:00:00Z", "last_error": null, "last_error_msg": null},
  "services": {"clamd": "active", "freshclam": "active", "clamonacc": "inactive"},
  "last_scan": {"started": "...", "finished": "...", "exit": 0, "scanned": 120345, "infected": 0, "errors": 0},
  "replay": false
}
```

`virus_event` is `clamfleet`, `other`, `none` or `null`; `replay` is `true` for a heartbeat sent from the agent's backlog (the server stores it as history only). Both were added after schema 1 was written and are compatible (servers ignore unknown fields).

### 7.4 Event payload

```json
{
  "schema": 1,
  "id": "0123456789abcdef0123456789abcdef",
  "host": "app01",
  "ts": "2026-11-12T10:03:12Z",
  "path": "/srv/upload/file.zip",
  "signature": "Win.Test.EICAR_HDB-1",
  "source": "clamd"
}
```

`id` is the agent's idempotency key (32 lowercase hex characters, or `null`): a retry carries the same id. The agent sends `path` so that two different file names never become one string: a backslash as `\\`, a byte that is not valid UTF-8 as `\xNN` (docs/api.md).

## 8. Storage

### 8.1 SQLite settings

```
journal_mode=WAL
busy_timeout=5000
synchronous=NORMAL
foreign_keys=ON
```

- One connection for writes. A separate pool for reads.
- All access goes through a `store` interface in `internal/store`. Queries are portable SQL so a Postgres implementation can be added later.

### 8.2 Tables

| Table | Columns (key ones) | Retention |
| --- | --- | --- |
| `hosts` | id, name (unique), token_hash, first_seen, last_seen, state, state_reason, last_report (JSON text) | Until deleted by an administrator |
| `host_tags` | host_id, tag | With host |
| `reports` | id, host_id, ts, payload (JSON text) | `reports` 30 days (14 to 90) |
| `events` | id, host_id, ts, path, signature, ack_by, ack_at | Default 12 months |
| `state_changes` | id, host_id, ts, from_state, to_state, reason | 365 days (30 to 3650); never while an alert is pending |
| `alert_targets` | id, type (email or webhook), config (JSON), min_severity, tag_filter | Until deleted |
| `alert_log` | id, target_id, state_change_id or event_id, ts, status, error | 90 days (30 to 3650) |
| `audit_log` | id, ts, actor, action, target, detail | 365 days (90 to 3650) |
| `users` | Local, `ldap` and `oidc` sources; see section 10 | n/a |

The 12-month defaults for `events` and `state_changes` suit common audit and log-retention requirements. They must be configurable.

### 8.3 Maintenance

- Daily retention job deletes in batches (for example 5000 rows per statement) and runs `PRAGMA optimize` afterwards.
- Backup: a `backup` command using `VACUUM INTO` (with `--keep`), plus a timer that ships disabled, and an automatic backup before migrations. Restore steps are in docs/operations.md. Litestream support is documented, not built in.

## 9. Health evaluation

States, in order of severity: `OK`, `WARN`, `CRIT`, `STALE`. Detections are tracked separately as unacknowledged events, not as a host state.

| Rule | Result |
| --- | --- |
| No report for 3 × the agent interval | STALE |
| clamd not running or not answering PING | CRIT |
| freshclam service not active | WARN |
| `daily` build time older than 24 hours, or last freshclam run failed | WARN |
| `daily` build time older than 72 hours | CRIT |
| `daily` version more than 2 behind the newest version seen in the fleet | WARN |
| Scheduled scan configured and missed or exited with an error | WARN |
| `clamd.conf` has no `VirusEvent` line (`virus_event` is `none`) | WARN, configurable (`health.require_virus_event`) |

- All thresholds are configurable.
- The host state is the most severe matching rule. `state_reason` lists every matching rule.
- Evaluation runs on every report and in a background loop every 60 seconds (needed to detect STALE).
- Each transition writes one row to `state_changes`.

## 10. Web UI

Server-rendered HTML with htmx. No JavaScript build step.

| Page | Content |
| --- | --- |
| Fleet | Table of hosts: name, tags, state, reason, last seen, clamd version, daily version and age. Filter by tag and state. Refreshes the table body every 15 seconds via `hx-trigger="every 15s"`. |
| Host detail | Current report, state history, recent events, signature age over time. |
| Events | Detections list, filter by host, signature, acknowledged. Admins acknowledge per row (`hx-post`), or "all matching as of this id". |
| Alert targets | Create, edit, test, delete targets. |
| Hosts admin | Register host, rotate token, delete host. |

Authentication: one config subtree per provider (M3 decision 3), several on at once.

- `local`: built-in accounts with argon2id passwords, created by a server CLI command. Default, so the project works with no external identity system. TOTP applies to local accounts only.
- `ldap`: one directory, search then bind (works with OpenLDAP; Active Directory is documented and untested). The login form takes an email or a user name; a local account with that exact email is tried first.
- `oidc`: one OpenID Connect provider, by a button that starts an authorization code flow with PKCE.

Two roles: `viewer` (read only) and `admin`. For `ldap` and `oidc`, the role is mapped from group membership or a claim at every sign-in, and a user with no matching group has no access. External accounts are created at first sign-in and are never linked to a local account. See docs/auth.md.

## 12. Configuration

Server, `/etc/clamfleet/server.yaml`:

```yaml
listen: ":8443"
tls: {cert: /etc/clamfleet/tls.crt, key: /etc/clamfleet/tls.key}
db_path: /var/lib/clamfleet/clamfleet.db
retention: {reports_days: 30, events_days: 365, state_changes_days: 365, alert_log_days: 90, audit_days: 365}
backup: {dir: /var/lib/clamfleet-server/backups, keep: 7}
metrics: {enabled: false, token_file: /etc/clamfleet/metrics.token}
health: {stale_factor: 3, daily_warn_hours: 24, daily_crit_hours: 72, behind_warn: 2}
public_url: https://clamfleet.example   # links in alerts
alert: {cooldown: 15m, webhook: {timeout: 10s, allow_private: true, allow_loopback: false}}
smtp: {host: smtp.example, port: 587, tls: starttls, from: clamfleet@example, username: clamfleet, password_file: /etc/clamfleet/smtp.pass}
auth: {local: {enabled: true}, ldap: {enabled: false}, oidc: {enabled: false}}   # one subtree per provider; every key is in docs/configuration.md and docs/auth.md
```

Agent, `/etc/clamfleet/agent.yaml`:

```yaml
server: https://clamfleet.example:8443
token_file: /etc/clamfleet/token
interval: 5m
tags: [prod]
clamd_conf: /etc/clamav/clamd.conf
db_dir: /var/lib/clamav
freshclam_log: /var/log/clamav/freshclam.log
units: {clamd: clamav-daemon, freshclam: clamav-freshclam, clamonacc: clamav-clamonacc}
spool: {dir: /var/lib/clamfleet/spool, max_mb: 50, max_event_days: 365}   # set in the file: the event command, run by clamd, cannot see the environment
scan: {paths: [/srv, /home], summary: /var/lib/clamfleet/last_scan.json}
```

Every setting can be overridden by an environment variable (`CLAMFLEET_` prefix).

## 13. Non-functional requirements

- Server handles 100 agents at a 5-minute interval on 1 vCPU and 512 MB RAM.
- Agent resident memory under 30 MB. Agent CPU negligible between reports.
- TLS 1.2 minimum on every connection to a public address. Plaintext is allowed only to loopback and private addresses (the reverse proxy in front of the server, alert receivers, an SMTP relay), and the console marks such alert targets as unencrypted. Tokens and secrets never logged.
- Structured JSON logs. Security-relevant actions (login, token change, acknowledgement, alert target change) logged with the acting user.
- The server keeps working and keeps alerting if SMTP or a webhook target is down.

## 14. Milestones and acceptance criteria

| # | Deliverable | Done when |
| --- | --- | --- |
| 1 | `internal/proto`, agent collectors, `collect --dry-run` | Dry run prints a valid report on Debian 12 and RHEL 9 with ClamAV installed. Unit tests parse real CVD and CLD headers and a recorded clamd socket session. |
| 2 | Server ingest API, SQLite schema, migrations, token auth | Agent reports are stored. Bad token returns 401. Unknown payload fields are accepted. |
| 3 | Health evaluator, `state_changes`, fleet page | Stopping clamd turns the host CRIT within one interval. Stopping the agent turns it STALE after 3 intervals. |
| 4 | Email and webhook alerting | Each transition yields at most one logical alert per target (changes within the cooldown are coalesced into one); a recovery alert is sent; the cooldown is respected; delivery is at least once (receivers deduplicate on the alert id); every attempt and every failure is recorded in `alert_log`. |
| 5 | Detection events, spool, events page, acknowledgement | An EICAR test file produces an alert within 30 seconds under the conditions of docs/detections.md, on Debian 13 with AppArmor enforcing (`make e2e-apparmor`) and in the ClamAV container. The event survives server downtime via the spool. RHEL 9 and SELinux are verified in milestone 6. |
| 6 | Split into 6a (packaging, retention, backup, `/metrics`, TLS reload, `clamfleet-agent scan` and its timer), 6b (LDAP and OIDC sign-in) and 6c (CI and releases) | .deb and .rpm install and start cleanly. Old rows are removed per config. Verified on Debian 13 (container and AppArmor VM) and AlmaLinux 9 with SELinux enforcing. |

General requirements for every milestone:

- `go vet` and `staticcheck` pass.
- Unit tests for parsers, health rules and alert logic.
- Integration test using a ClamAV container.
- README updated with build, install and configuration steps.

## 15a. Open source project requirements

- Public repository with `README.md`, `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md` (private vulnerability reporting) and `CHANGELOG.md`.
- CI on every pull request (GitHub Actions or equivalent): build, `go vet`, `staticcheck`, unit tests, integration test with a ClamAV container.
- Releases built by `goreleaser` from signed tags, with checksums and SBOM. Semantic versioning.
- Issue and pull request templates. Contributions require passing CI and one maintainer review.
- No organisation-specific names, hostnames or defaults anywhere in code, configs or docs. Examples use `example.com`/`.example`.
- Payload schemas (section 7) and config keys are public interfaces. Breaking changes need a major version bump and a migration note.
- Documentation in `docs/`: install, agent setup per distribution, configuration reference, API reference, alert payload reference, upgrade notes.

## 15. Open questions

Questions 1, 3, 4 and 5 are decided (marked below). Question 2, the final project name, is still open: the agent must ask before implementing anything that depends on it.

1. Decided: AGPL-3.0-only (see `LICENSE`).
2. Final project name. Open until the maintainer confirms "ClamFleet". Name check of 2026-11-16 (a search, not legal advice):
   - GitHub: no other repository or organisation named "clamfleet" besides this project's own.
   - Go, PyPI, npm, crates.io and RubyGems: no package of that name. The Docker Hub namespace `clamfleet` exists and holds no repository.
   - Debian, Ubuntu, Fedora and Alpine package indexes, and release-monitoring.org: no package or project of that name.
   - Domains clamfleet.com, .org, .net, .io and .dev: all five unregistered (RDAP answered not found).
   - Trademark: ClamAV is marked as a registered trademark (Cisco) on clamav.net and in the ClamAV README. The name contains "Clam" but not "ClamAV"; the README carries a "not affiliated with or endorsed by Cisco" notice. Whether the name is acceptable is the maintainer's judgement. No published ClamAV trademark policy was found on clamav.net or in its repository.
3. Decided (M4 decision 17): not in v1; webhook JSON to a collector, and one JSON log line per alert for journald forwarders.
4. Decided (M6 decision 13): no container image in v1.
5. Decided: Debian 13 and the RHEL 9 family (tested on AlmaLinux 9); Debian 12 is untested (M6 decision 12).

## 16. Instructions for the implementing agent

- Work milestone by milestone. Stop after each one, summarise what was built and how it was tested, and wait for review.
- Do not add dependencies beyond section 5 without asking.
- Do not change the payload schemas in section 7 without asking. If a change is needed, bump `schema` and keep the server accepting the old version.
- Mark any assumption in code comments and in the milestone summary.
