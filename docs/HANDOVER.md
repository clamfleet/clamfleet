<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# ClamFleet: Specification and Handover

Central management and reporting for ClamAV on Linux servers.

| Field | Value |
| --- | --- |
| Status | Design agreed, implementation not started |
| Project type | Open source, public repository, community contributions expected |
| Maintainer | Gabriel |
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
- If the server is unreachable, the agent spools reports and events to disk and retries. No data loss on server downtime.

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
| Email | `wneessen/go-mail` |
| Metrics | `prometheus/client_golang` |
| Config | YAML (`gopkg.in/yaml.v3`) with environment variable overrides |
| Logging | `log/slog`, JSON output |
| Release | `goreleaser` with `nfpm` |

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
- The `event` subcommand reads `CLAM_VIRUSEVENT_FILENAME` and `CLAM_VIRUSEVENT_VIRUSNAME` from the environment and POSTs to `/v1/event`.
- It must finish quickly and never block clamd. On failure it writes the event to the spool directory and exits 0. The main agent process sends spooled items.

### 6.4 Scan wrapper

- Subcommand `clamfleet-agent scan` runs `clamdscan` with configured paths and writes a summary (start, finish, exit code, files scanned, infected, errors) to `/var/lib/clamfleet/last_scan.json`.
- Scheduling is done by a systemd timer shipped in the package and disabled by default.

### 6.5 Spool

- Directory: `/var/lib/clamfleet/spool/`.
- One file per pending item, sent oldest first, deleted after a 2xx response.
- Size cap configurable. When full, drop the oldest heartbeats first, never detection events.

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
| `GET /metrics` | Prometheus metrics (fleet counts per state, per-host signature age, last seen) |

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
  "clamd": {"up": true, "version": "1.4.1", "queue": 0, "error": null},
  "sigs": {
    "daily":    {"version": 27450, "built": "2026-11-12T07:21:00Z", "sigs": 2071234},
    "main":     {"version": 62,    "built": "2021-09-16T19:32:00Z", "sigs": 6647427},
    "bytecode": {"version": 335,   "built": "2024-04-01T08:00:00Z", "sigs": 86}
  },
  "freshclam": {"last_ok": "2026-11-12T08:00:00Z", "last_error": null, "last_error_msg": null},
  "services": {"clamd": "active", "freshclam": "active", "clamonacc": "inactive"},
  "last_scan": {"started": "...", "finished": "...", "exit": 0, "scanned": 120345, "infected": 0, "errors": 0}
}
```

### 7.4 Event payload

```json
{
  "schema": 1,
  "host": "app01",
  "ts": "2026-11-12T10:03:12Z",
  "path": "/srv/upload/file.zip",
  "signature": "Win.Test.EICAR_HDB-1",
  "source": "clamd"
}
```

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
| `reports` | id, host_id, ts, payload (JSON text) | Configurable, default 30 days, range 14 to 90 |
| `events` | id, host_id, ts, path, signature, ack_by, ack_at | Default 12 months |
| `state_changes` | id, host_id, ts, from_state, to_state, reason | Default 12 months |
| `alert_targets` | id, type (email or webhook), config (JSON), min_severity, tag_filter | Until deleted |
| `alert_log` | id, target_id, state_change_id or event_id, ts, status, error | 90 days |
| `users` | Only if local accounts are added; see section 10 | n/a |

The 12-month defaults for `events` and `state_changes` suit common audit and log-retention requirements. They must be configurable.

### 8.3 Maintenance

- Daily retention job deletes in batches (for example 5000 rows per statement) and runs `PRAGMA optimize` afterwards.
- Backup: CLI command and optional daily job using `VACUUM INTO '<path>'`. Litestream support is documented, not built in.

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
| Events | Detections list, filter by host, signature, acknowledged. Acknowledge action via `hx-post`. |
| Alert targets | Create, edit, test, delete targets. |
| Hosts admin | Register host, rotate token, delete host. |

Authentication: pluggable, with three modes selected in config.

- `local`: built-in accounts with bcrypt passwords, created by a server CLI command. Default, so the project works with no external identity system.
- `ldap`: LDAP bind (works with Active Directory, OpenLDAP, FreeIPA).
- `oidc`: any OpenID Connect provider.

Two roles: `viewer` (read only) and `admin`. For `ldap` and `oidc`, roles are mapped from group membership or a claim, set in config.

## 11. Alerting

- Sources: rows in `state_changes` and new rows in `events`.
- Alerts fire on transitions only, including recovery to OK.
- Cooldown per host and target, default 15 minutes, so a flapping host does not flood targets. Detection events are never suppressed.
- Each target has a minimum severity and an optional tag filter.
- Email: SMTP with STARTTLS. Plain text body.
- Webhook: HTTP POST with JSON payload below. Optional HMAC-SHA256 signature header using a per-target secret. Retry with exponential backoff, up to 5 attempts. Every attempt is written to `alert_log`.

```json
{
  "kind": "state_change",
  "host": "app01",
  "tags": ["web", "prod"],
  "from": "OK",
  "to": "CRIT",
  "reason": ["clamd not responding"],
  "ts": "2026-11-12T10:05:00Z",
  "url": "https://clamfleet.example/hosts/app01"
}
```

For detections, `kind` is `detection` and the payload carries `path` and `signature` instead of `from`, `to` and `reason`.

## 12. Configuration

Server, `/etc/clamfleet/server.yaml`:

```yaml
listen: ":8443"
tls: {cert: /etc/clamfleet/tls.crt, key: /etc/clamfleet/tls.key}
db_path: /var/lib/clamfleet/clamfleet.db
retention: {reports_days: 30, events_days: 365, state_changes_days: 365}
health: {stale_factor: 3, daily_warn_hours: 24, daily_crit_hours: 72, behind_warn: 2}
alert: {cooldown: 15m}
smtp: {host: smtp.example, port: 587, from: clamfleet@example}
auth: {mode: local}   # or ldap / oidc, see section 10
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
spool: {dir: /var/lib/clamfleet/spool, max_mb: 50}
scan: {paths: [/srv, /home], summary: /var/lib/clamfleet/last_scan.json}
```

Every setting can be overridden by an environment variable (`CLAMFLEET_` prefix).

## 13. Non-functional requirements

- Server handles 100 agents at a 5-minute interval on 1 vCPU and 512 MB RAM.
- Agent resident memory under 30 MB. Agent CPU negligible between reports.
- TLS 1.2 minimum on all connections. Tokens and secrets never logged.
- Structured JSON logs. Security-relevant actions (login, token change, acknowledgement, alert target change) logged with the acting user.
- The server keeps working and keeps alerting if SMTP or a webhook target is down.

## 14. Milestones and acceptance criteria

| # | Deliverable | Done when |
| --- | --- | --- |
| 1 | `internal/proto`, agent collectors, `collect --dry-run` | Dry run prints a valid report on Debian 12 and RHEL 9 with ClamAV installed. Unit tests parse real CVD and CLD headers and a recorded clamd socket session. |
| 2 | Server ingest API, SQLite schema, migrations, token auth | Agent reports are stored. Bad token returns 401. Unknown payload fields are accepted. |
| 3 | Health evaluator, `state_changes`, fleet page | Stopping clamd turns the host CRIT within one interval. Stopping the agent turns it STALE after 3 intervals. |
| 4 | Email and webhook alerting | One alert per transition, recovery alert sent, cooldown respected, failures recorded in `alert_log`. |
| 5 | Detection events, spool, events page, acknowledgement | EICAR test file produces an alert within 30 seconds. Event survives server downtime via spool. |
| 6 | Packaging, LDAP and OIDC login, `/metrics`, retention job, backup command | .deb and .rpm install and start cleanly. Old rows are removed per config. |

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

These are not decided. The agent must ask before implementing anything that depends on them.

1. Licence: Apache-2.0 or MIT (permissive), or GPL-2.0 (matches ClamAV itself). Must be decided before the first public commit.
2. Final project name. Check for conflicts on GitHub, package registries and the ClamAV trademark before publishing.
3. Whether to add syslog or SIEM forwarding (for example CEF or JSON over syslog) as a built-in alert target.
4. Whether to support a container image for the server in v1, in addition to .deb and .rpm.
5. Supported distribution list for the agent beyond Debian 12 and RHEL 9.

## 16. Instructions for the implementing agent

- Work milestone by milestone. Stop after each one, summarise what was built and how it was tested, and wait for review.
- Do not add dependencies beyond section 5 without asking.
- Do not change the payload schemas in section 7 without asking. If a change is needed, bump `schema` and keep the server accepting the old version.
- Mark any assumption in code comments and in the milestone summary.
