<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Configuration reference

Every key of both programs, with its default, range and environment variable. The YAML key names and the
environment names are public interface. A test compares the environment names in this file with the ones the
programs derive from their configuration, so a key that is added without a row here fails the build.

Both programs read a YAML file (decoded strictly: an unknown key is an error) and then the environment, which wins.
Environment names are the prefix plus the key path upper-cased, nested keys joined by `_`; a list is
comma-separated; a duration is `30s`, `5m`, `12h`. The server's prefix is `CLAMFLEET_SERVER_`, the agent's
`CLAMFLEET_AGENT_`; each ignores the other's variables. Secrets (the SMTP password, the metrics token, the key file)
live in files with the key-file permission rule (not readable by others), never in YAML or the environment.

## Server (`/etc/clamfleet/server.yaml`)

| Key | Environment | Default | Range and notes |
|---|---|---|---|
| `listen` | `CLAMFLEET_SERVER_LISTEN` | `127.0.0.1:8443` | Without TLS it must be loopback. |
| `tls.cert` | `CLAMFLEET_SERVER_TLS_CERT` | empty | Absolute path; with `tls.key`. `systemctl reload` re-reads it. |
| `tls.key` | `CLAMFLEET_SERVER_TLS_KEY` | empty | |
| `tls.client_ca` | `CLAMFLEET_SERVER_TLS_CLIENT_CA` | empty | Turns on mTLS; needs `tls.cert`. |
| `db_path` | `CLAMFLEET_SERVER_DB_PATH` | `/var/lib/clamfleet-server/clamfleet.db` | Absolute. |
| `trusted_proxies` | `CLAMFLEET_SERVER_TRUSTED_PROXIES` | empty | IPs or CIDRs whose `X-Forwarded-For` is believed. |
| `secret_key_file` | `CLAMFLEET_SERVER_SECRET_KEY_FILE` | `/etc/clamfleet/server-secret.key` | `root:clamfleet-server 0640`. |
| `public_url` | `CLAMFLEET_SERVER_PUBLIC_URL` | empty | Links in alerts; no path prefix. |
| `health.stale_factor` | `CLAMFLEET_SERVER_HEALTH_STALE_FACTOR` | `3` | At least 2. |
| `health.default_interval` | `CLAMFLEET_SERVER_HEALTH_DEFAULT_INTERVAL` | `5m` | 10s to 24h. |
| `health.daily_warn_hours` | `CLAMFLEET_SERVER_HEALTH_DAILY_WARN_HOURS` | `24` | At least 1. |
| `health.daily_crit_hours` | `CLAMFLEET_SERVER_HEALTH_DAILY_CRIT_HOURS` | `72` | Greater than the warn value. |
| `health.behind_warn` | `CLAMFLEET_SERVER_HEALTH_BEHIND_WARN` | `2` | 0 or more. |
| `health.scan_warn_hours` | `CLAMFLEET_SERVER_HEALTH_SCAN_WARN_HOURS` | `48` | 0 switches the rule off. |
| `health.eval_interval` | `CLAMFLEET_SERVER_HEALTH_EVAL_INTERVAL` | `60s` | 1s to 60s. |
| `health.require_virus_event` | `CLAMFLEET_SERVER_HEALTH_REQUIRE_VIRUS_EVENT` | `true` | WARN when clamd.conf has no `VirusEvent`. |
| `auth.local.enabled` | `CLAMFLEET_SERVER_AUTH_LOCAL_ENABLED` | `true` | Email and password accounts. |
| `auth.local.totp_required` | `CLAMFLEET_SERVER_AUTH_LOCAL_TOTP_REQUIRED` | `false` | Needs the key file. |
| `auth.session_max_age` | `CLAMFLEET_SERVER_AUTH_SESSION_MAX_AGE` | `12h` | At most 720h. |
| `auth.session_idle` | `CLAMFLEET_SERVER_AUTH_SESSION_IDLE` | `1h` | At least 1m, not above the max age. |
| `auth.cookie_secure` | `CLAMFLEET_SERVER_AUTH_COOKIE_SECURE` | `true` | `false` only for plain-HTTP development. |
| `alert.cooldown` | `CLAMFLEET_SERVER_ALERT_COOLDOWN` | `15m` | 0 to 24h; 0 = no holds. |
| `alert.webhook.timeout` | `CLAMFLEET_SERVER_ALERT_WEBHOOK_TIMEOUT` | `10s` | 1s to 30s. |
| `alert.webhook.allow_private` | `CLAMFLEET_SERVER_ALERT_WEBHOOK_ALLOW_PRIVATE` | `true` | RFC 1918, CGNAT, fc00::/7. |
| `alert.webhook.allow_loopback` | `CLAMFLEET_SERVER_ALERT_WEBHOOK_ALLOW_LOOPBACK` | `false` | |
| `alert.webhook.deny_networks` | `CLAMFLEET_SERVER_ALERT_WEBHOOK_DENY_NETWORKS` | empty | CIDRs; matched against the address and the IPv4 inside it. |
| `alert.webhook.nat64_prefixes` | `CLAMFLEET_SERVER_ALERT_WEBHOOK_NAT64_PREFIXES` | empty | IPv6 prefixes of length /32, /40, /48, /56, /64 or /96. Also governs the SMTP relay. |
| `alert.webhook.ca_file` | `CLAMFLEET_SERVER_ALERT_WEBHOOK_CA_FILE` | empty | Extra trust anchors (PEM). |
| `smtp.host` | `CLAMFLEET_SERVER_SMTP_HOST` | empty | Empty switches email off. |
| `smtp.port` | `CLAMFLEET_SERVER_SMTP_PORT` | `587` | 1 to 65535. |
| `smtp.tls` | `CLAMFLEET_SERVER_SMTP_TLS` | `starttls` | `starttls`, `tls` or `none` (loopback or private relays only). |
| `smtp.from` | `CLAMFLEET_SERVER_SMTP_FROM` | empty | Required with `smtp.host`. |
| `smtp.username` | `CLAMFLEET_SERVER_SMTP_USERNAME` | empty | Needs `smtp.password_file`. |
| `smtp.password_file` | `CLAMFLEET_SERVER_SMTP_PASSWORD_FILE` | empty | Key-file permission rule. |
| `smtp.helo` | `CLAMFLEET_SERVER_SMTP_HELO` | empty | Default: the host of `public_url`, then the host name. |
| `smtp.ca_file` | `CLAMFLEET_SERVER_SMTP_CA_FILE` | empty | |
| `smtp.timeout` | `CLAMFLEET_SERVER_SMTP_TIMEOUT` | `30s` | 5s to 120s. |
| `retention.reports_days` | `CLAMFLEET_SERVER_RETENTION_REPORTS_DAYS` | `30` | 14 to 90. |
| `retention.events_days` | `CLAMFLEET_SERVER_RETENTION_EVENTS_DAYS` | `365` | 7 to 3650. |
| `retention.state_changes_days` | `CLAMFLEET_SERVER_RETENTION_STATE_CHANGES_DAYS` | `365` | 30 to 3650. |
| `retention.alert_log_days` | `CLAMFLEET_SERVER_RETENTION_ALERT_LOG_DAYS` | `90` | 30 to 3650. |
| `retention.audit_days` | `CLAMFLEET_SERVER_RETENTION_AUDIT_DAYS` | `365` | 90 to 3650. |
| `backup.dir` | `CLAMFLEET_SERVER_BACKUP_DIR` | `/var/lib/clamfleet-server/backups` | Absolute; a real directory, mode 0700, owned by the server user. |
| `backup.keep` | `CLAMFLEET_SERVER_BACKUP_KEEP` | `7` | 0 to 365; 0 keeps every backup. |
| `metrics.enabled` | `CLAMFLEET_SERVER_METRICS_ENABLED` | `false` | Off: `GET /metrics` is a 404. |
| `metrics.token_file` | `CLAMFLEET_SERVER_METRICS_TOKEN_FILE` | empty | Required when enabled; at least 32 bytes. |

## Agent (`/etc/clamfleet/agent.yaml`)

| Key | Environment | Default | Range and notes |
|---|---|---|---|
| `server` | `CLAMFLEET_AGENT_SERVER` | empty | `https://host[:port][/prefix]`; http only to a loopback host. Required to send. |
| `token_file` | `CLAMFLEET_AGENT_TOKEN_FILE` | `/etc/clamfleet/token` | Read on every send; keep it `root:clamfleet 0640`. |
| `tls.client_cert` | `CLAMFLEET_AGENT_TLS_CLIENT_CERT` | empty | With `tls.client_key`, for a server that requires mTLS. |
| `tls.client_key` | `CLAMFLEET_AGENT_TLS_CLIENT_KEY` | empty | |
| `interval` | `CLAMFLEET_AGENT_INTERVAL` | `5m` | Positive; the server clamps it to at least 10s. |
| `tags` | `CLAMFLEET_AGENT_TAGS` | `[]` | Reported, not authenticated. |
| `clamd_conf` | `CLAMFLEET_AGENT_CLAMD_CONF` | `/etc/clamav/clamd.conf` | RHEL family: `/etc/clamd.d/scan.conf`. |
| `db_dir` | `CLAMFLEET_AGENT_DB_DIR` | `/var/lib/clamav` | |
| `freshclam_log` | `CLAMFLEET_AGENT_FRESHCLAM_LOG` | `/var/log/clamav/freshclam.log` | |
| `units.clamd` | `CLAMFLEET_AGENT_UNITS_CLAMD` | `clamav-daemon` | RHEL family: `clamd@scan`. Empty = not systemd-managed. |
| `units.freshclam` | `CLAMFLEET_AGENT_UNITS_FRESHCLAM` | `clamav-freshclam` | |
| `units.clamonacc` | `CLAMFLEET_AGENT_UNITS_CLAMONACC` | `clamav-clamonacc` | |
| `spool.dir` | `CLAMFLEET_AGENT_SPOOL_DIR` | `/var/lib/clamfleet/spool` | **Set in the file, not the environment**: the event command cannot see the environment. |
| `spool.max_mb` | `CLAMFLEET_AGENT_SPOOL_MAX_MB` | `50` | 1 to 10240; file only. |
| `spool.max_event_days` | `CLAMFLEET_AGENT_SPOOL_MAX_EVENT_DAYS` | `365` | 30 to 3650; file only. |
| `scan.paths` | `CLAMFLEET_AGENT_SCAN_PATHS` | `[]` | Absolute paths for `clamfleet-agent scan`. |
| `scan.summary` | `CLAMFLEET_AGENT_SCAN_SUMMARY` | `/var/lib/clamfleet/last_scan.json` | Written atomically by `scan`. |
| `scan.timeout` | `CLAMFLEET_AGENT_SCAN_TIMEOUT` | `12h` | 1m to 72h. A scan that runs longer is stopped and recorded with exit 2. |

`scan` records `scanned: 0`, meaning "not reported by clamdscan": `clamdscan --multiscan` prints one `OK` line per
clean path argument, not one per file, and its summary has no file count.
