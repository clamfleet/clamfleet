<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Operating the server

## Retention

One daily pass (at start, then every 24 hours) prunes every table in batches of 5000 rows (one transaction per
batch, so ingest interleaves), then runs `PRAGMA optimize`. Everything counts from **arrival** on the server's
clock, never from the agent's clock.

| Key | Default | Range | What goes |
|---|---|---|---|
| `retention.reports_days` | 30 | 14-90 | heartbeat reports (the fleet page does not depend on them) |
| `retention.events_days` | 365 | 7-3650 | detections, with their receipts, window membership and alert rows |
| `retention.state_changes_days` | 365 | 30-3650 | health state history and its alert rows |
| `retention.alert_log_days` | 90 | 30-3650 | the alert attempt log, finished deliveries, closed detection windows |
| `retention.audit_days` | 365 | 90-3650 | the audit log (emails and client IPs are personal data) |

**A row whose alert is still unfinished is kept.** An event or state change whose alert is not yet planned, whose
delivery has no `finished_at`, or that belongs to a detection window that is still open, survives the prune; the
next pass after the alert finishes removes it. An alerting outage longer than the retention can therefore not eat
its own backlog.

Sessions, login challenges and the like expire on their own (an hourly cleanup).

**The first prune after an upgrade** can delete hundreds of thousands of `reports` rows (they were kept from
milestone 2 on). It runs in batches and logs counts (never a path). **The file does not shrink.** To reclaim the
space, `clamfleet-server backup` writes a compact copy (`VACUUM INTO`), or stop the server, `VACUUM` and start it.

## Backup and restore

```
sudo -u clamfleet-server clamfleet-server backup [--dir DIR] [--keep N] [--verify]
```

writes a consistent copy of the database while the server runs (`VACUUM INTO`) and prints its path, and only
that, on stdout. `backup.dir` (default `/var/lib/clamfleet-server/backups`) must be a real directory, `0700`, owned
by the user running the backup; it is created if missing. `backup.keep` (default 7, 0 = keep every backup) bounds
the regular backups. `--verify` opens the copy and checks `integrity_check` and the schema version. A lock stops
two backups from running at once, and a failure before publication leaves neither a final nor a temporary file.

**A `backup.dir` outside `/var/lib/clamfleet-server` is read-only for the packaged units** (`ProtectSystem=strict`
makes the state directory the only writable place). Without a drop-in the daily backup fails and so does the
backup before a migration, so the next upgrade that brings one ends in a restart loop. Add the directory to both
services (and keep it `0700`, owned by `clamfleet-server`):

```
# systemctl edit clamfleet-server        and        systemctl edit clamfleet-server-backup
[Service]
ReadWritePaths=/srv/clamfleet-backups
```

The server logs a warning at start (and `backup` logs it) when `backup.dir` is outside the state directory.

`clamfleet-server-backup.timer` runs `backup --verify` daily (`RandomizedDelaySec=1h`, `Persistent=true`) and ships
**disabled**: `systemctl enable --now clamfleet-server-backup.timer`.

- **What a backup holds:** every row, including detection paths beyond `retention.events_days`, sealed secrets and
  password hashes. Keep it as private as the database and give it a retention that matches your data retention
  (GDPR). **It does not hold the key file**: back up `/etc/clamfleet/server-secret.key` separately.
- The default directory is on the same disk: it protects against mistakes and corruption, not against losing the
  disk. Copy backups off the host.

### Backup before a migration

`serve` and `migrate` write `pre-migrate-v<from>-to-v<to>-<stamp>.db` into `backup.dir` before applying any pending
migration to an existing database (verified, the newest 3 kept; free disk space of 1.1 times the database is required).
**If the backup fails, the migration does not run** and neither does any retention prune. Fix the cause, or run
`clamfleet-server migrate --no-backup` once and then start the server (`serve` has no such flag).

### Restore

Migrations only move forward and an older binary refuses a newer database, so restore with the same or a newer binary.

```
systemctl stop clamfleet-server
install -o clamfleet-server -g clamfleet-server -m 0600 /path/to/backup.db /var/lib/clamfleet-server/clamfleet.db
rm -f /var/lib/clamfleet-server/clamfleet.db-wal /var/lib/clamfleet-server/clamfleet.db-shm
systemctl start clamfleet-server
```

The `-wal` and `-shm` files belong to the replaced database and must go. This procedure is run for real by
`TestRestoreFromBackup`.

## Metrics

`GET /metrics` in the Prometheus text format, **off by default** (404). Set `metrics.enabled: true` and
`metrics.token_file` (a file with at least 32 bytes, `root:clamfleet-server 0640`; `openssl rand -base64 48`). The
page lists every host, so a bearer token is required: a wrong or missing one gets 401 and a warn line with the client
address, never the header. Exported: hosts per state, one state series per host, last-seen time, signature age per
database (`daily`, `main`, `bytecode`), open detections, alert deliveries (`pending`, `retrying`, `failed` within
`retention.alert_log_days`) and the build version. **Never** a path, a signature or a tag.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: clamfleet
    scheme: https
    authorization:
      credentials_file: /etc/prometheus/clamfleet-token
    static_configs: [{targets: ['clamfleet.example:443']}]
```

## TLS reload

With `tls.cert` and `tls.key` set, `systemctl reload clamfleet-server` (SIGHUP) re-reads `tls.cert`, `tls.key` and
`tls.client_ca`. It is all or nothing: a key that does not match, a CA file without a certificate or a deleted file
logs an error and keeps the previous certificate and CA. On success the new expiry and serial are logged.

- Adding or removing `tls.client_ca` in the configuration changes the listener's mode: restart the server.
- Under mTLS session tickets are off, so every connection is a full handshake against the current CA.
- **Connections already open keep the handshake they made** for up to 120 s of idleness. A client certificate that was
  revoked stays usable on such a connection until then; restart for an immediate cut.

## Upgrade order

Server first, then agents. The upgrade notes of each release are in the [changelog](../CHANGELOG.md).
