<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# ClamFleet

Central management and reporting for ClamAV on Linux servers. ClamAV has no central console.
ClamFleet adds one: a small agent on each server reports ClamAV health, signature freshness and
detections to a central server. The design is in [docs/HANDOVER.md](docs/HANDOVER.md).

ClamAV is a registered trademark of Cisco Systems, Inc.; ClamFleet is not affiliated with or endorsed by Cisco.

**Status: early development, not production ready.** Milestones 1 and 2 exist: the agent collects
its report and sends it to a server, which authenticates the agent and stores the report in SQLite.
There is no web interface, no health evaluation and no alerting yet, and no packages.

## Who it is for

Administrators of small to medium Linux fleets (the target is 50 to 100 servers) who run ClamAV and
want one place to see whether it is running, whether its signatures are current, and whether it has
found anything.

## What works today

- `clamfleet-agent collect --dry-run` prints the report JSON to stdout and sends nothing. The report covers:
  - clamd: whether it answers, its version and its queue length
  - signature databases (daily, main, bytecode): version, build time and signature count
  - freshclam: last successful and last failed update, from the systemd journal, the log file, or as a last resort the database file times
  - systemd state of the clamd, freshclam and clamonacc units
  - host name, OS release, agent version and configured tags
  - the last scan summary, if a summary file exists (the scan command itself is planned)
- `clamfleet-agent run` sends a report now and then every `interval` (default 5 minutes);
  `run --once` sends one and exits 0 on success, 1 otherwise. There is no spool yet: a failed send is
  logged and the next interval tries again.
- `clamfleet-agent version`
- Configuration from a YAML file, with `CLAMFLEET_AGENT_*` environment overrides.
- `clamfleet-server serve` runs the ingest API (`POST /v1/report`, `POST /v1/event`, `GET /healthz`,
  see [docs/api.md](docs/api.md)) on SQLite. Agents authenticate with one bearer token per host;
  optional mutual TLS adds a client-certificate requirement.
- `clamfleet-server host add|list|show|rotate-token|revoke-token` manages hosts and their tokens,
  and every token change is written to an audit log. `clamfleet-server migrate` creates or upgrades
  the database.
- Configuration of the server from a YAML file, with `CLAMFLEET_SERVER_*` environment overrides.

A data source that cannot be read does not fail the report. It appears as `null`, and a warning goes
to stderr.

## Requirements

- **Go 1.27.4.** `go.mod` declares `go 1.26.0` and `toolchain go1.27.4`. With the default
  `GOTOOLCHAIN=auto`, the go command downloads the pinned toolchain if your installed Go is older.
- **GNU make.**
- **staticcheck v0.8.2** for `make check`:
  `go install honnef.co/go/tools/cmd/staticcheck@v0.8.2`
- **sqlc v1.31.1** for `make check` (`sqlc diff`) and `make generate`; build time only, nothing of it
  is in the binaries: `CGO_ENABLED=0 go install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1`
- **To run the agent:** Debian 13 with ClamAV, clamd and freshclam under systemd. See
  [Supported platforms](#supported-platforms).

## Build and test

```
make build      # static binaries bin/clamfleet-agent and bin/clamfleet-server (CGO_ENABLED=0)
make check      # go vet, staticcheck, sqlc diff, go test ./..., script tests; no container needed
make generate   # regenerate internal/store/sqlite/sqlcdb after changing a migration or query
make e2e        # end-to-end tests inside a ClamAV container; needs setup
```

`make e2e` runs the real agent and server binaries in an Incus container as unprivileged users. It
needs a prepared container and two settings that have no defaults (`CFT_EXEC` and `INCUS_HOST`). If
they are missing, it fails rather than skipping. Read [docs/testing.md](docs/testing.md) first.

## Try the dry run

The agent needs to read the clamd socket and the systemd journal. Create an unprivileged user for it:

```
useradd --system --no-create-home --shell /usr/sbin/nologin clamfleet
usermod -a -G clamav,systemd-journal clamfleet
```

Copy `bin/clamfleet-agent` to `/usr/local/bin/` and write a config file to
`/etc/clamfleet/agent.yaml`. Start from `deploy/agent.yaml.example` for Debian, or
`deploy/agent.rhel9.yaml.example` for the RHEL 9 family. Then run:

```
runuser -u clamfleet -- clamfleet-agent collect --dry-run | jq
```

The report JSON is on stdout. Log lines and per-source warnings are JSON on stderr.
Exit codes: `0` a report was produced (even a degraded one), `1` configuration or runtime error,
`2` usage error.

## Run a server and send reports

The intended deployment is the server listening on loopback behind a reverse proxy that terminates
TLS. The server can also terminate TLS itself. Plaintext is refused on any address that is not
loopback.

**1. Install and create the user.** The server has its own user and state directory, separate from
the agent's, so an agent and a server on one host never share an identity:

```
useradd --system --no-create-home --shell /usr/sbin/nologin clamfleet-server
install -d -o clamfleet-server -g clamfleet-server -m 700 /var/lib/clamfleet-server
install -m 755 bin/clamfleet-server /usr/local/bin/
install -d /etc/clamfleet
install -m 644 deploy/server.yaml.example /etc/clamfleet/server.yaml
```

**2. Configure** `/etc/clamfleet/server.yaml` (the example is annotated). Keys:

| YAML key | Environment variable | Default |
|---|---|---|
| `listen` | `CLAMFLEET_SERVER_LISTEN` | `127.0.0.1:8443` |
| `tls.cert` | `CLAMFLEET_SERVER_TLS_CERT` | empty (plaintext, loopback only) |
| `tls.key` | `CLAMFLEET_SERVER_TLS_KEY` | empty |
| `tls.client_ca` | `CLAMFLEET_SERVER_TLS_CLIENT_CA` | empty (mTLS off) |
| `db_path` | `CLAMFLEET_SERVER_DB_PATH` | `/var/lib/clamfleet-server/clamfleet.db` |

The config file path is `--config`, else `CLAMFLEET_SERVER_CONFIG`, else `/etc/clamfleet/server.yaml`.
The file is read strictly: an unknown key is an error, so a copy of the spec's example with keys of
later milestones (`retention`, `smtp`) fails until those milestones add them.

- **Behind a reverse proxy:** this is the default (`listen: 127.0.0.1:8443`, no TLS); a non-loopback `listen` without TLS is refused. The logged
  client address is then the proxy's: `X-Forwarded-For` is deliberately not trusted.
- **Direct TLS:** set `tls.cert` and `tls.key` (both), and `listen` as needed (for example `:8443`). The certificate is loaded at start; after a
  renewal, restart the server.
- **Mutual TLS (optional):** set `tls.client_ca` to a PEM bundle. Every agent must then present a
  certificate signed by it, or the handshake fails. The agent token is still required. It needs direct
  TLS, so it cannot be combined with a TLS-terminating proxy.
- **Database:** SQLite in WAL mode. It must be on a **local disk**, never a network filesystem. The file
  and its `-wal`/`-shm` files are mode 0600. To back it up for now, stop the server and copy the
  files; an online backup command comes with a later milestone. Upgrading migrates the schema when
  `serve` starts; take a copy first, and note that a database migrated by a newer version is refused by
  an older one.

**3. Run it** (a systemd unit; packages will ship one):

```
[Service]
User=clamfleet-server
ExecStart=/usr/local/bin/clamfleet-server serve
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/clamfleet-server
```

`serve` creates and migrates the database. Logs are JSON lines on stderr (use the journal). One line
per request: method, path, status, host name, duration and the client IP address, always.
`--log-level warn` hides the accepted-request lines; `debug` adds health checks.

**4. Register a host and give the agent its token.** Run the admin commands as the server user, so
audit rows name the person (`SUDO_USER`) and the commands run with least privilege (a host command
run as root works but warns). `migrate` and `serve` refuse to create a missing database file as a
user that does not own its directory: a root-created `clamfleet.db` could not be opened by the server user.

```
sudo -u clamfleet-server clamfleet-server host add web01      # prints the token once, and nothing else
sudo -u clamfleet-server clamfleet-server host list
sudo -u clamfleet-server clamfleet-server host show web01 --json
sudo -u clamfleet-server clamfleet-server host rotate-token web01   # the old token stops working at once
sudo -u clamfleet-server clamfleet-server host revoke-token web01   # the host and its history stay
```

The token (`cfa_` plus 43 characters) is shown once; only its SHA-256 is stored, so it cannot be
shown again, only replaced. Host names are lowercase `[a-z0-9._-]`. Every add, rotate and revoke
writes an audit row naming the OS user (`SUDO_USER` if set). Deleting a host is not available yet.

On the monitored host, put the token in the file named by `token_file` (default
`/etc/clamfleet/token`, mode 0640, owner `root`, group `clamfleet`) and set `server` in
`/etc/clamfleet/agent.yaml` to the server's `https://` URL (a path prefix is fine for a proxy).
`http://` is accepted only to a loopback host: the token must not cross a network in clear. Then:

```
runuser -u clamfleet -- clamfleet-agent run --once    # test: exit 0 means the server accepted it
```

and run `clamfleet-agent run` as a service (User=clamfleet). The token file is re-read on every send,
so a rotated token needs no restart. If the server certificate comes from a private CA, set
`Environment=SSL_CERT_FILE=/etc/clamfleet/ca.pem` in the unit (Go's standard variable; `SSL_CERT_DIR`
works too). For mutual TLS, add `tls: {client_cert: ..., client_key: ...}` to the agent config
(`CLAMFLEET_AGENT_TLS_CLIENT_CERT`, `CLAMFLEET_AGENT_TLS_CLIENT_KEY`).

Things to know:
- Report timestamps (`first_seen`, `last_seen`) use the **server's** clock. A host whose clock is more
  than five minutes ahead is logged, never rejected.
- Event paths can contain personal data (for example `/home/<user>/...`) and request logs contain client
  IP addresses. Both stay on your server; plan their retention yourself, since configurable retention
  arrives with a later milestone.
- Tags are reported by the agent and are not authenticated.

## Design principles

- **The agent never starts clamd.** On Debian, clamd is socket-activated: a connection to its socket
  starts the service. The agent reads the clamd unit's state first and does not touch the socket
  unless the unit is active. Otherwise the agent would hide the outage it exists to report.
- **Agents initiate every connection.** Agents talk to the server over outbound HTTPS only; the server
  never connects to them. Reports go up to the server, and future remote actions will work the same
  way: the server schedules a task and the agent pulls it on its next check-in.
- **Degrade, don't fail.** An unreadable source becomes `null` in the report. The key is never
  missing, so a reader can tell "unknown" from "absent".
- **Small and boring.** The agent is one static binary with one dependency,
  `go.yaml.in/yaml/v3` (the maintained successor of `gopkg.in/yaml.v3`), and never links SQLite (a
  test enforces it). The server adds `modernc.org/sqlite` (pure Go) and `github.com/pressly/goose/v3`
  (migrations). New dependencies need a justification in the spec.
- **Stable interfaces.** Report and event payloads and config keys are public. Changing them needs a
  schema version bump.

## Supported platforms

| Platform | Status |
|---|---|
| Debian 13 | Tested live, end-to-end tests in a container. |
| RHEL 9 family | **Untested.** The example config and hand-written fixtures follow the packages' documentation. Contributions welcome. |

## Roadmap

Milestones follow [docs/HANDOVER.md](docs/HANDOVER.md). Milestones 1 and 2 are built.

| # | Deliverable | Status |
|---|---|---|
| 1 | Shared payload structs, agent collectors, `collect --dry-run` | Built. Tested on Debian 13 only. |
| 2 | Server ingest API, SQLite schema, migrations, token authentication, `run` | Built. Tested on Debian 13 only. |
| 3 | Health evaluator, state history, fleet page | Planned |
| 4 | Email and webhook alerting | Planned |
| 5 | Detection events, spool, events page, acknowledgement | Planned |
| 6 | Packaging (.deb and .rpm), LDAP and OIDC login, `/metrics`, retention job, backup command | Planned |

Planned web console sign-in and access control (not built yet):

- **Local accounts** with email and password, and optional TOTP two-factor authentication.
- **TOTP enforcement** for all users, switched on by an environment variable.
- **LDAP authentication.**
- **SSO via OpenID Connect**, for example with Keycloak.
- **Two roles** to start: `viewer` (read only) and `admin`.

Later: scheduled remote actions (for example "update signatures now" or "scan this path") that
agents pull from the server.

## Contributing

Contribution guidelines are coming. Running the agent on the RHEL 9 family and reporting what breaks
is especially welcome.

## Licence

AGPL-3.0-only, see [LICENSE](LICENSE). Copyright The ClamFleet Authors.
