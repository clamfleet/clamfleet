<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# ClamFleet

Central management and reporting for ClamAV on Linux servers. ClamAV has no central console.
ClamFleet adds one: a small agent on each server reports ClamAV health, signature freshness and
detections to a central server. The design is in [docs/HANDOVER.md](docs/HANDOVER.md).

ClamAV is a registered trademark of Cisco Systems, Inc.; ClamFleet is not affiliated with or endorsed by Cisco.

**Status: early development, not production ready.** Only milestone 1 exists. The agent can print
the report it would send. Nothing is sent to a server yet.

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
- `clamfleet-agent version`
- Configuration from a YAML file, with `CLAMFLEET_AGENT_*` environment overrides.

A data source that cannot be read does not fail the report. It appears as `null`, and a warning goes
to stderr.

## Requirements

- **Go 1.27.4.** `go.mod` declares `go 1.26.0` and `toolchain go1.27.4`. With the default
  `GOTOOLCHAIN=auto`, the go command downloads the pinned toolchain if your installed Go is older.
- **GNU make.**
- **staticcheck v0.8.2** for `make check`:
  `go install honnef.co/go/tools/cmd/staticcheck@v0.8.2`
- **To run the agent:** Debian 13 with ClamAV, clamd and freshclam under systemd. See
  [Supported platforms](#supported-platforms).

## Build and test

```
make build      # static binary at bin/clamfleet-agent (CGO_ENABLED=0)
make check      # go vet, staticcheck, go test ./..., script tests; no container needed
make e2e        # end-to-end tests inside a ClamAV container; needs setup
```

`make e2e` runs the real agent binary in an Incus container as the unprivileged `clamfleet` user. It
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
  `go.yaml.in/yaml/v3` (the maintained successor of `gopkg.in/yaml.v3`). New dependencies need a
  justification in the spec.
- **Stable interfaces.** Report and event payloads and config keys are public. Changing them needs a
  schema version bump.

## Supported platforms

| Platform | Status |
|---|---|
| Debian 13 | Tested live, end-to-end tests in a container. |
| RHEL 9 family | **Untested.** The example config and hand-written fixtures follow the packages' documentation. Contributions welcome. |

## Roadmap

Milestones follow [docs/HANDOVER.md](docs/HANDOVER.md). Only milestone 1 is built.

| # | Deliverable | Status |
|---|---|---|
| 1 | Shared payload structs, agent collectors, `collect --dry-run` | Built. Tested on Debian 13 only. |
| 2 | Server ingest API, SQLite schema, migrations, token authentication | In planning |
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
