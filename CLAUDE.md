<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# ClamFleet: working rules

Central management for ClamAV on Linux fleets. Spec: `docs/HANDOVER.md`. Current plan:
`docs/plans/milestone-1.md` (local only, gitignored; its section 10 holds the maintainer's decisions and overrides the rest).

## Commands

- `make check`: `go vet`, `staticcheck`, `sqlc diff`, `go test ./...` and `scripts-test` (the shell tests of `deploy/test`, fake ssh; no container needed).
- `make e2e`: runs the agent inside the `clamfleet-test` Incus container. Read `docs/testing.md` first.
- `make webfixture`: builds `bin/webfixture`, a throwaway console on 127.0.0.1 with seeded users and hosts for browser tests (see `docs/testing.md`, "Browser fixture").
- `make e2e-web`: Playwright browser tests of the console (`e2e/web`, `@playwright/test` 1.63.0 on Chromium 1243 from `/opt/playwright/browsers`); run from a fresh shell so `/opt/env.sh` is loaded.
- Tests in `cmd/*` and `hack/webfixture` build binaries that `go test` caching cannot see: use `-count=1` when changing code they cover.
- `make fixtures`: re-records `internal/agent/testdata` from the container. Never hand-edit recorded files.
- `make generate` runs sqlc over `migrations/sqlite` and `internal/store/sqlite/queries`; `make check` runs `sqlc diff`. Never hand-edit `internal/store/sqlite/sqlcdb`.
- Tools: Go 1.27.4 (`go 1.26.0` in go.mod), staticcheck 2026.2.2 (v0.8.2), sqlc v1.31.1 (`CGO_ENABLED=0 go install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1`, build-time only).

## Rules

- Licence AGPL-3.0-only. Every source, script and config file starts with
  `SPDX-License-Identifier: AGPL-3.0-only` and `SPDX-FileCopyrightText: The ClamFleet Authors`.
  Files that cannot carry a header (JSON, binary fixtures) are covered by `internal/agent/testdata/README.md`.
- No dependency beyond the table in spec section 5, using the maintained successor where the spec
  names an unmaintained module (`go.yaml.in/yaml/v3`, not `gopkg.in/yaml.v3`). Ask before adding any other.
- Environment prefixes: `CLAMFLEET_AGENT_` for the agent; `CLAMFLEET_SERVER_` is the server's (`internal/server`); the
  agent neither reads nor warns about it, and the server likewise ignores `CLAMFLEET_AGENT_`. The decisions are in `docs/plans/milestone-1.md` sections 10 and 11
  (`docs/plans` is local and gitignored, so it is not in a fresh clone).
- Payload structs in `internal/proto` and config keys are public interfaces. Do not change them without a schema bump.
- Time goes through an injected clock, never `time.Now()` inside a collector.
- The agent never starts clamd: it does not touch the clamd socket while the clamd unit is not active (socket activation).
- Bind nothing to non-loopback addresses in tests or tools.
- No org-specific hostnames in fixtures; scrub them to `mirror.example`.
- The agent never imports `internal/store`, `internal/server` or the SQLite and goose modules (a test pins it).
- Agent credentials live only in `internal/agentauth` and `hosts.token_hash`; web-console users (later) get their own package and tables. Routes are registered only in `server.NewHandler` (table `server.Routes`).
- Admin commands of `clamfleet-server` run as the server user (`sudo -u clamfleet-server`), not as root, for audit attribution and least privilege. Creating the database as root (`sudo clamfleet-server migrate` on a fresh install) leaves a root-owned file the server user cannot open, so `migrate` and `serve` refuse to create it when the effective user does not own its directory.
