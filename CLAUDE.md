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
- `make fixtures`: re-records `internal/agent/testdata` from the container. Never hand-edit recorded files.
- `make generate` runs sqlc over `migrations/sqlite` and `internal/store/sqlite/queries`; `make check` runs `sqlc diff`. Never hand-edit `internal/store/sqlite/sqlcdb`.
- Tools: Go 1.27.4 (`go 1.26.0` in go.mod), staticcheck 2026.2.2 (v0.8.2), sqlc v1.31.1 (`CGO_ENABLED=0 go install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1`, build-time only).

## Rules

- Licence AGPL-3.0-only. Every source, script and config file starts with
  `SPDX-License-Identifier: AGPL-3.0-only` and `SPDX-FileCopyrightText: The ClamFleet Authors`.
  Files that cannot carry a header (JSON, binary fixtures) are covered by `internal/agent/testdata/README.md`.
- No dependency beyond the table in spec section 5, using the maintained successor where the spec
  names an unmaintained module (`go.yaml.in/yaml/v3`, not `gopkg.in/yaml.v3`). Ask before adding any other.
- Environment prefixes: `CLAMFLEET_AGENT_` for the agent; `CLAMFLEET_SERVER_` is reserved for the server and the
  agent neither reads nor warns about it. The decisions are in `docs/plans/milestone-1.md` sections 10 and 11
  (`docs/plans` is local and gitignored, so it is not in a fresh clone).
- Payload structs in `internal/proto` and config keys are public interfaces. Do not change them without a schema bump.
- Time goes through an injected clock, never `time.Now()` inside a collector.
- The agent never starts clamd: it does not touch the clamd socket while the clamd unit is not active (socket activation).
- Bind nothing to non-loopback addresses in tests or tools.
- No org-specific hostnames in fixtures; scrub them to `mirror.example`.
