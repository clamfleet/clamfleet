<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# ClamFleet: working rules

Central management for ClamAV on Linux fleets. Spec: `docs/HANDOVER.md`. Maintainer decisions, cited in code as
"M4 decision 19": `docs/decisions.md` (the milestone plans are local, gitignored working notes; a cited decision
that is missing from the log gets a line there in the same change).

## Commands

- `make check`: `go vet`, `staticcheck`, `sqlc diff`, `go test ./...` and `scripts-test` (the shell tests of `deploy/test`: fake ssh and fake docker, the systemd units and SELinux module statically, the package maintainer scripts under stub commands, the SPDX header, workflow policy and sign-off checks; no container needed).
- `make ci`: what CI's `check` job runs: `make check` without plain `go test`, plus `actionlint`, `go mod tidy -diff`, `go mod verify`, `gofmt`, and the test gate (`hack/testgate`, which fails on a skipped test as well as a failed one). `make tools` installs the pinned staticcheck and sqlc.
- `make release-snapshot`: builds and self-checks every unsigned release asset into `dist/release` as `0.0.0-rc.1` (needs `rpm`, `rpm2cpio`, `cpio`, `dpkg-deb`, `jq`); never signed or published. The scripts are `deploy/release/*.sh`, `docs/releasing.md` is the runbook. **The release key is never on this machine**: only the release workflow's `sign` job holds it.
- `make e2e-image` and `make e2e-docker`: the e2e suite in a Debian 13 systemd container with no network (`deploy/test/ci`), through the test gate with `-expect-pkg`. Needs Docker, which the maintainer's machine does not have: CI is where it runs; `make e2e` is the local equivalent.
- `make packages VERSION=x.y.z`: the `.deb` and `.rpm` of the agent and the server into `dist/`, built by nfpm (`deploy/packaging`, build-time only).
- `make e2e`: runs the agent inside the `clamfleet-test` Incus container. Read `docs/testing.md` first.
- `make webfixture`: builds `bin/webfixture`, a throwaway console on 127.0.0.1 with seeded users and hosts for browser tests (see `docs/testing.md`, "Browser fixture").
- `make e2e-el9`: the rpm and the detection path on the AlmaLinux 9 VM (SELinux enforcing); part of milestone 6 acceptance, together with `make e2e` and `make e2e-apparmor`. Needs `CFE_EXEC` and `CFE_HOST`; fails, never skips (`docs/testing.md`).
- `make e2e-idp`: the real server against OpenLDAP and Keycloak in the Incus container `clamfleet-idp` (milestone 6b). Needs `CFI_EXEC` and `CFI_HOST`; fails, never skips. Built with `-tags e2e_idp` without `e2e` (`docs/testing.md`).
- `make e2e-apparmor`: the detection path on the VM `clamfleet-aa` (Debian 13, AppArmor enforcing); part of milestone 5 acceptance, together with `make e2e`. Needs `CFA_EXEC` and `CFA_HOST`; it fails, never skips (see `docs/testing.md`).
- `make e2e-web`: Playwright browser tests of the console (`e2e/web`, `@playwright/test` 1.63.0 on Chromium 1243 from the browser cache `PLAYWRIGHT_BROWSERS_PATH` points at); run from a shell that has that variable set.
- Tests in `cmd/*` and `hack/webfixture` build binaries that `go test` caching cannot see: use `-count=1` when changing code they cover.
- `make fixtures`: re-records `internal/agent/testdata` from the container. Never hand-edit recorded files.
- `make generate` runs sqlc over `migrations/sqlite` and `internal/store/sqlite/queries`; `make check` runs `sqlc diff`. Never hand-edit `internal/store/sqlite/sqlcdb`.
- Tools: Go 1.27.4 (`go 1.26.0` in go.mod), staticcheck 2026.2.2 (v0.8.2), sqlc v1.31.1 (build-time only), actionlint v1.7.12 (`go run`), nfpm v2.49.0 and cyclonedx-gomod v1.12.0 (`go run`, build-time only, nothing installed). The Makefile holds every pin (`STATICCHECK_VERSION`, `SQLC_VERSION`, `ACTIONLINT_VERSION`, `NFPM_VERSION`, `CYCLONEDX_VERSION`); `make tools` installs staticcheck and sqlc. Tools are never added to go.mod.

## Rules

- The repository is public: **PR bodies, comments, commit messages and CI logs never name homelab hosts, private paths or private notes** (`docs/plans`, the maintainer's machines). Say "the Incus host", not its name.
- Licence AGPL-3.0-only. Every source, script and config file starts with
  `SPDX-License-Identifier: AGPL-3.0-only` and `SPDX-FileCopyrightText: The ClamFleet Authors`.
  Files that cannot carry a header (JSON, binary fixtures) are covered by `internal/agent/testdata/README.md`.
- No dependency beyond the table in spec section 5, using the maintained successor where the spec
  names an unmaintained module (`go.yaml.in/yaml/v3`, not `gopkg.in/yaml.v3`). Ask before adding any other.
- Environment prefixes: `CLAMFLEET_AGENT_` for the agent; `CLAMFLEET_SERVER_` is the server's (`internal/server`); the
  agent neither reads nor warns about it, and the server likewise ignores `CLAMFLEET_AGENT_`. The decisions are in `docs/decisions.md` (Milestone 1).
- Payload structs in `internal/proto` and config keys are public interfaces. Do not change them without a schema bump.
- The alert payload (`internal/alert/payload.go`, pinned by `internal/alert/testdata/*.golden.json`, documented in `docs/alerts.md`) is a public interface: changes need a schema decision.
- Time goes through an injected clock, never `time.Now()` inside a collector.
- The agent never starts clamd: it does not touch the clamd socket while the clamd unit is not active (socket activation).
- Bind nothing to non-loopback addresses in tests or tools.
- Package maintainer scripts never edit another package's files (`clamd.conf`, Debian's AppArmor local include for clamd): the postinstall prints the lines for the administrator. The SELinux module is installed and removed at priority 300 only (`semodule -X 300`).
- No org-specific hostnames in fixtures; scrub them to `mirror.example`.
- The agent never imports `internal/store`, `internal/server`, `internal/alert`, `net/smtp` or the SQLite and goose modules (a test pins it).
- Agent credentials live only in `internal/agentauth` and `hosts.token_hash`; web-console users (later) get their own package and tables. Routes are registered only in `server.NewHandler` (table `server.Routes`).
- Spooled items are untrusted input: clamd's group can write `spool/events`, so the reader opens only regular files, compares inodes, bounds every read, and **validates and re-encodes before sending** (`internal/agent/validate.go`); the request body is never the bytes from disk.
- `clamfleet-agent event` runs as clamd's user with only `PATH` and two variables: no network, no token, no environment of ours, and the config is read with no fallback (an unreadable config spools nothing and says so). It only writes the spool; `run` sends.
- Detection paths are personal data: never in a log line, an audit row, a URL or a summary payload (marker tests pin it). The page shows them only through `displayPath`.
- Admin commands of `clamfleet-server` run as the server user (`sudo -u clamfleet-server`), not as root, for audit attribution and least privilege. Creating the database as root (`sudo clamfleet-server migrate` on a fresh install) leaves a root-owned file the server user cannot open, so `migrate` and `serve` refuse to create it when the effective user does not own its directory.
- The TOTP gate exempts only the listed external sources (`exemptSources` in `internal/webauth/middleware.go`: `ldap`, `oidc`). An unknown source is gated, and a session whose user's source is not in `Manager.Sources` is no session. A new sign-in source needs both lists, deliberately.
- External users are never linked to a local account: an email held by another user refuses the sign-in. LDAP and OIDC secrets live only in files under the key-file rule. No secret, code, token, verifier or failed-search DN in a log line or an audit row.
- Commits are signed off (`git commit -s`, DCO): `hack/ci/dco.sh` fails a pull request whose commit lacks a `Signed-off-by` with the author's email.
- Workflows (`.github/workflows`, rules in `deploy/test/workflows_test.sh`): GitHub-owned actions only, each pinned by full commit SHA with its version in a comment; per-job `permissions:` and `persist-credentials: false`; never `pull_request_target` or `workflow_run`; `secrets` only in the release workflow's `sign` job, which runs no build tool. The required checks are the job names `check`, `e2e`, `web`, `dco`, `release-dry-run`: a rename or removal blocks merges until the ruleset is updated first. Adding one: the ruleset is updated after the PR that adds the job has run (its run shows the exact check names) and before it merges (`docs/releasing.md`, R1 decision 8). `l1-paths` is not required and must never be listed.
- L1 runs (`make e2e-apparmor`, `make e2e-el9`; `make e2e`, `e2e-idp`, `fixtures` and `record-freshclam-history` are guarded the same way): `deploy/test/l1-paths.txt` says which changes need one (the `l1-paths` job prints it); every release candidate runs all of them. For a fork's PR nobody runs L1 before the maintainer has read the diff and approved it; `deploy/test/l1-guard.sh` refuses a commit on no origin branch unless `L1_APPROVED` is its full SHA, and an agent never sets that itself (R1 decision 6).
- A skipped test is a failed test in CI (`hack/testgate`). Exclude a test from a CI job with a build tag in a reviewed change, never with a runtime `t.Skip`.
