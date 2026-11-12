<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Testing

## Unit and functional tests

```
make check      # go vet, staticcheck, sqlc diff, go test ./..., script tests (no container, no network)
```

`staticcheck` and `sqlc` must be installed (`go install honnef.co/go/tools/cmd/staticcheck@v0.8.2`;
2026.2.2 supports Go 1.27; `CGO_ENABLED=0 go install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1`).
`sqlc diff` fails when `internal/store/sqlite/sqlcdb` is stale: run `make generate`. The tests inject the clock, the time zone, `systemctl`/`journalctl` and the
hostname, and replay recorded clamd sessions from `internal/agent/testdata`; none of them reads
the real date or touches the machine.

`cmd/clamfleet-agent` tests build the real binary once and run it through its command dispatch.
`cmd/clamfleet-server` tests build both binaries; `TestAgentRunOnceStoresReportThroughServer` starts
the real server as a child process on `127.0.0.1:0` with throwaway certificates
(`internal/testtls`), registers a host with the admin CLI, and runs `clamfleet-agent run --once`
against it (with `SSL_CERT_FILE` pointing at the test CA), so nothing is injected between the two.
The API tests (`internal/api`) go through the real router and a real SQLite store in a temp
directory; every test uses an injected clock far from the real date. Everything binds loopback only.

## End-to-end tests (`make e2e`)

They run the real static agent binary inside a ClamAV container as the unprivileged
`clamfleet` user and compare its report with `sigtool`, `clamd --version`, `systemctl` and
`journalctl`. The server scenarios (`e2e/server_e2e_test.go`) also run the real static server
binary there, as the unprivileged `clamfleet-server` user.

Prerequisites:

- An Incus container `clamfleet-test` on an Incus host you can reach by ssh (Debian 13, distro `clamav`,
  `clamav-daemon`, `clamav-freshclam`, 3 GB RAM: clamd needs well over 1 GB while loading
  signatures) with a snapshot `clean-clamav` in which clamd runs, signatures are installed and
  **freshclam is disabled and stopped**.
- Passwordless ssh to the Incus host with `sudo incus` rights, and two required settings with
  no default (they name infrastructure, which does not belong in a public repository):
  `CFT_EXEC`, the command prefix that runs a command inside the container, for example
  `ssh <incus-host> sudo incus exec clamfleet-test --`; and `INCUS_HOST`, the ssh target of that
  host. Set them in the environment, or copy `local.mk.example` to `local.mk` and
  `deploy/test/local.env.example` to `deploy/test/local.env` (both gitignored). If `CFT_EXEC` is
  empty the suite fails; it never skips.
- Arguments passed through `CFT_EXEC` must contain no spaces or shell syntax (ssh re-parses
  them on the far side). Scripts go over stdin to `bash -s`.

What happens: `deploy/test/reset.sh` restores the snapshot, `deploy/test/prepare-agent.sh`
creates the `clamfleet` user (groups `clamav`, `systemd-journal`) and `/etc/clamfleet/agent.yaml`,
the binary is pushed, and the test waits until clamd can really scan. Every test starts with this
reset, and the suite ends with one, so the container finishes as it started (about 10 s each).

The server scenarios additionally run `deploy/test/prepare-server.sh` (user `clamfleet-server`,
`/var/lib/clamfleet-server` 0700, `/etc/clamfleet/server.yaml`), push the server binary and
throwaway TLS files (CA, server certificate; key 0600 owned by the server user), and start the
server as a transient systemd unit `clamfleet-server-e2e` with `--uid=clamfleet-server`, listening on
`127.0.0.1:8443` **inside the container**: nothing listens on a non-loopback address. The agent runs
as `clamfleet` with `SSL_CERT_FILE=/etc/clamfleet/ca.pem` (the documented way to trust a private CA);
the token is `/etc/clamfleet/token`, `root:clamfleet`, 0640. Admin commands run as the server user
(`runuser -u clamfleet-server`), never as root, as the documented production flow does
(`sudo -u clamfleet-server`): least privilege, and `SUDO_USER` gives the audit log the human's name. The snapshot reset removes the users, the
files and the transient units, so nothing needs cleaning up. The server scenarios take about 12 s
each, the agent service-loop scenario about 22 s.

The health scenarios (`e2e/health_e2e_test.go`, spec 14 acceptance for M3) run the agent as a service
next to the server and read the state with `host show --json`: stopping clamd (service and socket)
turns the host CRIT within one report interval, restarting it brings the state back, and stopping
the agent turns the host STALE after 3 intervals. They depend on two settings worth knowing when
one of them fails in a way that does not look like the cause:

- `deploy/test/server.yaml` carries a `health:` block (`daily_warn_hours: 100000`,
  `daily_crit_hours: 200000`, `eval_interval: 2s`). The snapshot's signatures are frozen and freshclam is
  disabled, so with the default thresholds the host starts CRIT (`daily_old_crit`) and the clamd
  transition is invisible. With the override the baseline is WARN (`freshclam_inactive`), which each test
  asserts first. If you refresh the snapshot with newer signatures nothing changes; if you remove the block,
  both tests fail at the baseline.
- The server clamps the agent's reported interval to at least 10 s, so the STALE test runs the agent at
  10 s (window 30 s); the CRIT test uses 5 s. A 5 s agent would still be judged as 10 s.
- STALE is measured on the server clock only (`last_seen` against the transition time), so the
  assertion does not depend on the clock of the test host.

Unknown JSON fields and body limits are not repeated here: they are tested through the real router
and listener at functional level, and the container may not have curl.

Things that fail in ways that do not look like the cause:

- **`clamdscan --ping` answers before clamd is ready.** `PONG` arrives roughly 5 s before clamd
  finishes loading signatures, and a report taken in that window says `up=false, ping: timeout`,
  which is correct. `reset.sh` and the suite (`waitClamd`) therefore wait for a real scan.
- **Never let a test run freshclam against the real mirrors.** The CDN rate-limits (HTTP 429/403)
  and freshclam then keeps a cool-down for hours. The freshclam scenario starts the real unit
  with a drop-in that points it at an unreachable loopback mirror.
- **Stopping `clamav-daemon.service` is not enough to stop clamd on Debian:** the socket unit
  stays active, and any connection to it starts the service again. The agent must not do that;
  `TestClamdStoppedIsNotRestartedByTheAgent` checks it.
- A missing `CFT_EXEC` is a hard failure, never a skip.
- The container must be on UTC: freshclam's log times have no zone, and the tests compare them
  with UTC values. The suite checks this first.

## Re-recording fixtures (`make fixtures`)

`deploy/test/capture-fixtures.sh` re-records `internal/agent/testdata` from the container
(see `testdata/README.md`). It contacts the signature CDN twice at most per run (one freshclam
daemon start, one `LogTime no` run). Do not run it in a loop; `SKIP_FRESHCLAM=1` skips every step
that touches the network.

The script scrubs private names from what it records and aborts if one survives. Generic patterns
(RFC 1918 addresses, `.incus`/`.lan`/`.internal`/`.local` names) are built in; your own host names
go in `deploy/test/scrub-private.txt` (gitignored, one per line, see
`scrub-private.txt.example`).
