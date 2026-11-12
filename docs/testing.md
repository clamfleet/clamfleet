<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Testing

## Unit and functional tests

```
make check      # go vet, staticcheck, go test ./..., script tests (no container, no network)
```

`staticcheck` must be installed (`go install honnef.co/go/tools/cmd/staticcheck@v0.8.2`; 2026.2.2
supports Go 1.27). The tests inject the clock, the time zone, `systemctl`/`journalctl` and the
hostname, and replay recorded clamd sessions from `internal/agent/testdata`; none of them reads
the real date or touches the machine.

`cmd/clamfleet-agent` tests build the real binary once and run it through its command dispatch.

## End-to-end tests (`make e2e`)

They run the real static agent binary inside a ClamAV container as the unprivileged
`clamfleet` user and compare its report with `sigtool`, `clamd --version`, `systemctl` and
`journalctl`.

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
