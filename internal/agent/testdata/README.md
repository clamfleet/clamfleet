<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Test fixtures

Recorded files cannot carry a licence header (they are JSON, raw socket bytes or binary
database headers). **This note is their licence statement: everything in this directory is
covered by AGPL-3.0-only, copyright The ClamFleet Authors**, except that the 512-byte
`cvd/*/*.hdr` files are the unmodified headers of ClamAV signature databases published by
Cisco; they hold no signatures, only a version, a count, a time and a signature blob.

The same statement covers the hand-written golden files in `internal/alert/testdata`, `internal/proto/testdata` and
any other `testdata` directory that holds JSON (the alert ones have their own README).

## Captured, do not edit by hand

Recorded by `deploy/test/capture-fixtures.sh` (`make fixtures`) from the `clamfleet-test`
container: Debian 13 (trixie), distro ClamAV 1.4.3, systemd, UTC, on 2026-11-12.
Re-run the script instead of editing. It scrubs private addresses and lab host names to
`mirror.example` and refuses to continue if any survive.

| Path | What it is |
|---|---|
| `clamd/<cmd>.req`, `.resp` | Raw bytes sent to and received from the clamd socket: `ping`, `version`, `stats`, `unknown` (`zFOO`). Recorded by `hack/clamd-record`, which shares no code with the agent. |
| `cvd/initial/*.hdr` | First 512 bytes of `daily.cvd`, `main.cvd`, `bytecode.cvd`. |
| `cvd/initial/*.info` | `sigtool --info` of the full file: the independent oracle the header tests compare against. |
| `freshclam/initial-download.log` | freshclam log of the first download (`LogTime yes`). |
| `freshclam/after-rerun.log` | The same log after a second, up-to-date run (daemon started by systemd). |
| `freshclam/logtime-no.log` | An up-to-date run with `LogTime no`. |
| `freshclam/failure.log` | A failed run: mirror unreachable (loopback port 9), never the real CDN. |
| `freshclam/journal-rerun.txt`, `journal-failure.txt` | `journalctl -u clamav-freshclam -o cat` for the same two runs through the real unit. |
| `services/*.show` | `systemctl show --property=LoadState,ActiveState` for a unit that is active, inactive, failed, and one that does not exist. |
| `clamdscan/<case>.out`, `.err`, `.exit`, `.paths` | stdout, stderr, exit status and arguments of `clamdscan --config-file=... --multiscan` for a clean directory, an infected one (EICAR), an unreadable one, several paths, and clamd down. Recorded 2026-11-16 (ClamAV 1.4.3). Shows that `--multiscan` prints one `OK` line per clean path ARGUMENT, not one per file, and no file count. |
| `debian13/os-release`, `debian13/clamd.conf` | Verbatim files. |

## Not captured

- **No `.cld` was captured.** A `.cld` only appears after freshclam applies a CVD diff, which
  needs the live CDN to publish a newer `daily` than the local copy; the container had the
  newest one and we deliberately make no extra CDN requests. The `.cvd`/`.cld` precedence is
  tested with headers rewritten in the test code (version field changed), and assumption A9
  (clamd prefers the higher version) is unverified on a live host.
- **No multi-pool STATS reply** was recorded (one pool only); `handmade/stats.two-pools.resp.txt`
  is hand-written from the documented format.

## Hand-written (`handmade/`)

Written by a person from documentation, **not captured from a real host**. RHEL 9 is untested
live (decision Q6); contributions of real recordings are welcome.

- `clamd.rhel9.conf`, `os-release.rhel9`: RHEL 9 family layout.
- `clamd.tcp-only.conf`: a clamd with no `LocalSocket`.
- `os-release.debian-sid`: no `VERSION_ID`.
- `stats.two-pools.resp.txt`: STATS with two thread pools.

## Golden file

`report.golden.json` is the expected output of `TestCollectGolden`. Regenerate with
`go test ./internal/agent -run TestCollectGolden -update` and review the diff by hand against
the fixtures above.
