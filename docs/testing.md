<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Testing

## Unit and functional tests

```
make check      # go vet, staticcheck, sqlc diff, go test ./..., script tests (no container, no network)
```

The web console is tested through the real router: `internal/web` starts `server.NewHandler` behind an
`httptest` TLS server (the production cookie is `Secure`, so a plain-HTTP client would never send it back),
signs in with a cookie-jar client and an injected clock, and posts real agent reports. Note that the
`cmd/clamfleet-server` and `hack/webfixture` tests build the binaries themselves, which `go test` does not
see as inputs: use `go test -count=1` when you change code they cover, or a cached "ok" proves nothing.

`staticcheck` and `sqlc` must be installed: `make tools` installs the versions the Makefile pins (staticcheck v0.8.2,
which is 2026.2.2 and supports Go 1.27; sqlc v1.31.1).
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

Alerting (Milestone 4) is tested at four levels. `internal/alert` has table tests of the pure planner and the
retry schedule, golden files for the payload, and sender tests against real local servers: a loopback
`httptest` receiver with a scripted resolver and dialer (every address the sender is asked to connect to is
recorded, and the tests assert none is forbidden), and `internal/testsmtp`, a scriptable fake SMTP server
(STARTTLS with `internal/testtls`, implicit TLS, AUTH PLAIN and LOGIN, per-recipient replies, a connection
dropped at the end of DATA with or without a reply, a stalled session; `Update` changes the script while it
runs). The dispatcher tests use the real SQLite store, an injected clock and `RunOnce`, and abandon and reopen
the store to prove restart behaviour. `internal/web/alerts_test.go` goes through the real router with a
loopback webhook receiver and the SMTP fake. `cmd/clamfleet-server` tests run the real binaries (serve
refusals, an alert delivered after the real agent reports a down clamd, the CLI's refusal to take a URL as an
argument, key rotation and `key check`). Everything binds loopback only.

## CI (`.github/workflows/ci.yml`)

Four jobs. Their names are the repository's required status checks, so a rename blocks merges until the ruleset is
changed first.

| Job | Runs on | What it proves |
|---|---|---|
| `check` | every pull request (drafts too), every push to `develop` and `main`, weekly | `make ci`: vet, staticcheck, `sqlc diff`, the unit and script tests through the test gate, actionlint on the workflows, `go mod tidy -diff`, `go mod verify`, gofmt. About 5 minutes. |
| `e2e` | ready pull requests and pushes | the e2e suite in a container with a real ClamAV and systemd (below, "The e2e suite in Docker") |
| `web` | ready pull requests and pushes | the Playwright browser tests of the console (`make e2e-web`), the layer that sees a dead button |
| `dco` | pull requests | every commit carries a `Signed-off-by` with the author's email (`hack/ci/dco.sh`) |

**Draft pull requests run only `check`.** A draft cannot be merged, and marking it ready for review starts the full run.
A job skipped by its `if:` reports success to a required check, which is safe only because of that rule;
`deploy/test/workflows_test.sh` allows exactly this `if:` on the required jobs and no other.

`make ci` is `make check` with `hack/testgate` in place of plain `go test`, plus `lint-workflows`, `go mod tidy -diff`,
`go mod verify` and a gofmt check. Run it before you push. The gate reads `go test -json`, prints the output as text, and
fails on a failed test, on a **skipped** test, on a package that does not build, and on a stream in which nothing passed.
`go test` itself exits 0 for a skip, and a test that skips itself at run time cannot fail when the feature breaks. There is
no allowlist: a test that cannot run in a CI job is excluded by a build tag in a reviewed change. `-expect-pkg ./e2e -tags e2e`
also fails the run unless the set of top-level tests that passed equals the set the package declares (the go tool evaluates
the build constraints, `go/parser` reads the files; subtests and `TestMain` do not count), so a narrowed `-run` or a test
that never ran cannot pass. The gate has its own unit tests (`hack/testgate`).

`-count=1` is used everywhere: the `cmd/*` and `hack/webfixture` tests build binaries that the test result cache cannot see.

The workflows follow rules that `deploy/test/workflows_test.sh` (part of `make check`) and actionlint enforce: GitHub-owned
actions only, each pinned by full commit SHA with its version in a comment; per-job `permissions:` and
`persist-credentials: false`; no `pull_request_target` or `workflow_run`; no secrets in these jobs (pull requests from forks
run them). The script is a guardrail over a list of patterns, not a proof that a workflow is safe.

Other `make check` tests added for CI: `deploy/test/headers_test.sh` (every tracked file has both SPDX lines, or is a listed
exception with its reason) and `deploy/test/dco_test.sh` (the sign-off check against a temporary repository, including a range
that was never fetched, which must fail and not look empty).

Tools are pinned in the Makefile and installed with `make tools` (staticcheck, sqlc); actionlint runs through `go run` at its
pinned version. None of them is in `go.mod`.

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

The alert scenarios (`e2e/alert_e2e_test.go`, spec 14 acceptance for M4) additionally build and push
`hack/alertsink`, a loopback receiver (a webhook on `127.0.0.1:9100` and plaintext SMTP on `127.0.0.1:2525`)
that appends one JSON line per request or message to `/run/alertsink/sink.jsonl`, and run as a transient unit
`clamfleet-alertsink-e2e` as the server user. `deploy/test/server.yaml` carries the matching `alert:` and
`smtp:` blocks (`alert.cooldown: 0s` because the cooldown is proven with an injected clock; `smtp.tls: none`
because the relay is on loopback). The server fixture creates the secret key file before `serve` starts
(`key generate`, `root:clamfleet-server 0640`), because webhook targets seal their URL with it.
`TestAlertClamdStoppedAndRecovered` creates a webhook target (URL through `--url-stdin`) and an email target
with the CLI, expects the baseline NULL to WARN alert, stops clamd and expects exactly one WARN to CRIT on each
(the webhook verified with the key the CLI printed), restarts clamd and expects exactly one recovery on each,
nothing redelivered, and a `sent` row per delivery in `alert log --json`. `TestAlertTargetDownIsRecorded`
points a target at a closed loopback port and expects `retrying` rows with `connection refused` while ingest
keeps working. The one-shot report that proves ingest works is the only writer and
lands in a later second than the last stored report (the server keeps one report per host and second and
silently ignores a duplicate), so the test stops the agent service and waits for the container's clock first.

The detection scenarios (`e2e/event_e2e_test.go`, milestone 5 acceptance) wire the container's real clamd to the real
`clamfleet-agent event` with a `VirusEvent` line (added to `clamd.conf` only in this file's tests; the snapshot
reset restores it), run the agent as a service with the spool that `prepare-agent.sh` creates
(`/var/lib/clamfleet` `clamfleet:clamav 0750`, `spool/` `2750`), and use the alert sink. The EICAR string is built
at run time from two halves and never committed.

- `TestEICARAlertWithin30s`: `clamdscan` of an EICAR file returns in under 5 s, and a signed `detection` reaches
  the sink within 30 s with the real path and a signature containing EICAR, `source: clamd`; the spool is empty,
  `event_count` is 1 and the next report carries `virus_event: clamfleet`. It logs the measured latency.
- `TestEventSurvivesServerDowntime`: with the server stopped the event is spooled (owner `clamav:clamav`, mode
  0640, `spool/events` `3770`), stays 10 s with a `network` failure in the agent journal and no path, and after
  the restart exactly one alert arrives with `ts` before the restart and `received_at` after it.
  `TestEventSurvivesAgentAndServerDowntime` stops both.
- `TestEICARDuringBacklog`: 300 detections spooled during an outage, then one fresh one alerts within 30 s of its
  scan; all 301 arrive.
- `TestDetectionBurst`: 200 detections in one `--multiscan`: all stored within 60 s, exactly 10 sent one by one
  (the summary is proven with the injected clock in the unit tests; the 10 minute window is not shortened
  here), the agent's peak RSS (`VmHWM`) under 30 MB. It logs the scan time and the per-detection cost.
- `TestEventFullStorage` (a 256 KiB tmpfs under the spool, mounted before the agent starts), `TestEventWithoutSpoolAccess`
  (`spool/events` without its sticky bit) and `TestEventUnreadableConfig` (`agent.yaml` mode 0600): the scan returns
  in under 5 s, clamd still answers, clamd's journal holds exactly one `event not spooled` line without the path,
  and nothing is half written.

`deploy/test/server.yaml` sets `health.require_virus_event: false`: most scenarios run a clamd with no `VirusEvent`
line, which would add a second WARN reason next to the baseline the health scenarios assert.

**Why the container cannot test AppArmor.** It has no `apparmor` package and clamd runs unconfined there, so a
profile that refuses `VirusEvent` on a stock Debian host would pass every scenario above. That is what the VM is for.

### The AppArmor VM (`make e2e-apparmor`)

Part of the milestone 5 acceptance (decision 7): `make e2e` and `make e2e-apparmor` both green. It needs a
throwaway **Debian 13 VM** with AppArmor enforcing (`aa-status`: `/usr/sbin/clamd` in enforce mode), ClamAV 1.4.3
from the distribution, `apparmor-utils` (`aa-exec`), freshclam disabled, the signatures copied in, at least
2 GiB of RAM (clamd needs well over 1 GB), and a snapshot named `clean`. Two settings with no default:
`CFA_EXEC` (the command prefix that runs a command in the VM, for example `ssh <incus-host> sudo incus exec <vm> --`)
and `CFA_HOST` (the ssh target of the Incus host that holds it). Set them in the environment or in `local.mk`
(see `local.mk.example`). Without them the target **fails** with a pointer here; it never skips.

The Makefile points the container suite's own variables at the VM (`CFT_EXEC=$CFA_EXEC`, `INCUS_HOST=$CFA_HOST`,
`CT=clamfleet-aa`, `SNAP=clean`) and runs the scenarios of `e2e/apparmor_e2e_test.go` (build tags `e2e e2e_apparmor`).
Each starts with `deploy/test/reset.sh` restoring the VM's `clean` snapshot (the VM reboots; the script waits
until `incus exec` works and clamd can scan), `prepare-agent.sh` and `prepare-server.sh`, then
`deploy/test/aa-prepare.sh`: the clamfleet-agent **.deb** is installed (its postinstall loads the profile; nothing in the
script does, and the script fails if the profile is not enforcing afterwards), the package's own service is stopped (the suite
runs its own agent unit), clamd's local include lines are appended from the doc file the package installs, the `VirusEvent` line is added with a check that it
survives `dpkg-reconfigure clamav-daemon`, clamd's profile is reloaded and clamd restarted. `dpkg` runs with `--force-confold` and
`</dev/null`: its stdin is the script itself, and at a conffile prompt it would read its answer from the script and
swallow the lines that follow. The suite ends
with one more reset, so the VM finishes as it started. EICAR files live in `/tmp/e2e` (Debian's clamd profile allows
`/tmp/**`, nothing under `/srv`).

- Preconditions, asserted first: `aa-status --json` lists `clamfleet-agent-event` and `/usr/sbin/clamd` in enforce
  mode, and `/proc/<clamd pid>/attr/current` reads `/usr/sbin/clamd (enforce)`.
- `TestAppArmorEICARAlert`: the alert arrives within 30 s, clamd's journal holds no line from our command, and the
  kernel log (`journalctl -k`) holds no `apparmor="DENIED"` line since the scan, except the stock one for clamd's read of
  `/etc/hostname` (Debian's profile denies it on every detection, with or without our line: checked with `VirusEvent` removed).
- `TestAppArmorTransitionFromClamd`: `VirusEvent` set to the agent with the token as its config file: the DENIED
  line for the token names `profile="clamfleet-agent-event"`. With `ix` instead of `Px` it would name
  `/usr/sbin/clamd`; unconfined there would be no line, only a YAML error.
- `TestAppArmorEventProfileDenies`: as the user clamd runs as (`clamav`) under `aa-exec -p clamfleet-agent-event`, with the files' modes loosened first
  (the kernel's own permission check comes before AppArmor and would refuse clamd's user without a line in the kernel
  log; root does not work either, because without capability rules in the profile a root process is refused before
  any file rule is reached), so only the profile can refuse: the token as config gives "permission denied" and a DENIED line; a
  `spool.dir` of `spool/reports` or `spool/quarantine` that holds a real `events/` with the right owner and mode (the
  command's own checks pass) is refused by the profile and no file appears; `run --once` cannot even create an inet
  socket (a DENIED `class="net"` line).
- `TestClamdOnlyExecsTheAgent`: a `VirusEvent` of `/usr/bin/touch /tmp/e2e/touched` gets a DENIED `exec` line under
  clamd's profile and no file.
- `TestAppArmorPackageRemoval`: `apt-get remove clamfleet-agent` unloads `clamfleet-agent-event`.

If clamd runs out of memory in the VM, the run fails: the VM is not resized by the suite.

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

## The e2e suite in Docker (`make e2e-image`, `make e2e-docker`)

What CI's `e2e` job runs, and what anyone with Docker can run: the same suite as `make e2e`, with the container replaced
by one made from `deploy/test/ci/Dockerfile`. The maintainer has no Docker; the Incus suite is his equivalent.

- **The image** is Debian 13 with systemd as PID 1 (the suite uses `systemctl`, `journalctl`, `systemd-run` and the
  packages' units, which is why it is not the official ClamAV image), the distribution's ClamAV packages, and a frozen
  copy of the signature databases taken from the official ClamAV image, pinned by digest. freshclam is never run and its
  unit is disabled. Three tests take the Incus snapshot's one real freshclam run as their premise, so the image carries a
  scrubbed recording of one (`deploy/test/ci/testdata`: `freshclam.log` as a file, the journal lines replayed at boot by a
  oneshot). `make record-freshclam-history` re-records it from the Incus container; never hand-edit it.
- **Each reset starts a new container** (`RESET_RUNTIME=docker` in `deploy/test/reset.sh`): `--privileged --cgroupns=private
  --tmpfs /run --tmpfs /run/lock --network none`. `--privileged` is root on the runner VM, accepted because the VM is
  discarded after the job, which holds no secrets (the policy test keeps `secrets` out of these jobs). The script asserts
  `NetworkMode=none` with `docker inspect` and fails otherwise. A reset takes about 7 s; the suite about 8 minutes.
- **What "no network" guarantees:** during the tests the container has no network, so nothing in them can reach the ClamAV
  CDN or anything else; binaries and packages go in over `docker exec -i`. Building the image does use the network (Docker
  Hub for the two base images, `deb.debian.org` for packages), but never contacts the ClamAV CDN.
- **The gate:** `make e2e-docker` pipes `go test -json` through `hack/testgate -expect-pkg ./e2e -tags e2e`: every
  top-level test the package declares (`TestMain` is not one) must pass, none may skip, and the set must equal what the package declares.
- **Journals:** `reset.sh` writes the journal of each container to `dist/e2e-journals` (`E2E_JOURNAL_DIR`) before replacing
  it, named by end time. CI uploads them for 7 days when the job fails. They hold synthetic data only.
- **The image is cached** as a tarball by the Dockerfile hash and the ISO week, so Docker Hub is pulled a few times a
  week at most (anonymous pulls are limited per address, and runners share addresses).
- **Refreshing the signatures:** change the digest in the Dockerfile's first `FROM` (Dependabot proposes it monthly) and
  let CI judge it. The old digest may disappear from Docker Hub; the weekly cache holds the built image until then.
- **Distribution drift:** the image takes the live Debian 13 archive, so a ClamAV or systemd update can turn CI red.
  Open an issue, fix it in its own pull request, and let others wait; the temporary escape is a pinned package version in the
  Dockerfile with a removal date, in a reviewed commit. A red run is never simply re-run until it is green.
- **A failure only CI shows:** read the uploaded journals and the test log first. If that is not enough, run the suite
  in a Docker of your own (`make e2e-image`, `make e2e-docker`), or the Incus suite (`make e2e`), and say in the pull request what
  you could not reproduce; the maintainer can look at the failing run's logs.

## Packages (`make packages`) and the package scenarios

`make packages VERSION=x.y.z` builds the static binaries and runs **nfpm v2.49.0** (`go run`, pinned in the Makefile and
CLAUDE.md like sqlc; build time only) for the agent and the server in both formats into `dist/` (`PKG_DIR` changes the
directory). `make e2e`, `make e2e-apparmor` and `make e2e-el9` build `VERSION=0.6.0-e2e1` first. The maintainer scripts are
POSIX sh and are covered in two ways: `deploy/test/packages_test.sh` (part of `make check`) runs them under stub commands
with every argument convention of both formats, the rpm upgrade order (new `%post 2`, then the old `%preun`/`%postun`
with 1), idempotence (a second run changes nothing), recovery from a failed step, and a purge that never follows a symlink
or crosses a mount; `deploy/test/units_test.sh` and `selinux_test.sh` pin the unit directives and the SELinux module's
contract statically.

`e2e/package_e2e_test.go` (in `make e2e`) installs the .deb files with apt in the clean container and runs: install and
start; a detection through the packaged agent (the test a `0640` agent.yaml would fail); the scan timer's service
(exit 1, `last_scan.json`, clamd never started while stopped, its socket unit included); the retention acceptance
(`hack/seeddb` writes a database with rows of known ages, `retention.reports_days: 14`); `/metrics`; an upgrade from
`0.6.0~e2e1` to `0.6.0~e2e2` that keeps the configuration edit and the key file and restarts both services; remove and
purge (the database and key survive); a purge across a tmpfs mount (nothing is removed, the mount is named); and
`TestDebFailedUpgradeLeavesDataAlone`: the new package is built with `make packages E2E_BUILD_TAGS=e2e_migration` (refused unless `VERSION` contains `e2e`), a
test-only migration (`migrations/e2e_overlay.go`, never in a release build) so the upgrade changes the schema; with an
unwritable `backup.dir` the restarted server refuses to migrate, keeps restarting (`Restart=on-failure`), leaves the schema
and every old row alone (no prune), and recovers with a `pre-migrate-v6-to-v7` backup once the directory is fixed. **After an e2e run `bin/` holds the overlay
builds** (binaries that print `+e2e_migration` after their version) until the next `make build`; never ship from `bin/` after one.

### The AlmaLinux 9 VM (`make e2e-el9`)

Part of the milestone 6 acceptance with `make e2e` and `make e2e-apparmor`. SELinux cannot be tested in a container: it
shares the Debian host's kernel, which has none, so this needs a throwaway **AlmaLinux 9 VM** with SELinux **Enforcing**,
ClamAV from EPEL (`clamd`, `clamav-freshclam`, `clamav`; 1.4.6 when written), `policycoreutils`, `setools-console` and
`audit`, the signatures copied in, freshclam disabled, `LocalSocket /run/clamd.scan/clamd.sock` enabled in
`/etc/clamd.d/scan.conf` (stock: commented out), at least 3 GiB of RAM, and a snapshot `clean`. Two settings with no default:
`CFE_EXEC` and `CFE_HOST` (as for AppArmor; see `local.mk.example`). Without them the target **fails**; it never skips. The claim is
"tested on AlmaLinux 9", not RHEL itself (RHEL needs a subscription).

**The harness module.** `incus exec` reaches the VM through the Incus agent, which runs in `init_t` and starts commands in
`initrc_t`. The image carries a harness-only CIL module `incus-agent-harness` (it allows `init_t` the vsock the agent
uses); it is part of the VM, not of ClamFleet, and is in the `clean` snapshot. Denials of `init_t`, `initrc_t` and
`load_policy_t` in the audit log (`siginh`, pipes) are the harness and are ignored; the suite looks at `antivirus_t` only,
and one stock denial is filtered by name: clamd searching `/selinux`, an unlabeled directory the image ships. Files for clamd
to scan live in `/var/lib/clamav/e2e` (the harness context cannot hand clamd a path under `/srv`: clamdscan answers
"Can't access file"), and `READY_FILE` is a file under `/var/lib/clamav` clamd may read.

`deploy/test/el9-prepare.sh` installs both .rpm files with dnf (the `%post` loads the module at priority 300 and
relabels the spool; nothing in the script does) and adds the `VirusEvent` line to `scan.conf`. The scenarios of
`e2e/el9_e2e_test.go` (tags `e2e e2e_el9`), each from the `clean` snapshot:

- `TestEL9RpmInstallAndStart`: the preconditions (`getenforce` Enforcing, clamd in `antivirus_t`, `semodule -lfull` lists
  `clamfleet` at 300, `spool/events` and `spool/usage` are `clamfleet_spool_t`), the server not enabled by the preset, users, the
  modes and the groups (`clamscan`, `virusgroup`, `systemd-journal`), the agent waiting for its token, and a report under the hardened unit.
- `TestEL9DryRun`: `collect --dry-run` with the packaged RHEL example agrees with `sigtool`, `clamd --version` and systemd.
- `TestSELinuxEICARAlert`: the alert within 30 s and **no AVC denial for clamd's domain** (the stock `/selinux` one apart): no
  spool, shell or binary denial. It also proves `antivirus_t` can read the packaged `agent.yaml`.
- `TestSELinuxModuleIsNeeded`: with the module removed at priority 300 and the spool relabelled `var_lib_t`, the same scan is
  denied (an AVC for the event command), nothing is spooled and nothing reaches the sink: the module is what makes it work,
  and the test above can fail.
- `TestSELinuxEventCannotWriteElsewhere`: the event command pointed at another spool directory (a real `events/`, the right
  owner and mode, `var_lib_t`, loosened to 0755) is denied by SELinux and no file appears.
- `TestEL9EventSurvivesServerDowntime`: the milestone 5 scenario (the event is spooled with group `clamscan`, delivered after the restart).
- `TestEL9RpmUpgradeAndRemove`: the module stays loaded at 300 across an upgrade, the configuration edit is kept, both services restart;
  `dnf remove` leaves no module at any priority, and the units are gone.
- `TestSELinuxRuleSet`: `sesearch -A -s antivirus_t` with and without the module, diffed: exactly the two reviewed rules on
  `clamfleet_spool_t`, nothing on a stock type.

Findings from writing it, all in the docs now: EPEL's `/run/clamd.scan` is `clamscan:virusgroup 0710` (the agent needs `virusgroup`); the
event command's standard error is lost on this family (`clamd@scan` is `Type=forking`), so a failing event leaves no journal line;
the event files must exist before the spool is labelled (tmpfiles.d pre-creates them).

If the VM runs out of memory the run fails; the suite never resizes it. Restore after a manual session with
`ssh <incus-host> sudo incus snapshot restore <vm> clean` and `incus start`.

## Browser fixture (`make web-fixture`)

The console's browser tests (Playwright) need a server they can start on loopback with known logins and
hosts. `hack/webfixture` is that server; `make webfixture` builds `bin/webfixture` (and the server), and
`make web-fixture` runs it in the foreground until Ctrl-C. A test runner should start the binary itself:

```
bin/webfixture --server-bin bin/clamfleet-server [--port N] [--json-out PATH] [--keep] [--totp-required]
```

`--totp-required` starts the console with `auth.local.totp_required: true` and seeds the `forced` user.
The fixture also writes a `secret_key_file` inside its temp directory (made with the real
`clamfleet-server key generate`); the developer's own key file is never read.

It creates a private temp directory with throwaway TLS files, migrates, seeds, starts the real server
(`https://127.0.0.1:<port>`, 1 s health evaluation, production cookie settings), prints one line
`READY https://127.0.0.1:<port>` on stdout and waits. SIGINT or SIGTERM stops the server and deletes
the directory; nothing outlives it and nothing listens beyond 127.0.0.1. The browser must ignore the
certificate error (`ignoreHTTPSErrors`) or trust `ca_cert`. The server log is `server_log` in the JSON.

`<tmp>/fixture.json` (also copied to `--json-out`; mode 0600) holds the URL, the CA, the logins and the
host tokens. Passwords and tokens are random per run, so read them from the file:

| Seed | Content |
|---|---|
| `admin` | `admin@fixture.example`, role admin |
| `viewer` | `viewer@fixture.example`, role viewer |
| `must_change` | `newbie@fixture.example`, viewer with a one-time password: signing in lands on `/account` |
| `enrol` | `enrol@fixture.example`, viewer with a password and no authenticator: the enrolment flow signs in as it |
| `totp` | `totp@fixture.example`, viewer with an authenticator. `fixture.json` holds `secret_base32` and the 10 `recovery_codes` (display form, each works once) |
| `forced` | only with `--totp-required`: `forced@fixture.example`, no authenticator, in a console that requires one: signing in lands on `/account/totp` |
| `ok01` | OK, tags `prod`, `web` |
| `warn01` | WARN, freshclam unit inactive (tags `prod`, `db`) |
| `crit01` | CRIT, clamd down with `ping: timeout` (tag `staging`) |
| `stale01` | OK at start (report interval 10 s), STALE about 35 s later |
| `pending01` | registered, never reported: state `pending` |
| `xss01` | WARN, with HTML in a tag, the reported host name and the freshclam error: it must render inert |
| `alerts01` | OK, tag `alerts`: the only host the seeded alert target takes (see "Alerts in the fixture") |

**Making a TOTP code.** The server under test runs on the real clock, so a code is made from `secret_base32`
for the real time: RFC 6238 (HMAC-SHA1 over the 8-byte big-endian counter `floor(unix / 30)`, dynamic
truncation, 6 digits). A code is accepted for the current 30 s step and one step either side, but **each step
only once per user**: a spec that signs in twice as `totp` within 30 s must use the code of the next step
(`floor(unix / 30) + 1`) the second time. A recovery code works once.

A spec can change a state by posting its own report with the host's token to `POST /v1/report`
(`Authorization: Bearer <token>`, schema 1, `ts` strictly newer than the previous one; see `docs/api.md`):
the fleet page's live region refreshes every 15 s.

Stable selectors (`data-testid`): `login-form`, `login-email`, `login-password`, `login-submit`, `error`
(an error banner), `notice`, `current-user`, `nav-fleet`, `nav-admin` (admins only), `nav-account`,
`logout-button`, `fleet-live`, `fleet-counts`, `count-<STATE>`, `fleet-table`, `fleet-row-<host>` (with
`data-state`), `fleet-state-<host>`, `fleet-reasons-<host>`, `fleet-link-<host>`, `fleet-filter-tag`,
`fleet-filter-state`, `fleet-filter-submit`, `fleet-empty`, `fleet-no-match`; `host-page`, `host-state`,
`host-reasons`, `host-report`, `host-history`, `host-history-row`, `host-admin`, `host-audit`,
`host-actions-<host>`; `admin-hosts-page`, `admin-register-form`, `admin-register-name`,
`admin-register-submit`, `admin-hosts-table`, `admin-host-row-<host>`, `rotate-open-<host>`,
`rotate-submit-<host>`, `revoke-open-<host>`, `revoke-submit-<host>`, `delete-open-<host>`,
`delete-confirm-<host>`, `delete-submit-<host>`; `token-page`, `token-value`, `token-done`;
`account-page`, `account-form`, `account-current`, `account-new`, `account-new2`, `account-submit`,
`must-change`; `error-page` (with `data-status`). Two-factor pages: `totp-login-page`, `totp-login-form`,
`totp-code`, `totp-submit`, `totp-restart` (`/login/totp`); `account-totp-card`, `account-totp-status`,
`account-totp-link` (on `/account`); `totp-page`, `totp-status`, `totp-codes-left`, `totp-required-notice`,
`totp-unavailable`, `totp-external`, `totp-setup-form`, `totp-setup-password`, `totp-setup-submit`,
`totp-recovery-form`, `totp-recovery-password`, `totp-recovery-submit`, `totp-disable-form`,
`totp-disable-password`, `totp-disable-submit`, `totp-back` (`/account/totp`); `totp-setup-page`,
`totp-secret` (the key in groups of four), `totp-uri` (read-only input), `totp-confirm-form`,
`totp-confirm-code`, `totp-confirm-submit`; `recovery-codes-page`, `recovery-codes` (a `<pre>`, one code
per line), `recovery-continue`. The CSRF token is in `<meta name="csrf-token">`.
Rotate, revoke and delete forms are inside `<details>` elements: click the `*-open-*` summary first.
`make check` starts the fixture once and signs in with it (`hack/webfixture`'s own test).

### Alerts in the fixture

The fixture starts the server with `alert.cooldown: 0s` (no holds: every transition is alerted at once),
`alert.webhook.allow_loopback: true` and `public_url` set to the fixture URL; email is **off** (`smtp.host`
empty), so the Alerts page shows its "email is not configured" banner and an email target cannot be created.
It also runs a **webhook receiver on 127.0.0.1** that records requests, and creates one target through the real
CLI. `fixture.json` has an `alerts` object:

| Key | Content |
|---|---|
| `receiver_url` | `http://127.0.0.1:PORT`, plaintext on purpose: a target with this URL shows the "unencrypted" badge and warning |
| `requests_url` | `GET` returns the recorded requests as JSON (oldest first): `{ts, method, path, header, body}`; `DELETE` clears them. The headers hold `Webhook-Id`, `Webhook-Timestamp` and `Webhook-Signature` |
| `status_url` | `POST ?code=503` makes the receiver answer 503 from now on, `?code=0` resets to 204 |
| `seeded_target`, `hook_url`, `signing_key` | a webhook target named `seeded-hook` for `hook_url` (`receiver_url/hook/seeded`), signed with `signing_key` (`whsec_...`; the HMAC key is the base64-decoded part) |
| `host` | `alerts01`: the seeded target has the tag filter `alerts`, so only this host's transitions reach the receiver |

Flows a spec can drive (all as `admin`, who is signed in with the usual login form):

- **Add a target.** `/admin/alerts` -> `alert-add-webhook` -> fill `alert-name` and `alert-url` (a receiver
  URL, for example `receiver_url + "/hook/spec"`; the field is never filled back in) -> `alert-submit`. The
  next page (`secret-page`) shows the key once in `secret-value` and has `Cache-Control: no-store`; its
  `secret-done` link goes to the target page. Reloading `/admin/alerts` or the target page never shows the key
  or the URL path (`alert-destination-<name>` shows `http://127.0.0.1:PORT/...`).
- **Send test.** `alert-test-<name>` on the list is an htmx button: the answer replaces the content of
  `alert-test-result-<name>` without a page load, with the text `Delivered: HTTP 204 in N ms` (inside
  `test-result-text-<name>`, class `ok` or `fail`). The receiver then holds one request with `"kind":"test"`.
  A second test within 10 s answers 429 with a message in the same place. After `POST status_url?code=404` the
  text reads `HTTP 404: ...` (class `fail`, permanent), after `503` the same with 503. No inline script runs:
  watch for console and CSP errors.
- **Delivery.** `POST /v1/report` for `alerts01` with its token (`hosts.alerts01.token`) and `clamd.up=false`
  (a `ts` strictly newer than the seeding report, one second resolution): within about 5 s `requests_url`
  holds one `state_change` to CRIT with `url` = `public_url/hosts/alerts01`, and the target's page
  (`/admin/alerts/seeded-hook`) lists a `sent` row in the table `alert-log-table` (rows `alert-log-row`).
- **Viewer.** The viewer has no `nav-alerts` and gets 403 on `/admin/alerts`.

Selectors added for the Alerts pages: `nav-alerts` (admins only); on `/admin/alerts`: `admin-alerts-page`,
`alert-add-webhook`, `alert-add-email`, `alerts-table`, `alerts-empty`, `alert-row-<name>`,
`alert-destination-<name>`, `alert-unencrypted-<name>`, `alert-disabled-<name>`, `alert-last-<name>`,
`alert-edit-<name>`, `alert-test-<name>`, `alert-test-result-<name>`, `alert-log-table`, `alert-log-row`,
`alert-log-empty` and the banners `alert-banner-email-off`, `alert-banner-no-public-url`,
`alert-banner-unrouted`, `alert-banner-unreadable-<name>`; on the form pages (`/admin/alerts/new?type=webhook|email`
and `/admin/alerts/<name>`): `alert-form-page`, `alert-form`, `alert-name`, `alert-url`, `alert-url-hint`,
`alert-url-current`, `alert-unencrypted-badge`, `alert-to`, `alert-min-severity`, `alert-tags`,
`alert-state-changes`, `alert-detections`, `alert-enabled`, `alert-switchoff-hint`, `alert-pending`,
`alert-submit`, `alert-form-email-off`, `alert-form-smtp-plain`, `alert-form-unreadable`; on the target page:
`alert-actions`, `alert-test-submit` (a plain form, answers with a redirect and a notice), `alert-rotate-open`,
`alert-rotate-submit`, `alert-delete-open`, `alert-delete-confirm`, `alert-delete-submit`; on the key page:
`secret-page`, `secret-notice`, `secret-value`, `secret-done`. Rotate and delete are inside `<details>`
elements: click the `*-open` summary first.

### Detections in the fixture

The fixture posts 12 detections through the real `POST /v1/event` with the hosts' tokens, **before** the alert
target exists and after the dispatcher has planned them (with no target they match none), so no seeded
detection is ever delivered to the receiver. `ok01`'s two are then acknowledged by `admin@fixture.example`
straight in the store. `fixture.json` has an `events` object:

| Key | Content |
|---|---|
| `open_count` | 9: the number in the nav badge at the start (and the rows of the default Open filter) |
| `ids_by_host` | event ids per host, oldest first (a merged duplicate counts once) |
| `acked_ids`, `acked_by` | the two acknowledged events of `ok01` and the admin's email |

| Host | Seeded detections |
|---|---|
| `crit01` | 2 open EICAR detections (`/srv/eicar/a.com`, `b.com`): the acknowledgement flow clicks one, then `fleet-open-crit01` reads 1 |
| `xss01` | 5 open: a path with markup and a real U+202E (`/srv/<img src=x onerror=alert(1)>/` + RLO + `txt.exe`) and a signature with HTML; a path with the literal text `\u{202E}`; a path with a real U+2028; a file name with a real backslash (`back\slash.txt`, the agent sends it doubled); a path with a raw non-UTF-8 byte (`\xff`) |
| `warn01` | 1 row shown "x2": one detection posted twice with two ids and the same key |
| `alerts01` | 1 open detection |
| `ok01` | 2 acknowledged detections, detected 3 h before they arrived ("received 3h later, spooled") |

Selectors added for the Detections pages: `nav-events` and `nav-events-count` (every signed-in user); on
`/events`: `events-page`, `events-filter`, `events-filter-host`, `events-filter-sig`, `events-filter-ack`,
`events-filter-submit`, `events-count` ("N matching"), `events-table`, `events-empty` (no detection exists),
`events-no-match` (the filters match none), `events-older`, `events-newest`, and, **for admins only**,
`events-bulk-open` (a `<details>`: click it first), `events-bulk-expected` (the count the admin is shown) and
`events-bulk-submit`; per row `event-row-<id>` (with `data-ack="true|false"`), `event-sig-<id>`,
`event-path-<id>`, `event-occurrences-<id>` (only when more than one), `event-late-<id>`, `event-status-<id>`,
`event-ackby-<id>` (once acknowledged), and, admins only and only while open, `event-ack-<id>`. On the fleet
page: `fleet-open-<host>` and `fleet-count-open`; on a host page: `host-events`, `host-events-open`,
`host-events-all`, `host-no-events` and `host-virusevent`; on the alert target form: `alert-detection-burst`.

How the path is shown: an escape is `<span class="esc" title="...">\u{202E}</span>` (an invisible or
direction-changing character, or `\xNN` for a non-UTF-8 byte), and literal text is plain text, so a spec can
tell a real U+202E (an `.esc` element) from a file literally named `\u{202E}` (text). The raw characters
(U+202E, U+2028) must never appear in the HTML.

**Acknowledging.** As admin, `event-ack-<id>` is an htmx form: the row swaps to "Acknowledged by
admin@fixture.example" without a page load and with no console or CSP error; a reload keeps it, `nav-events-count`
is one lower and `fleet-open-<host>` follows. A viewer's page has no `event-ack-*` or `events-bulk-*` at all,
and a `POST /events/<id>/ack` from the page context with the CSRF token answers 403.

### SSO in the fixture (`--sso`)

`bin/webfixture --sso` starts two in-process fakes on loopback next to the server and switches `auth.oidc` and `auth.ldap`
on in the real server's configuration (the secrets are in files in the temp directory, as in production):
`internal/testoidc`, an OpenID Connect provider, and `internal/testldap`, a directory with one user. `fixture.json` gains `sso`:
`issuer_url`, `button_text`, the provider's user keys `oidc_admin` (`sso-admin`), `oidc_viewer` (`sso-viewer`) and
`oidc_norole` (`sso-norole`, who has no groups claim at all), and `ldap_admin` (`ldap-admin`, a user name, with a password).

**Two sites.** The console is `https://127.0.0.1:<port>` and the provider `https://localhost:<port2>` (the test certificate
covers both names). Ports do not make sites different: with both on 127.0.0.1 even a `SameSite=Strict` cookie would be sent
and the browser test of the Lax state cookie would pass for nothing. `sso.spec.ts` asserts first that the callback request
carried `Sec-Fetch-Site: cross-site` (read with Playwright's `request.allHeaders()`; the fixture could record it, but
the browser is the one place that sees the header it actually sent).

`make e2e-web` starts both of its fixtures with `--sso`, so every local sign-in and two-factor spec runs with the SSO button
and the "Email or user name" field present. The state cookie, the redirect chain, the cross-origin check on the start form and
the button are only provable in a browser: the first run of `sso.spec.ts` found that Chromium blocks a redirect out of a form
under `form-action 'self'` (see [auth.md](auth.md)).

## The IdP container (`make e2e-idp`)

OpenLDAP and Keycloak in a throwaway Debian 13 container, `clamfleet-idp`, on the Incus host (M6 decision 11). The
real `clamfleet-server` runs **inside** it, so nothing is exposed: slapd is on `127.0.0.1:389`, Keycloak on `127.0.0.1:8080`
and the console on `127.0.0.1:8443`, all inside the container. Set `CFI_EXEC` (the command prefix that runs a command in it, such
as `ssh <host> sudo incus exec clamfleet-idp --`) and `CFI_HOST` (the ssh target of the Incus host) in the environment or in
`local.mk`; without them the target **fails**, it never skips. The container has a snapshot `clean`, restored before every
scenario by `deploy/test/idp-prepare.sh`, which waits until both providers answer (Keycloak's dev mode needs about a minute).

What the container holds (made by hand by the sysadmin agent on 2026-11-16, **not** scripted in the repository: if you rebuild it,
rebuild exactly this and take a new `clean` snapshot). All credentials are test-only and are in `e2e/idp_e2e_test.go`.

- **OpenLDAP** (Debian's slapd) with the memberOf overlay, `ldap://127.0.0.1:389` with **StartTLS** (use the IP, not `localhost`: the
  certificate names `127.0.0.1`), the test CA in `/etc/clamfleet-idp/ca.crt`. Base `dc=example,dc=test`, `ou=people` with `alice`,
  `bob` and `carol` (password `<name>-test-pw`, mail `<name>@example.test`), `ou=groups` with `cn=clamfleet-admins` (alice) and
  `cn=clamfleet-viewers` (bob), a read-only service account `cn=clamfleet-ro,dc=example,dc=test`. Carol is in no group.
- **Keycloak 26.8.2** in `start-dev` on Debian's OpenJDK, bound to loopback (`keycloak.service`, the bootstrap administrator
  in `/etc/keycloak.env`). Realm `clamfleet`, a confidential client `clamfleet` with **PKCE S256 required** and the redirect URIs
  `http(s)://127.0.0.1:8443/*`, a Group Membership mapper that puts the short group names in `groups`, and the same three users
  and two groups. A user in no group gets **no** `groups` claim (missing, not empty).
- Gotchas of the build: the Incus host's default profile has no disk or network, so `incus launch -s default` and add a NIC on
  `incusbr0`; switch LLMNR off (systemd-resolved listens on 0.0.0.0:5355 otherwise); Keycloak's login form action contains `&amp;`.

The suite is built with `-tags e2e_idp` and **without** the `e2e` tag (this container has no clamd, and the ClamAV suite's
`TestMain` restores a ClamAV snapshot). It pushes the server and `e2e/idpdriver`, a small Go program that plays a browser: it
posts the console's forms and, for OIDC, submits Keycloak's login form (the action is parsed out of the page and unescaped).

- `TestLDAPAgainstOpenLDAP`: sign-in over StartTLS; admin, viewer, and a user in no group refused with the "no role" page and no
  user created; a wrong password; by uid and by mail; `entryUUID` is the stored identity; after alice moves between groups the next
  sign-in has the new role on the same row.
- `TestOIDCAgainstKeycloak`: the code flow with PKCE; the role from the `groups` claim; carol (no claim) refused as "no role";
  a wrong password never leaves Keycloak; the identity is issuer + subject; after the group changes in Keycloak (through `kcadm.sh`)
  the next sign-in has the new role.
- Active Directory is **not** tested (no Samba AD DC): `auth.md` marks it "configuration documented, untested".

## Re-recording fixtures (`make fixtures`)

`deploy/test/capture-fixtures.sh` re-records `internal/agent/testdata` from the container
(see `testdata/README.md`). It contacts the signature CDN twice at most per run (one freshclam
daemon start, one `LogTime no` run). Do not run it in a loop; `SKIP_FRESHCLAM=1` skips every step
that touches the network.

The script scrubs private names from what it records and aborts if one survives. Generic patterns
(RFC 1918 addresses, `.incus`/`.lan`/`.internal`/`.local` names) are built in; your own host names
go in `deploy/test/scrub-private.txt` (gitignored, one per line, see
`scrub-private.txt.example`).
