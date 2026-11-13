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
keeps working.

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

## Re-recording fixtures (`make fixtures`)

`deploy/test/capture-fixtures.sh` re-records `internal/agent/testdata` from the container
(see `testdata/README.md`). It contacts the signature CDN twice at most per run (one freshclam
daemon start, one `LogTime no` run). Do not run it in a loop; `SKIP_FRESHCLAM=1` skips every step
that touches the network.

The script scrubs private names from what it records and aborts if one survives. Generic patterns
(RFC 1918 addresses, `.incus`/`.lan`/`.internal`/`.local` names) are built in; your own host names
go in `deploy/test/scrub-private.txt` (gitignored, one per line, see
`scrub-private.txt.example`).
