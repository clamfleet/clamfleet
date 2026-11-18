<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Decision log

Source comments, migrations and docs cite maintainer decisions as "M4 decision 19" (milestone 4, decision 19).
This file is where those citations resolve. Each line gives the outcome that was accepted, and the reason in a
few words; it is not the discussion. The milestone plans that held the full discussion are private working notes
and are not in the repository.

How to read it:

- Milestone 1 cites its decisions as "M1 Q<n>": its plan numbered them Q1 to Q10, and a few post-review decisions
  that no file cites by number.
- For milestones 2 to 6, the number is the position in the decision list of that milestone's plan. M6 covers 6a (packages, operations)
  and 6b (external sign-in); its decisions 16 to 22 are 6b's.
- Only decisions that a tracked file cites are listed. A decision no file refers to is not here.
- Plan-section references ("plan 4.8", `docs/plans/...`) appear only in older commits. They point at those private
  working notes. Nothing needs the plan to be understood: the user documentation in this directory describes the
  behaviour.
- Release 1.0 (distribution support) cites its decisions as "R1 decision <n>", numbered in the order of its section.
- A later decision can change an earlier one. The line says so where it matters.

## Milestone 1: the agent

- **M1 Q2, YAML module.** `go.yaml.in/yaml/v3`. Anything the specification names that is deprecated or unmaintained is
  replaced by its maintained successor from the start.
- **M1 Q4, socket activation.** The agent never starts clamd: it asks systemd for the unit's state first and does not
  touch the socket while the unit is inactive.
- **M1 Q6, other distributions.** Only Debian 13 is tested live. The RHEL 9 example configuration and its fixtures are
  hand-written, labelled untested, and real recordings are welcome. (Milestone 6 later tested the RHEL 9 family on
  AlmaLinux 9; see M6 decision 11.)
- **M1 Q7, copyright.** `SPDX-FileCopyrightText: The ClamFleet Authors`.
- **M1 Q8, freshclam state.** Read freshclam's entries from the systemd journal first, then its log file, then the
  database file modification times. The report says which source was used (`freshclam.source`).
- **M1 Q9, problems.** The payload has no `problems` field; problems go only to the agent's log (the journal).
- **Post-review decision 1, environment prefixes.** `CLAMFLEET_AGENT_` for the agent and `CLAMFLEET_SERVER_` for the
  server. This departs from the specification's single `CLAMFLEET_CONFIG`.

## Milestone 2: ingest and storage

- **M2 decision 1, timestamps.** INTEGER unix seconds, UTC. Unambiguous, sortable, no driver time-format coupling.
- **M2 decision 2, deleting a host.** Cascade to everything that belongs to it. Long-term detection history is the
  job of the operator's central logging, and a cascade makes GDPR erasure simple.
- **M2 decision 3, server user.** The server runs as its own user `clamfleet-server` with its own state directory,
  so an agent and a server on one machine share no identity or directory.
- **M2 decision 7, deployment.** Behind a reverse proxy, plaintext on loopback only; the server refuses plaintext on
  any other address. Direct TLS (`tls.cert`, `tls.key`) is optional.
- **M2 decision 10, client IP.** Always logged in request lines. What happens to it is the operator's business.
- **M2 decision 11, mutual TLS.** Optional and off by default (`tls.client_ca` on the server, `tls.client_cert` and
  `tls.client_key` on the agent). The bearer token stays mandatory on top of a valid certificate.
- **M2 decision 12, trusted proxies.** `trusted_proxies` (default empty). Only when the direct peer is listed is the
  client IP taken from `X-Forwarded-For` (the rightmost address that is not itself a trusted proxy).

## Milestone 3: health, accounts, console

- **M3 decision 3, `auth:` shape.** One subtree per provider (`auth.local`, later `auth.ldap` and `auth.oidc`),
  several on at once, so a local break-glass admin can sit next to single sign-on.
- **M3 decision 4, STALE interval.** The agent reports its own interval; the server clamps it to 10 s to 24 h and
  evaluates "3 intervals" per host. Older agents fall back to the server's default.
- **M3 decision 5, first state of a host.** No state until the first evaluation. The first `state_changes` row has a
  NULL `from_state`, and alerting treats it as a change only when the new state is not OK.
- **M3 decision 6, health defaults.** A missing daily database is CRIT; a scan exit code of 2 or more is WARN (1 means
  infected, not a failure); a scan older than `scan_warn_hours` (48) is WARN; a freshclam unit that is not found counts
  as inactive.
- **M3 decision 11, `users` table.** `email` is nullable and UNIQUE; `auth_source` and `external_id` exist from the
  start; there are no CHECK constraints on role, source or state (validated in Go), so adding a value never needs a
  table rebuild.

## Milestone 4: alerting

- **M4 decision 5, retries.** At most 5 attempts per delivery, at once and then after about 1, 5, 15 and 60 minutes
  with jitter. Permanent failures (most 4xx, SMTP 5xx, authentication failures) stop at once. The schedule is fixed.
- **M4 decision 7, webhook signature.** The Standard Webhooks format (HMAC-SHA256 over id, timestamp and body). Every
  webhook target is signed; there is no unsigned option.
- **M4 decision 10, alert secrets the key cannot open.** The server still starts; the affected webhook targets fail
  with a clear error until their URL is re-entered. Unlike TOTP, which refuses to start.
- **M4 decision 11, SMTP.** The standard library's `net/smtp` plus a small in-repo layer, not `go-mail`. `starttls`
  is the default and has no plaintext fallback; the password lives only in a file, never in YAML or the environment.
- **M4 decision 12, `public_url`.** A top-level key used for links in alerts. The console has no path-prefix
  support, because `__Host-` cookies require `Path=/`.
- **M4 decision 17, syslog/CEF target.** Not in v1. Webhook JSON feeds SIEM collectors, and each alert is also one
  JSON log line in the journal for syslog forwarders.
- **M4 decision 18, who sees alert targets.** Administrators only. Recipient addresses and receiver hosts are
  configuration, not fleet state.
- **M4 decision 19, plaintext alert connections.** Allowed only to loopback and private addresses, checked on the
  address actually dialled, never to a public one. SMTP credentials go in plaintext only to loopback. Turning
  `allow_private` off turns off private plaintext as well. This relaxes the specification's "TLS on all connections".

## Milestone 5: detections

- **M5 decision 3, spool permissions.** clamd's group may add to the detections folder but not delete from it; the
  heartbeat and quarantine folders are the agent's alone. The configuration must be readable by clamd's user.
- **M5 decision 6, wiring check.** The report says whether `VirusEvent` is wired up; a WARN reason (which can be
  switched off) fires when it is not.
- **M5 decision 7, mandatory access control.** An AppArmor profile ships in the `.deb`, proven by an automated test on
  a Debian 13 VM with AppArmor enforcing (`make e2e-apparmor`). SELinux was checked with the packages in M6.
- **M5 decision 10, mass detections.** Per host and target, the first 10 detections in 10 minutes are sent one by one
  and the rest as one summary; a per-target limit where 0 means every detection.
- **M5 decision 12, file paths.** Every signed-in user sees them, escaped. They never appear in logs, audit rows or
  URLs.
- **M5 decision 14, backlog order.** After an outage, detections less than a minute old go first (newest first), then
  the backlog oldest first, so a fresh detection is heard within 30 seconds even behind a long backlog.
- **M5 decision 15, held detections.** If a target's detections are switched off, or the target is disabled, while a
  summary is held, that summary is discarded and one log line says how many. The detections stay stored.
- **M5 decision 16, event ids and file-name escaping.** The agent gives each detection a random id (resent unchanged
  on retry), old heartbeats sent from the backlog carry `replay`, and a backslash is sent as `\\` and an invalid byte
  as `\xNN`. All additive; the schema stays 1.

## Milestone 6: operations, packages and external sign-in

- **M6 decision 6, `/metrics`.** A small in-repo Prometheus text exposition, no dependency and no Go or process
  metrics.
- **M6 decision 7, who reads `/metrics`.** Off by default; when on, it requires a bearer token read from a file,
  because the page lists every host name.
- **M6 decision 9, install and removal.** Debian services are enabled and started; the RHEL family follows system
  presets. The first server install creates the secret key file. A purge never deletes the database or the key file.
- **M6 decision 10, SELinux.** A small module: one label for the detection spool and permission for clamd's domain to
  write there, and nothing else. It is installed at priority 300 only.
- **M6 decision 11, test machines.** (Superseded by R1 decision 1 for the machines: the Rocky Linux 10 VM and the
  Ubuntu runner job join them.) Throwaway machines: a Debian 13 VM with AppArmor, an AlmaLinux 9 VM with SELinux
  enforcing as the RHEL 9 stand-in, and a Debian 13 container with OpenLDAP and Keycloak for 6b.
- **M6 decision 12, Debian 12.** Not in the supported list; untested. (Superseded by R1 decision 4: Debian 12 is
  install-tested until 2028-06-30.)
- **M6 decision 13, container image.** None in v1.
- **M6 decision 15, certificate reload.** `systemctl reload` (SIGHUP) re-reads certificate, key and client CA, all or
  nothing; a broken new file keeps the old one.
- **M6 decision 16, LDAP library.** `github.com/go-ldap/ldap/v3`.
- **M6 decision 17, OIDC.** Standard library only: authorization code flow with PKCE, one-time state, every claim
  checked. The ID token comes from the token endpoint over verified TLS, so its signature is not checked
  (OIDC Core 3.1.3.7); no JOSE library. Front-channel tokens, encrypted ID tokens and back-channel logout would need
  signature checks and are not supported.
- **M6 decision 18, several sign-in methods.** One LDAP directory and one OIDC provider next to local accounts. The
  login form tries a local account with exactly that email first, so a directory entry can never shadow a local
  break-glass admin.
- **M6 decision 19, external identity.** Created at first sign-in with a stable identifier (`entryUUID` or
  `objectGUID`; OIDC issuer plus subject), never the DN. Never linked to a local account: an email that belongs to
  another user refuses the sign-in. An OIDC email counts only when the provider marks it verified.
- **M6 decision 20, roles of external users.** From groups (LDAP) or a claim (OIDC) at every sign-in; admin wins; no
  matching group means no access. The command line refuses to change their role or password. `user disable` and
  `enable` apply to everyone at once.
- **M6 decision 21, second factor and external users.** The "TOTP required" rule exempts only an explicit list (OIDC,
  where the provider owns the second factor, and LDAP). Any other or unknown source is gated. LDAP sign-ins are
  password-only, and the server warns at start when both are on.
- **M6 decision 22, LDAP encryption.** `ldaps://` or StartTLS, except to a directory on the same machine. Unlike
  alert receivers (M4 decision 19) there is no plaintext to private networks, because LDAP carries every user's
  password.

## Release 1.0: distribution support

Decided 2026-11-18. R1 decisions 1 and 4 supersede M6 decisions 11 and 12 and the specification's section 15, question 5
(`docs/HANDOVER.md`).

- **R1 decision 1, the test matrix.** Three Incus VMs run the full level-1 scenarios with the mandatory access control
  enforcing: Debian 13 (AppArmor), AlmaLinux 9 (SELinux) and Rocky Linux 10 (SELinux). Ubuntu 24.04 and 26.04 get the
  same level on the GitHub-hosted runner VM (AppArmor), on every ready pull request. Level 2 (a systemd container on a
  runner, on every ready pull request) covers Debian 12, Ubuntu 22.04, Rocky Linux 9 and AlmaLinux 10; Debian 13 stays
  the existing `e2e` job. One VM per release was rejected for its monthly snapshot refresh and RAM; the runner is free
  and already runs Ubuntu with AppArmor on.
- **R1 decision 2, EL vendors.** Rocky Linux is the bug-for-bug RHEL rebuild and AlmaLinux the ABI-compatible one; one of
  each is tested at both levels so the README can name both, and neither lets it say "tested on RHEL".
- **R1 decision 3, not supported.** EL8 has no test leg and is not supported. CentOS Stream and RHEL itself are
  "untested" (expected to work): Stream runs ahead of RHEL and would turn CI red for reasons that are not ours.
- **R1 decision 4, end dates.** Ubuntu 22.04 is supported until 2027-05-31 (the end of its standard support, and its
  runner image goes away in 2027-04, so it is a container leg only). Debian 12 is "install-tested, Debian LTS" until
  2028-06-30.
- **R1 decision 5, rc.1 and 1.0.0.** v1.0.0-rc.1 ships with its current claim (Debian 13, AlmaLinux 9). The matrix is
  built on `develop` during the soak and rc.2 carries the wider claim; a target still red at 1.0.0 is listed as
  "untested" instead of holding the release.
- **R1 decision 6, fork pull requests on the Incus host.** A level-1 run executes the pull request's code as root in
  VMs on the maintainer's machine. For a fork it is run only after the maintainer has read the diff and said so;
  `deploy/test/l1-guard.sh` is the speed bump (a pushed branch of this repository passes, anything else needs
  `L1_APPROVED` set to the full commit SHA). It is not a security boundary. Whether the VMs also lose their route
  to the LAN is a separate infrastructure change.
- **R1 decision 7, who needs a level-1 run.** The globs live in one file, `deploy/test/l1-paths.txt`; a non-required CI
  job prints the verdict in the job summary and the maintainer decides at merge. A commit status plus a gate job was
  rejected for now: a gate must be re-run after the status is posted. Every release candidate runs all level-1 targets.
- **R1 decision 8, adding a required check.** The new check is added to the `protect` ruleset after the pull request
  that adds the job has run (its run shows the exact check names, which a matrix generates) and before that pull
  request merges. Adding it earlier would mean guessing the names, and a wrong guess blocks every merge. Renaming or
  removing a required check still means the ruleset first, then the workflow.
