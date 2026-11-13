<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# The web console

The server serves a small console at the root of its origin: a fleet overview, a page per host, host
administration for admins, and a password page. It is server-rendered HTML with a little htmx
(vendored, no CDN) for the live fleet table. There is no JavaScript build step and no third-party
request from the browser.

Agents never use it: `/v1/*` accepts only the agent bearer token, and the console accepts only its
own session cookie. Neither credential works on the other's routes.

## Users and roles

Users are managed on the server with `clamfleet-server user ...` and nowhere else in this release
(user management in the console, LDAP and OIDC come later; two-factor sign-in is below). Run the commands as the server
user, so the audit log names you:

```
sudo -u clamfleet-server clamfleet-server user add ann@example.com --role admin
sudo -u clamfleet-server clamfleet-server user list [--json]
sudo -u clamfleet-server clamfleet-server user set-role ann@example.com viewer
sudo -u clamfleet-server clamfleet-server user disable ann@example.com     # and: enable
sudo -u clamfleet-server clamfleet-server user reset-password ann@example.com
sudo -u clamfleet-server clamfleet-server user reset-totp ann@example.com   # remove their authenticator
```

- **Roles:** `viewer` sees the fleet and the host pages. `admin` can also register, rotate, revoke and
  delete hosts. The role is read from the database on every request.
- **First password.** `user add` and `user reset-password` print a generated one-time password on
  stdout, once, and nothing else (so `PW=$(...)` works and it never lands in a log). The user must
  change it at first login: until then every page except the password page, sign-out and the static
  files redirects there. `--password-stdin` reads one line from stdin instead, for automation; that
  password is also treated as a one-time password. A password is never taken from the command line
  (it would show in `ps` and shell history).
- **Password rules:** 15 to 256 bytes, no composition rules. Passwords are stored as argon2id hashes
  (m=19456 KiB, t=2, p=1, PHC format); the parameters can be raised later and every hash is upgraded
  at the user's next login.
- **A fresh install has no users.** The login page then says so and shows the command. The server never
  creates an account by itself.
- **A locked-out admin** is recovered with `user reset-password` on the server: shell access to the
  server is the root of trust.
- Disabling a user, changing a role and resetting a password end that user's sessions at once.
  Changing your own password keeps the current session and ends the others.

## Sessions

A session is a random 256-bit token in a cookie; the database stores only its SHA-256. Defaults: 12 h
absolute and 1 h idle (`auth.session_max_age`, `auth.session_idle`). The fleet table polls every 15 s
and the polls count as activity, so an open tab stays signed in until the absolute limit and then goes
to the login page. For an unattended wall display raise `auth.session_max_age` (up to 720h); a
separate read-only display token is not available.

The cookie is `__Host-clamfleet_session` with `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/` and no
`Domain`; it has no expiry date of its own (the server enforces the limits). A fresh token is issued at
every login.

A session is created only if nothing about the account changed while the password was being checked:
a password reset or change, a disable, or a disable followed by an enable (a per-user `auth_version`
counter catches the last one) leaves that login without a session.

## Two-factor sign-in (TOTP)

A local user can protect their account with an authenticator app (any app for time-based one-time
passwords: Aegis, 2FAS, Google Authenticator, a password manager). It is optional per user, or required
for everyone with `auth.local.totp_required: true` (below). Accounts that sign in through an identity
provider (LDAP, OIDC; later milestones) are not offered it: their second factor is the provider's.

**Setting it up** (Account, then "Two-factor sign-in"):

1. Enter your current password. Every change to two-factor sign-in asks for it again, the first set-up
   included, so a stolen session cookie alone cannot plant someone else's authenticator.
2. The page shows the key as text, in groups of four, and the same key as an `otpauth://` setup URI. There
   is no QR code: add the account in your app by typing the key (time-based, 6 digits, 30 seconds, SHA-1
   are the defaults of every app) or by pasting the URI where the app accepts one. No third party ever
   sees the key.
3. Enter the 6-digit code the app shows. Only then is it switched on. You then see 10 **recovery codes**,
   once. Store them like a password; each works once, if you lose your phone.

Switching it on ends your other sessions. An unfinished set-up expires after 15 minutes and belongs to the
browser session that started it.

**Signing in** takes two steps. After the right password you are sent to a second page and are **not**
signed in yet (the pending login is a separate, short-lived record with its own cookie, valid for 5 minutes,
and cannot be used as a session). Enter the code from the app, or one recovery code. A code works once: the
same code is refused a second time even inside its 90-second window. If every code is refused, check
that the phone's clock is set automatically; the server's clock must be right too (run NTP, for example
systemd-timesyncd), because the server accepts the code of the current 30 seconds and one step either side.

After a recovery code the page tells you how many are left. "New recovery codes" (password needed) replaces
all of them. "Turn off" (password needed) removes the authenticator and the codes and ends your other
sessions; it is not offered when TOTP is required.

**Wrong codes.** They are slowed like wrong passwords (5 free attempts, then 30 s, doubling to 15 min), and
after **100 consecutive wrong codes** the second factor is locked: even the right code is refused. That
only a holder of the password can cause, so treat a lock as a sign the password is known: **reset the
password** (`user reset-password`, which also lifts the lock) or reset the authenticator (`user reset-totp`).
Everything is audited: `user.login` with `mfa` = `totp` or `recovery_code`, `user.login.failed` with the
reason, `user.totp.enable`, `.replace`, `.disable`, `.reset`, `.recovery.regenerate` and `.locked`. A code,
a secret or a recovery code is never written to the audit log or the log.

**An administrator's reset** is `user reset-totp EMAIL` on the server. It removes the authenticator and the
recovery codes, lifts a lock and ends the user's sessions and pending logins. It needs no key file. `user
list` shows each user's TOTP state (`off`, `on`, `locked`).

### Requiring it for everyone

`auth.local.totp_required: true` (or `CLAMFLEET_SERVER_AUTH_LOCAL_TOTP_REQUIRED=true`) makes every local
user enrol. A user without an authenticator can then open only the set-up pages and sign out, on every
request and in sessions that already exist; a user with a one-time password changes it first and enrols in
the same session. Turning it off again leaves enrolled users enrolled.

**Trust on first use.** Until a user has enrolled, their password alone is enough to enrol. Switch the
setting on **before** handing out one-time passwords, so the first thing a new user does is set up their
authenticator, and treat a password issued earlier as unprotected until its owner has enrolled. An
administrator-issued enrolment code would remove this; it is not built.

## The secret key file

TOTP secrets and the URLs and signing keys of webhook alert targets are stored encrypted (AES-256-GCM) with a key from a file, `secret_key_file` (default
`/etc/clamfleet/server-secret.key`). The key is not in the database, and a backup of the database does not
carry it. Recovery codes are stored as SHA-256 hashes and do not depend on the key.

```
sudo clamfleet-server key generate                     # as root: creates the file, mode 0600, never overwrites
sudo chgrp clamfleet-server /etc/clamfleet/server-secret.key
sudo chmod 0640 /etc/clamfleet/server-secret.key
```

- **Ownership and mode.** `root:clamfleet-server` `0640`, or the server user with `0600`. The server
  **refuses to start** with a key file that others can read, that its group can write, or that is a
  symbolic link or not a key file at all: a file that exists must be valid.
- **Keep it out of the state directory and back it up separately.** A backup that holds the database and
  the key protects nothing.
- **Start-up checks.** No key file and nobody uses TOTP: the server starts and logs a warning, TOTP is
  unavailable (a TOTP user's password alone is never enough: the second step answers 503 for a code, and a
  recovery code still works). With `totp_required` on, or with users who have TOTP, and no key file: it
  refuses to start and says how many. With a key file that cannot open every stored secret: it refuses to
  start and names the count. Webhook alert targets are the exception: when their secrets cannot be opened
  (no key file, a retired key) the server starts, logs the count and the fix, and only those targets' alerts
  fail (see [alerts.md](alerts.md#key-rotation)).
- **Rotation.** `key generate --add` puts a new key at the top of the file (the first key seals, every key
  opens); restart the server; `sudo -u clamfleet-server clamfleet-server key reencrypt` re-seals every
  secret (TOTP and webhook targets) with the new key in one transaction (audited, safe to repeat; it exits 1
  with `incomplete` when a row changed meanwhile: run it again); `key check` must exit 0 (it opens every secret
  and reports how many still use an older key); only then delete the old key line; restart. The
  server reads the file only at start. An enrolment that was in progress during a rotation has to be
  started again.
- **A lost key.** The enrolments cannot be opened and the server refuses to start. Create a new key with
  `key generate` (move the broken file away first), run `user reset-totp EMAIL` for each user listed by
  `user list` with TOTP `on` or `locked` (anything but `off`), and start the server. Users enrol again (at once, with `totp_required`).
  If the old key turns up, restoring it also works.

## Protection against forged requests (CSRF)

Three layers, all on:

1. the cookie is `SameSite=Lax`;
2. every non-GET request is checked by Go's `http.CrossOriginProtection` (the browser's
   `Sec-Fetch-Site`, or `Origin` against `Host` for old browsers), which also covers the login form;
3. every non-GET request of a signed-in user must carry the session's CSRF token, in a hidden form field
   or the `X-CSRF-Token` header (htmx sets it for you).

## Login protection

- One generic error for every failed login, and every attempt costs one password verification (a dummy
  one for an unknown email), so neither the text nor the timing says whether an account exists.
- After 5 failed logins for one email within 15 minutes, only one attempt per 30 s is answered, doubling
  up to 15 min; a success resets it. There is no hard lockout (it would let anyone lock an admin out)
  and no per-IP limit in the server. The state is in memory and a restart forgets it.
- At most 4 password hashes run at once (about 76 MiB), so a flood of logins cannot exhaust memory.
- Every failure is written to the audit log (`user.login.failed`, with the typed email, the client IP
  and the reason) and logged at warn with the IP only. Successful logins, logouts, password changes,
  user changes and every host change made in the console are audited too (`actor_kind` = `user`,
  `actor` = the email).
- **Rate limiting per IP belongs in your reverse proxy.** The client IP the server sees is only as good
  as `trusted_proxies`, and it is logging-only by design.

## Reverse proxy and TLS

The console must be served at the root of its origin, over HTTPS (`__Host-` cookies need a secure
context). A path prefix works for the agent API but not for the console in this release. The proxy
should pass `Host` unchanged and set `X-Forwarded-For` (see the README); the cross-origin check
compares `Origin` with `Host` for browsers that send no `Sec-Fetch-Site` (every browser since 2023
does).

Over plain HTTP, for development through an SSH tunnel only, set `auth.cookie_secure: false`: the
cookie loses `Secure` and the `__Host-` prefix, and the server logs a warning at start.

## What the console never does

- It shows an agent token exactly once, when you register a host or rotate its token, on a page the
  browser must not cache. The token is not in the log, the audit row or the database.
- Everything an agent reports (tags, host name, versions, error messages) is escaped on output. The
  Content-Security-Policy allows only same-origin resources and no inline script or style, and
  forbids framing.
- It keeps no browser-side copy of fleet data: htmx's history snapshots are switched off.

## Privacy

Detection events hold file paths, which can name a person's files: they are shown to every signed-in user,
escaped, and never appear in a URL, a log line or an audit row; `retention.events_days` deletes them
(see [detections.md](detections.md#retention-and-privacy)). `users` holds email addresses and `audit_log` holds the emails typed at login plus client IP
addresses. With two-factor sign-in, `users` also holds each user's encrypted TOTP secret, the last
accepted time step and a failure counter, and the database holds the SHA-256 of each recovery code. All of
it stays in your database: no QR-code service, no CDN, no other third party is involved. Deleting a user is not available; the audit rows keep the
email as text, and retention for the audit log arrives with a later milestone. Alerting adds recipient
addresses (in a target's configuration and, per delivery, in the delivery and log rows, pruned after 90 days
or with the target) and the payloads sent to the receivers you choose; see [alerts.md](alerts.md#privacy).

## Pages

| Path | Who | What |
|---|---|---|
| `/login` | everyone | sign in |
| `/login/totp` | everyone, with a pending login | the second step: a code from the authenticator app or a recovery code |
| `/` | signed in | fleet: state counts, filters by tag and state, one row per host, worst state first |
| `/hosts/NAME` | signed in | state and reasons, newest report, a Detections card, state history; admins also see audit rows and actions |
| `/events` | signed in | detections: filters by host, signature and state (Open by default), 50 per page by keyset, open counts in the menu; **admins** acknowledge one detection or all matching "as of this id" (see [detections.md](detections.md)). File paths are shown to every signed-in user, with invisible and direction-changing characters as visible escapes |
| `/account` | signed in | change your password; a card for two-factor sign-in |
| `/account/totp` | signed in | set up, replace or turn off the authenticator; new recovery codes (each asks for your password) |
| `/admin/hosts` | admin | all hosts including revoked ones; register, rotate, revoke, delete (type the name to confirm) |
| `/admin/alerts` | admin | alert targets, banners that say why alerts may not go out, recent deliveries; add, edit, send test, rotate the signing key, delete (see [alerts.md](alerts.md)). Viewers see no menu item and get 403 |

Revoked hosts are not on the fleet page, because their state is frozen.
