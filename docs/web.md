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
(user management in the console, TOTP, LDAP and OIDC come later). Run the commands as the server
user, so the audit log names you:

```
sudo -u clamfleet-server clamfleet-server user add ann@example.com --role admin
sudo -u clamfleet-server clamfleet-server user list [--json]
sudo -u clamfleet-server clamfleet-server user set-role ann@example.com viewer
sudo -u clamfleet-server clamfleet-server user disable ann@example.com     # and: enable
sudo -u clamfleet-server clamfleet-server user reset-password ann@example.com
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

### Known limit: disable and enable within one login

A session is only created if the user still has the password hash that the login verified and is not
disabled, so a password reset, a password change or a disable that commits while a login is hashing
leaves that login without a session. One window stays open: if an admin disables a user and enables
them again while that user's login is hashing (a few tens of milliseconds), the hash is unchanged and
the login succeeds. Closing it would need a per-user version counter (a schema change). Enabling a user
ends the sessions that existed at that moment.

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

`users` holds email addresses and `audit_log` holds the emails typed at login plus client IP
addresses. All of it stays in your database. Deleting a user is not available; the audit rows keep the
email as text, and retention for the audit log arrives with a later milestone.

## Pages

| Path | Who | What |
|---|---|---|
| `/login` | everyone | sign in |
| `/` | signed in | fleet: state counts, filters by tag and state, one row per host, worst state first |
| `/hosts/NAME` | signed in | state and reasons, newest report, state history; admins also see audit rows and actions |
| `/account` | signed in | change your password |
| `/admin/hosts` | admin | all hosts including revoked ones; register, rotate, revoke, delete (type the name to confirm) |

Revoked hosts are not on the fleet page, because their state is frozen.
