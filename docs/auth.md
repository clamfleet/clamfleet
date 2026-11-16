<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# External sign-in: LDAP and OpenID Connect

The console signs people in three ways, in any combination: **local accounts** (email and password, with
optional two-factor, see `web.md`), **one LDAP directory**, and **one OpenID Connect (OIDC) provider**. Each is its
own `auth:` subtree and each is off unless you switch it on (local accounts are on by default). Keep a local
break-glass admin when you turn the others on: it is the way back in when the directory or the provider is down.

| | Local | LDAP | OIDC |
|---|---|---|---|
| Where the password is checked | ClamFleet (argon2id) | your directory (a bind) | the provider |
| Second factor | TOTP in ClamFleet | **none** (password only) | the provider's |
| Where the role comes from | the CLI or admin | the user's groups, at every sign-in | a claim of the ID token, at every sign-in |
| How a person signs in | the form | the same form, with a user name | the "Single sign-on" button |
| Who they are (the stable identity) | the email | the `entryUUID` / `objectGUID` | the issuer and the subject |

All keys are in `configuration.md` with their environment names. Secrets (the LDAP bind password, the OIDC client
secret) are **only** read from files that follow the key-file rule (`root:clamfleet-server 0640`, or the server user
with `0600`), never from YAML or the environment.

## Rules that hold for both

- **External accounts are created at their first sign-in** and are never linked to a local account. A local user
  and an LDAP user with the same email are two different accounts, and the second one cannot sign in (below).
- **The role is decided at every sign-in** from the user's groups or claim, and replaces the stored one (an audit
  row `user.role.mapped` says from and to). Admin wins if any admin value matches, otherwise viewer if any viewer value
  matches, **otherwise the sign-in is refused** ("No role is assigned to your account"). There is no default role.
- **A removal at the provider takes effect at the next sign-in**, or when the session ends (12 h absolute by default,
  `auth.session_max_age`). To cut someone off now: `sudo -u clamfleet-server clamfleet-server user disable ldap:alice`
  (or `oidc:alice`, or the email). It ends their sessions at once.
- **The CLI does not change what the provider owns.** `user set-role`, `user reset-password` and `user reset-totp`
  refuse an LDAP or OIDC user with the reason and exit 1: the role would be overwritten at the next sign-in, and the
  password and second factor are not ClamFleet's. `disable`, `enable` and `list` work. `user list` shows the source;
  `user list --json` also shows `external_name` and `external_id`.
- **Switching a provider off ends its users' sessions** at their next request (a session is valid only while its
  user's source is enabled). The same is true of `auth.local.enabled: false` for local users: that is a change from
  milestone 3, where such sessions kept working.
- **An unknown source is never trusted.** A session of a user whose source this build does not know is no session
  at all, and the two-factor requirement (`auth.local.totp_required`) exempts **only** `ldap` and `oidc`.
- **Names and emails come from the provider** and are refreshed at each sign-in. There is no `user delete` yet
  (`disable` only), so an external user's name and email stay in the database after they leave.

### An email that belongs to another account refuses the sign-in

Linking accounts by email is how accounts get taken over, so ClamFleet never does it. If the email a provider
presents belongs to **another** user (a local one, or another external one), the sign-in is refused with
"This sign-in method is not available for this account", nothing is created or changed, and the audit row of the
failed sign-in says `email in use`. The same applies to an existing external user whose email changed at the
provider into someone else's address: the stored email stays as it was.

To resolve it, make the addresses differ: change or remove the `mail` attribute (LDAP) or the email at the provider.
An OIDC email is only used when the provider says `email_verified: true`; without it the user is stored with no
email, and is named `oidc:<preferred_username>` in the audit log and on the page.

### Where a person is named

The audit actor, "acknowledged by" and the page header show the email, or `source:name` for a user without one
(`oidc:alice`, `ldap:alice`). The audit row of a failed sign-in holds what was typed (cut to 254 bytes), the client
IP and the reason, **never** a password. The DN of an LDAP user is in the audit row of a **successful** sign-in only.

## LDAP

ClamFleet signs a user in by **search, then bind**: it searches the directory (as a service account, or anonymously)
for the entry that matches what was typed, then binds as that entry's DN with the typed password. The password check
is the directory's.

```yaml
auth:
  ldap:
    enabled: true
    url: ldaps://ldap.example:636            # or ldap://ldap.example with start_tls: true
    ca_file: /etc/clamfleet/ldap-ca.pem      # extra trust anchors; verification is never skipped
    bind_dn: cn=clamfleet-ro,dc=example,dc=org
    bind_password_file: /etc/clamfleet/ldap-bind-password
    user_base_dn: ou=people,dc=example,dc=org
    user_filter: "(&(objectClass=inetOrgPerson)(|(uid={username})(mail={username})))"
    id_attribute: entryUUID
    admin_groups:  ["cn=clamfleet-admins,ou=groups,dc=example,dc=org"]
    viewer_groups: ["cn=clamfleet-viewers,ou=groups,dc=example,dc=org"]
```

The login form then reads "Email or user name", and accepts either. **A local account with exactly the typed email is
tried first**, and only its password is checked: LDAP is never asked. That way a directory entry cannot shadow a
local admin. Anything else is looked up in the directory.

- **Encryption is required.** Use `ldaps://`, or `ldap://` with `start_tls: true`. Plain `ldap://` is accepted only
  for a directory on the same machine (a loopback host): there is no exception for private networks, because LDAP carries
  every user's password. A failed StartTLS ends the attempt; there is no fallback to plaintext. The certificate is
  always verified (TLS 1.2 or later), against the system roots plus `ca_file`.
- **`{username}` is escaped** (RFC 4515) before it goes into the filter, so a name such as `*)(uid=*` is a literal
  value that matches nothing. The search asks for at most two entries and **anything other than exactly one is a
  refusal**: two matching entries never pick one at random.
- **An empty password is refused before anything is sent.** A bind with a name and an empty password is an
  "unauthenticated bind", which many servers answer with success (RFC 4513 section 5.1.2).
- **`id_attribute` is the identity.** Use `entryUUID` (OpenLDAP, 389-ds) or `objectGUID` (Active Directory; a binary
  value, stored as hex). Never the DN: it changes when an entry is renamed, and a renamed user must stay the same user.
- **Groups** come from the user entry (`group_attribute`, default `memberOf`, which needs the memberOf overlay on
  OpenLDAP) or, with `group_attribute: ""`, from a search under `group_base_dn` with `group_filter` (`{dn}` is the
  user's DN, escaped). DNs are compared case-insensitively with the spaces around `=` and `,` removed.
- **A directory that is down or misbehaving** is a "could not be reached" page (503), audited as `ldap: unavailable`,
  and it does not count against the sign-in throttle. A wrong password or an unknown name is the same generic text as
  for a local account, and is throttled per typed name (5 free failures, then a growing wait).
- **LDAP sign-ins are password-only.** LDAP has no second factor ClamFleet can enforce, so
  `auth.local.totp_required` does not apply to LDAP users, and the server warns at start when both are on. Where a second
  factor matters, use OIDC and let the provider enforce it.
- **Timing:** when LDAP is on, the response time can tell whether an email has a *local* account (the local path hashes,
  the LDAP path binds). The throttle bounds probing. This is accepted and stated here rather than hidden.
- **The throttle's key is the name as typed**, so `alice` and `alice@example.org` are two keys, and an attacker can rotate
  spellings. The directory's own lockout policy (OpenLDAP `ppolicy`, AD account lockout) is the real defence against password
  guessing; turn it on.
- At most **4 sign-ins** talk to the directory at once; each connection lives for one sign-in, and each operation is
  bounded by `auth.ldap.timeout` (default 10 s).

### Active Directory

Configuration documented, **untested** (there is no Active Directory server in the test setup): `id_attribute: objectGUID`,
`username_attribute: sAMAccountName`, `user_filter: "(&(objectClass=user)(sAMAccountName={username}))"`, groups through
`memberOf` (direct membership only), or, for nested groups, `group_attribute: ""` with
`group_filter: "(member:1.2.840.113556.1.4.1941:={dn})"`. Use `ldaps://` on port 636 with your domain's CA in
`ca_file`.

## OpenID Connect

ClamFleet runs the **authorization code flow with PKCE (S256)**, `state` and `nonce`. It needs `public_url`: the
provider is told to send the browser back to `public_url/login/oidc/callback` (no path prefix, as for alert links).

```yaml
public_url: https://clamfleet.example
auth:
  oidc:
    enabled: true
    display_name: "Sign in with Keycloak"           # the button text
    issuer: https://id.example/realms/main
    client_id: clamfleet
    client_secret_file: /etc/clamfleet/oidc-client-secret
    role_claim: groups                                 # a dotted path: realm_access.roles
    admin_values:  [clamfleet-admins]
    viewer_values: [clamfleet-viewers]
```

### Keycloak

1. Create a client with the ID `clamfleet`: **Client authentication on** (confidential), **Standard flow** on, everything
   else off (no implicit, no direct access grants). Under *Advanced*, set **Proof Key for Code Exchange Code Challenge
   Method** to `S256`.
2. **Valid redirect URIs:** exactly `https://clamfleet.example/login/oidc/callback`. Copy the secret from *Credentials*
   into the `client_secret_file`.
3. Add a **Group Membership** mapper to the client's dedicated scope (token claim name `groups`, **Full group path off**,
   *Add to ID token* on). The values are then the short group names.
4. `issuer` is `https://<host>/realms/<realm>`.

A user who is in **no group gets no `groups` claim at all** (the claim is missing, not empty). That is "no role": the
sign-in is refused with the "No role is assigned" page, which is not an error.

### What is checked

The ID token comes straight from the provider's token endpoint over TLS that ClamFleet verified, in answer to a code only
this server can redeem (it holds the PKCE verifier). OpenID Connect Core 1.0 section 3.1.3.7 rule 6 allows the TLS check
to **replace the signature check** in exactly that case, and ClamFleet relies on it: **the signature of the ID token is not
verified**, and there is no JOSE library in the binary. Everything else is checked: the token is a compact JWS of three parts
(an encrypted 5-part token, and `alg: none`, are refused), `iss` equals the configured issuer exactly, `aud` contains the
client ID, `azp` is required with several audiences and must equal the client ID whenever it is present, `exp`, `iat`
and `nbf` are in range (a minute of clock skew is allowed), the `nonce` is the stored one, and `sub` is 1 to 255 bytes.

If you need front-channel tokens, encrypted ID tokens or back-channel logout, you need signature verification, and a
different implementation. For contributors: this is why those are out of scope, not an oversight.

- **One-time state.** Each sign-in has a row (state, nonce, verifier) found only through the hash of a
  `__Host-clamfleet_oidc` cookie (Secure, HttpOnly, **SameSite=Lax**, 10 minutes). The callback takes the row, once: a
  callback URL used a second time, opened in another browser, or after ten minutes, shows "This sign-in has expired or was
  already used" and signs nobody in. The row is gone whatever else is wrong with that callback. Starting a sign-in needs no
  session, so two bounds apply: **one client IP may have 15 sign-ins in progress** (the 16th start gets a 429 page until
  the others finish or expire after ten minutes; the address is the one the console logs, so set `trusted_proxies` behind a
  proxy or every visitor shares the proxy's), and at most 10,000 are in progress in all. Without the first, one host could fill
  the table and switch SSO off for everybody. The count is in memory: a restart forgets it.
- **Why SameSite=Lax:** the provider returns the browser with a top-level GET from another site. A Strict cookie is not sent on
  that navigation and every sign-in would fail. This is tested in a real browser with the console and the provider on two
  different sites (`e2e/web/tests/sso.spec.ts`).
- **The start page.** `POST /login/oidc` answers with a page whose meta refresh (and a "continue" link) goes to the provider,
  not with a redirect: the console's Content-Security-Policy says `form-action 'self'`, and Chromium blocks a redirect from a
  form to another origin. The policy was left strict.
- **Discovery** (`issuer/.well-known/openid-configuration`) is fetched at the first sign-in, cached for an hour and
  fetched again after a failed exchange. Its `issuer` must equal `auth.oidc.issuer` exactly, and its endpoints must be
  https (http only to a loopback host, for tests). Every request to the provider uses TLS 1.2 or later with verification,
  follows no redirect, has the `auth.oidc.timeout`, must answer JSON, and is bounded (256 KiB for discovery, 1 MiB for the
  token response). **A provider that is down when the server starts only disables SSO** until it comes back: the console
  starts, the button shows an error page, and local and LDAP sign-in are not affected.
- **Logout** ends ClamFleet's session only. The provider's own session stays (RP-initiated logout is not built).
  ClamFleet stores no access, refresh or ID token.
- **No per-user throttle.** There is no guessable secret at ClamFleet in this flow.

## Two-factor sign-in and the external sources

`auth.local.totp_required` makes every user without an authenticator enrol one before anything else. It covers **local
users only** by design: the provider owns an OIDC user's second factor, and LDAP has none (above). The exempt list is
explicit, `{ldap, oidc}`, in `internal/webauth/middleware.go`; **a source that is not on it is gated, and a source that
is not in `Manager.Sources` has no sessions at all**. A contributor who adds a source (SAML, a second directory) must
add it to `Manager.Sources` through `Auth.EnabledSources`, and to the exempt list only deliberately: forgetting the second
fails safe (the user is made to enrol), where the milestone 3 test `source == local` failed open.

The TOTP pages explain this to an external user, and every change there is refused (403). The account page shows the
source and the name, and no password or two-factor card.

## Reading the audit log

| Action | Meaning |
|---|---|
| `user.add` | an external user was created at their first sign-in (`{role, source}`) |
| `user.login` | `{source, ip}`, plus `dn` for LDAP |
| `user.role.mapped` | the role changed at sign-in (`{from, to}`) |
| `user.login.failed` | the reason is one of: `ldap: invalid credentials`, `ldap: no unique entry`, `ldap: empty password`, `ldap: invalid user name`, `ldap: unavailable`, `no role`, `email in use`, `user disabled`, or an `oidc:` reason naming the check that failed (`oidc: id token nonce does not match`, `oidc: state used, expired or unknown`, ...) |

## Testing

- **In process:** `internal/testldap` and `internal/testoidc` are small fakes of both protocols. They record what they
  received (the filter as it arrived on the wire, whether a bind was encrypted, the PKCE parameters) and can misbehave on
  command, so the tests assert on the wire and not only on the outcome.
- **Real servers:** `make e2e-idp` runs the real server against OpenLDAP (StartTLS, memberOf) and Keycloak, inside a
  throwaway container (`testing.md`). Active Directory is not tested.
- **Browser:** `make e2e-web` signs in through the fake provider on another site, and through LDAP.
