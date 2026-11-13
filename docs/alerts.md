<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Alerts

ClamFleet sends an alert when a host changes state (including recovery to OK) and when a detection arrives.
Targets are email addresses and webhooks. Admins manage them under **Alerts** in the console, or with
`clamfleet-server alert ...`. This page is the reference: setup, semantics, the payload, how to verify the
signature, the network policy, key rotation and troubleshooting.

## Contents

1. [Set up](#set-up)
2. [Targets](#targets)
3. [What is sent, and when](#what-is-sent-and-when)
4. [Delivery, retries and the log](#delivery-retries-and-the-log)
5. [Payload reference (schema 1)](#payload-reference-schema-1)
6. [Verifying the signature](#verifying-the-signature)
7. [Where a webhook may connect](#where-a-webhook-may-connect)
8. [The command line](#the-command-line)
9. [Key rotation](#key-rotation)
10. [Privacy](#privacy)
11. [Troubleshooting](#troubleshooting)

## Set up

Everything is in `/etc/clamfleet/server.yaml` (see `deploy/server.yaml.example`); every key also has an
environment variable, `CLAMFLEET_SERVER_` plus the key path in capitals.

```yaml
public_url: https://clamfleet.example      # links in alerts point here; empty = links are null
alert:
  cooldown: 15m
  webhook: {timeout: 10s, allow_private: true, allow_loopback: false, deny_networks: []}
smtp:
  host: smtp.example
  port: 587
  tls: starttls
  from: clamfleet@example.org
  username: clamfleet
  password_file: /etc/clamfleet/smtp.pass
```

**Email** needs `smtp.host` and `smtp.from`. Without `smtp.host`, email is off: creating an email target is
refused, existing email deliveries fail with "email is not configured", and the Alerts page says so.

- `smtp.tls: starttls` (default, port 587): the connection is upgraded to TLS before anything else. If the
  server does not offer STARTTLS the attempt **fails**; there is no fallback to plaintext.
- `smtp.tls: tls`: implicit TLS from the first byte (port 465).
- `smtp.tls: none`: plaintext. Only for a relay on a **loopback or private address** (a hostname is checked
  on the address it resolves to), and credentials are never sent unencrypted beyond loopback: `none` with
  `smtp.username` is refused for any relay that is not on loopback. The console marks such targets
  "unencrypted". Use it for a local postfix, not for anything across a network you do not control.
- AUTH is PLAIN or LOGIN, used when `smtp.username` is set. The password is read **only** from
  `smtp.password_file` (absolute path, mode `0640 root:clamfleet-server` or `0600`, read once at start). It is
  never in the YAML or the environment. A systemd `LoadCredential=` path works. A bad file refuses the start.
- `smtp.ca_file` adds a CA bundle for the relay; `smtp.helo` names the host in EHLO (default: the host of
  `public_url`, else the machine name); `smtp.timeout` bounds a whole mail session (5s to 120s).

**Webhooks** need the secret key file (`clamfleet-server key generate`, see
[web.md](web.md#the-secret-key-file)): the URL and the signing key are stored encrypted with it. Without it,
creating a webhook target is refused with a page that says how to create one.

Deliverability (SPF, DKIM, DMARC) is the relay's job.

## Targets

| Field | Meaning |
|---|---|
| Name | 1-64 characters of `a-z 0-9 . _ -`, starting with a letter or digit; fixed after creation; `new` is reserved. |
| Type | `email` (1 to 20 recipients, each gets **its own message** so each recipient's outcome is recorded and retried on its own) or `webhook` (one HTTPS or HTTP URL). |
| Minimum severity | `WARN`, `CRIT` or `STALE`; applies to state changes only. |
| Tags | Only hosts with **any** of these tags. Empty: every host. Tags are asserted by the agent; a compromised host can change them. |
| Send state changes / detections | Both on by default. |
| Enabled | A disabled target sends nothing. |

A webhook URL is a credential (chat tools put their token in the path). It is stored encrypted, the list shows
only scheme and host, editing replaces it (a blank field keeps it) and it is never in a log, an audit row or an
error message. A new URL is checked exactly like one typed at creation; a refused one leaves the old one
untouched.

`http://` webhook URLs are allowed only to loopback and private addresses (the check is on the address
actually dialled, so a name that resolves to a public address is refused). The console marks them
**unencrypted**: the payload and the URL then travel in clear on the network. The signature protects
integrity, not confidentiality.

**Test send.** "Send test" delivers a `kind: "test"` payload (see below) with the saved settings, through the
same sender and the same network policy as real alerts. It bypasses the queue, cooldown, filters and retry. The
page shows the class and our own text ("Delivered: HTTP 204 in 140 ms", "Blocked: ...", "TLS: certificate signed
by unknown authority") and **never** the response body or the URL. One test per target at a time and one per 10
seconds. It is logged and audited.

## What is sent, and when

**State changes** are alerts about a host's state (`OK < WARN < CRIT < STALE`).

- Each target sees the fleet through its own minimum severity. A state below the minimum is "below". A target
  is told about a host only when the view of the new state differs from the view of the state it was last told.
- Dropping below the minimum is sent once as **resolved for this target** (`resolved: true`), so a target that
  was told CRIT is never left believing it.
- A host's first evaluation to OK sends nothing; its first evaluation to a state at or above the minimum does.
- Example, target minimum `CRIT`: OK to WARN sends nothing; WARN to CRIT sends; CRIT to WARN sends "resolved";
  WARN to OK sends nothing.

**`from` and `changes`.** `from` is the state **this target was last told** about the host, so each alert's
`from` is the previous alert's `to`; `changes` is how many state changes the alert covers (1 unless the cooldown
coalesced several).

**Cooldown** (`alert.cooldown`, default 15 minutes; 0 turns it off). At most one state alert per host per
target per window. Changes inside the window are **held**; when the window ends, one alert reports the host's
**current** state, but only if it differs from what the target was last told. A recovery can therefore be
delayed by up to one cooldown, and is never lost. A flapping host costs at most one alert per window. Held
changes show as `held` rows in the log and as `skipped` when the host went back to the told state.

```
12:00  OK -> CRIT         sent (CRIT)
12:02  CRIT -> OK         held
12:05  OK -> CRIT         held
12:08  CRIT -> OK         held
12:15  window ends        one alert: from CRIT to OK, changes 3, resolved for a WARN target
```

**Detections** (`kind: detection`) are never held and ignore the minimum severity: one alert per detection per
target (and per recipient for email). A detection no target takes (tags, switches) is still stored and shown on
the host page; the Alerts page says "N detections in the last 7 days matched no alert target".

**Switching a kind off** (or disabling the target, or removing a recipient) **cancels** the pending alerts of
that kind, and drops the cooldown state; the page says how many were cancelled. Switching it back on starts
fresh: nothing is sent for the current state until it changes.

**Upgrading** does not alert on history: only changes recorded after the upgrade are alerted.

## Delivery, retries and the log

- Every alert is a row in the database before anything is sent, so a restart, an SMTP outage or a webhook
  outage loses nothing. The server keeps working and keeps alerting if SMTP or a webhook target is down.
- Up to **5 attempts** per delivery: at once, then +1, +5, +15 and +60 minutes after the previous attempt
  finished (about 81 minutes), each with up to 10% jitter. A receiver's `Retry-After` (seconds or an HTTP date)
  can lengthen the wait, up to 60 minutes.
- **Retried:** connection errors, timeouts, TLS handshake errors, HTTP 408, 425, 429 and 5xx, SMTP 4xx.
  **Permanent (one attempt):** HTTP 3xx (redirects are never followed: use the final URL) and other 4xx, SMTP
  5xx and authentication failures, an address the policy blocks, a secret that cannot be opened.
- **At least once.** A crash after the receiver accepted but before the server recorded it, or a mail
  connection lost between the end of DATA and its reply, produces a duplicate with the same `id`. **Receivers
  deduplicate on `id`.** An email counts as delivered at the server's positive reply to the end of DATA.
- **Order.** For one (target, host, recipient) a newer alert waits while an older one is still being retried,
  so a receiver never gets "OK" before the "CRIT" that is still being retried. Different hosts, targets and
  recipients never wait for each other.
- **Every attempt is a row** in the alert log (`alert_log`): time, target, recipient, host, kind, attempt,
  status (`attempting`, `sent`, `retrying`, `failed`, `interrupted`, `held`, `skipped`, `cancelled`,
  `test_sent`, `test_failed`), a short code (`HTTP 503`, `SMTP 550`, `blocked`, `timeout`, `tls`, ...) and our
  own text, never a response body, a URL path or a secret. See it on the Alerts page or with
  `clamfleet-server alert log`. A crash during an attempt shows as `interrupted`; a delivery whose last attempt
  was interrupted ends as failed, so a delivery that crashes the server is not retried forever.
- Finished deliveries and log rows are pruned after 90 days (not configurable until the retention block of a
  later milestone). Pending deliveries are never pruned.
- The server logs one JSON line `"alert"` per planned alert (kind, host, from, to, alert_id), an info line per
  delivery and a warning per retry, so log forwarders see alerts too.

## Payload reference (schema 1)

The payload is a **public interface**: receivers are written against it. A Go type (`internal/alert/payload.go`)
and golden files pin it. Keys are always present for their kind; an unknown value is an explicit `null`.

```json
{
  "schema": 1,
  "id": "6f1c0e8b2d4a4f7e9a3b5c7d9e1f2a3b",
  "kind": "state_change",
  "target": "ops-webhook",
  "host": "app01",
  "tags": ["prod", "web"],
  "ts": "2031-03-04T12:00:00Z",
  "url": "https://clamfleet.example/hosts/app01",
  "from": "OK",
  "to": "CRIT",
  "reason": ["clamd not responding: connection refused"],
  "reason_codes": ["clamd_down"],
  "resolved": false,
  "changes": 1
}
```

| Field | Type | Meaning |
|---|---|---|
| `schema` | number | Always `1` for this format. |
| `id` | string | The alert id (128 random bits, hex). One per alert, shared by its targets, recipients and **retries**. Deduplicate on it. Also the `webhook-id` header. |
| `kind` | string | `state_change`, `detection` or `test`. **Ignore kinds you do not know.** |
| `target` | string | The target's name. |
| `host` | string | The **registered** host name (admin-assigned), never the name in the agent's report. |
| `tags` | array of strings | The host's tags when the alert was planned, sorted. |
| `ts` | string | UTC, whole seconds. State change: when the host changed state (for a coalesced alert, its latest change). Detection: when the agent saw it. |
| `url` | string or null | `public_url` + `/hosts/` + the host name; `null` while `public_url` is unset. |
| `from` | string or null | The state this target was last told about the host; for the first alert to this target about this host, the change's own previous state, `null` on the host's first evaluation. |
| `to` | string | The host's state this alert reports: `OK`, `WARN`, `CRIT` or `STALE`. |
| `reason` | array of strings | Human texts of the reasons behind `to`. |
| `reason_codes` | array of strings | Stable rule codes of those reasons (`clamd_down`, `daily_old`, `freshclam_inactive`, `daily_behind`, `scan_missed`, `stale`, ...): key your logic on these, not on `reason`. |
| `resolved` | boolean | `to` is below the target's minimum severity: the problem is over **for this target**. |
| `changes` | number | State changes this alert covers (more than 1 when the cooldown coalesced several). |

A **detection** has the keys `schema`, `id`, `kind`, `target`, `host`, `tags`, `ts` (the agent's event time),
`url`, and instead of the state keys: `path`, `signature`, `source` and `received_at` (the server's time).

```json
{"schema":1,"id":"0a1b2c3d4e5f60718293a4b5c6d7e8f9","kind":"detection","target":"ops-webhook","host":"app01","tags":["prod","web"],"ts":"2031-03-04T12:00:00Z","url":"https://clamfleet.example/hosts/app01","path":"/home/alice/eicar.com","signature":"Win.Test.EICAR_HDB-1","source":"clamonacc","received_at":"2031-03-04T12:00:03Z"}
```

A **test** has `schema`, `id`, `kind`, `target`, `ts` and `url` (the root of `public_url`, or `null`).

**Rules.**

- Receivers must **ignore unknown fields** and unknown `kind` values. Adding a field or a kind keeps
  `schema: 1`; renaming, removing or retyping a field bumps `schema`.
- **`reason`, `path` and `signature` are text controlled by the monitored host**, and `host`, `tags` come from
  an agent report or an admin. Treat them as untrusted: escape them before putting them in HTML or markdown
  (chat bridges), never in a shell or SQL.
- The same `id` can arrive more than once: deduplicate.

Emails carry the same facts as plain text (quoted-printable). Headers hold only the admin-assigned host name
and fixed words; reasons, paths and signatures appear in the body with control characters shown as `\xNN`,
so nothing from a host can start a header or end the message. Each message has `Auto-Submitted:
auto-generated`, a `Message-ID` that is the same on every retry of the same alert to the same target, and
`X-ClamFleet-Alert-Id`.

## Verifying the signature

Every webhook request is signed in the [Standard Webhooks](https://www.standardwebhooks.com) format; there is
no unsigned option. Libraries for several languages verify it as is.

Headers:

- `webhook-id`: the alert id.
- `webhook-timestamp`: unix seconds **at the time of this attempt** (each retry has a fresh one).
- `webhook-signature`: `v1,` plus the base64 of `HMAC-SHA256(key, id + "." + timestamp + "." + body)`. Several
  space-separated entries are allowed; one valid entry is enough.

The key is shown once, as `whsec_` plus base64. **The HMAC key is the base64-decoded part after `whsec_`**,
not the `whsec_` text: signing with the text does not verify. The body is the raw request body, byte for byte:
verify before parsing.

```python
import base64, hashlib, hmac, time

def verify(key_text, headers, body, seen_ids, tolerance=300):
    key = base64.b64decode(key_text.removeprefix("whsec_"))
    msg_id = headers["webhook-id"]
    ts = headers["webhook-timestamp"]
    if abs(time.time() - int(ts)) > tolerance:
        return False                       # replay protection: reject old (or far-future) timestamps
    signed = msg_id.encode() + b"." + ts.encode() + b"." + body
    expected = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    ok = any(hmac.compare_digest(expected, part.split(",", 1)[1])
             for part in headers["webhook-signature"].split() if part.startswith("v1,"))
    if not ok:
        return False
    if msg_id in seen_ids:                 # at-least-once delivery: process each id once
        return True                        # (acknowledge it, do not act twice)
    seen_ids.add(msg_id)
    return True
```

- **Timestamp window:** reject when `|now - timestamp|` is more than 5 minutes. This needs clocks within
  seconds on both sides (NTP).
- **Remember ids for at least 2 hours.** Retries come up to about 81 minutes after the first attempt (plus a
  lease after a crash), each with a fresh timestamp: a receiver that forgets ids after 5 minutes treats a retry
  of an alert it already handled as new.
- **Compare in constant time** (`hmac.compare_digest` above).
- Rotating the key replaces it at once, with no overlap: update the receiver first or right after.

## Where a webhook may connect

A webhook makes the server open connections to addresses an admin chose, so the destination is restricted.
The check runs **at connection time on the resolved address**: ClamFleet resolves the name itself, drops every
answer the policy blocks, and connects to the rest as IP addresses (a DNS answer that changes between a check
and the connection cannot get around it, and every attempt resolves again). The socket address is checked a
second time. There are no redirects, no proxy (environment proxies are ignored), no keep-alive, TLS 1.2 or later
with certificate verification always on (`alert.webhook.ca_file` adds a CA), and the response body is read up to
64 KiB and **discarded**.

**Always blocked**, whatever the settings: unspecified addresses (`0.0.0.0`, `::`), link-local
(`169.254.0.0/16`, `fe80::/10`, which holds the cloud metadata address `169.254.169.254` and AWS ECS
`169.254.170.2`), multicast, `255.255.255.255`, `192.0.0.0/24` (IANA special purpose; includes an old Oracle
Cloud metadata address), and these metadata and platform endpoints that are not link-local:
`100.100.100.200` (Alibaba Cloud), `fd00:ec2::254` (AWS IMDS over IPv6) and `168.63.129.16` (Azure). IPv4-mapped
forms (`::ffff:a.b.c.d`) are judged as the IPv4 address. Not decoded: NAT64 (`64:ff9b::/96`) and other embedded
IPv4 forms: a **known gap**.

| Setting | Default | Effect |
|---|---|---|
| `alert.webhook.allow_loopback` | `false` | `127.0.0.0/8`, `::1` and the names `localhost`, `*.localhost`. |
| `alert.webhook.allow_private` | `true` | RFC 1918, `100.64.0.0/10`, `fc00::/7`, and `http://` to them. `false` also stops plaintext to private addresses: https to public addresses only. |
| `alert.webhook.deny_networks` | `[]` | Extra CIDRs that are always blocked. An invalid entry refuses the start. |

**What this cannot do.** The list cannot know every provider's or network's internal services. On a cloud host,
or next to internal APIs that answer unauthenticated requests, set `allow_private: false` or list the sensitive
subnets in `deny_networks`, and use an **egress firewall**, which is the stronger control: with private
networks allowed, a stolen admin session can still make the server POST to an internal service and read the
status code (not the body). The action is admin-only, audited and rate limited for tests.

## The command line

Run as the server user (`sudo -u clamfleet-server`), like the other admin commands; the audit rows carry the
operating-system user.

```
clamfleet-server alert list [--json]
clamfleet-server alert log [--target NAME] [--limit N] [--json]
clamfleet-server alert add-webhook NAME (--url-stdin | --url-file PATH) [--min-severity S] [--tags a,b] [--no-state-changes] [--no-detections]
clamfleet-server alert add-email NAME --to a@x.example,b@x.example [same options]
clamfleet-server alert test NAME
clamfleet-server alert delete NAME --yes
```

The webhook URL **never** goes on the command line, where it would land in shell history, `ps` output and
`sudo` logs. Pipe it in, or point at a file with mode `0600` or `0640`:

```
sudo -u clamfleet-server clamfleet-server alert add-webhook ops --url-stdin < url.txt
```

`add-webhook` prints the signing key (`whsec_...`) once on stdout and nothing else. A URL given as an
argument is a usage error (exit 2) whose message does not repeat it. `test` prints one result line per
recipient and exits 1 when delivery fails. Editing a target stays in the console.

## Key rotation

Webhook secrets use the same key file as TOTP. The rotation procedure:

1. `key generate --add` (as root), restart the server.
2. `key reencrypt`: re-seals TOTP and webhook secrets in **one transaction**. It exits **1** with
   `incomplete: N re-sealed, M changed meanwhile` when a row changed between its read and write (an admin
   rotated a webhook key meanwhile); run it again until it exits 0.
3. `key check` must exit **0**: it opens every stored secret and reports, per purpose, how many use the active
   key, an older key still in the file, or cannot be opened.
4. Only then delete the old key line and restart.

If the old line is removed too early, `key check` exits 1 naming the counts; putting the line back restores
everything. At start, TOTP secrets that cannot be opened refuse the start (see [web.md](web.md)); webhook
targets whose secret cannot be opened do **not**: the server starts, logs the count and the fix, those targets'
alerts fail with "the webhook secret cannot be opened", and the Alerts page shows a banner per target. Email
and the other targets keep working. Fix a target by entering its URL again (which issues a new signing key) or
by restoring the key. A lost key file is the same case.

## Privacy

Alert payloads leave ClamFleet for the receivers you choose. They can hold personal data: detection paths such
as `/home/alice/...`, and host names and tags that identify people or customers. Pick receivers that match your
data-residency duties (an EU-hosted chat or SIEM, your own mail relay). Recipient addresses are stored in the
target's configuration and, per delivery, in the delivery and log rows; those copies are pruned after 90 days or
with the target, and deleting a host removes the alert history of its state changes and detections.

## Troubleshooting

| Symptom | Look at |
|---|---|
| Nothing arrives | The Alerts page: banners, the target's last result, Recent deliveries. `clamfleet-server alert log`. Is the target enabled, do its tags match the host, is "state changes" on, is the minimum severity too high? |
| `blocked` | The text names the address and the setting (`allow_loopback`, `allow_private`, `deny_networks`). |
| `plaintext` | `http://` or `smtp.tls: none` to a public address: use https, or starttls or tls. |
| `tls` | The receiver's certificate is not trusted: use `alert.webhook.ca_file` / `smtp.ca_file`, or fix the certificate. |
| `HTTP 3xx` | Redirects are not followed: use the final URL. |
| `HTTP 401/403/404` | The receiver refuses the request: check the URL and the receiver's configuration. Permanent: not retried. |
| `secret` / "cannot be opened" | The key file is missing or the key was retired: [Key rotation](#key-rotation). |
| `SMTP 535` | Wrong user name or password in `smtp.username` and `smtp.password_file`. |
| "email is not configured" | `smtp.host` is empty. |
| Signature does not verify | You used the `whsec_` text as the key instead of its base64-decoded bytes; or you parsed and re-serialised the body before verifying. |
| A recovery came late | By design: up to one cooldown (`held` rows in the log). |
| Alerts for a host are missing but others arrive | Tags: the host's tags are asserted by its agent. |
