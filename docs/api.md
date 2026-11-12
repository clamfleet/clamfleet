<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# ClamFleet ingest API

The HTTP API that agents use to report to the server (spec sections 7.2 to 7.4). It is a public
interface: other agents and servers can be written against it. The JSON payloads are defined by
`internal/proto` and carry `"schema": 1`; changing them needs a schema bump, and a server keeps
accepting the older schemas it supported.

Agents initiate every connection. The server never connects to an agent.

## Transport and authentication

- HTTPS, TLS 1.2 or later. The intended deployment is the server on loopback behind a reverse proxy
  that terminates TLS; the server can also terminate TLS itself (`tls.cert`, `tls.key`). The default is plaintext on `127.0.0.1:8443`; plaintext on any other address is refused.
- Every `/v1/*` request carries an agent token: `Authorization: Bearer cfa_...`.
  - A token is `cfa_` followed by 43 base64url characters (no padding): 256 random bits, 47
    characters in all. `cfa_` marks it as an agent credential.
  - The server stores only the SHA-256 of the token. A token is created by
    `clamfleet-server host add NAME` and replaced by `host rotate-token NAME`. There is one token per
    host, and a rotation invalidates the old token at once.
  - The identity of the caller is the host behind the token. The `host` field in the payload is
    display data only: a report that names another host is stored under the token's host.
- Optional mutual TLS: when the server has `tls.client_ca`, every client must also present a
  certificate signed by that CA, or the TLS handshake fails before any HTTP request. The token is
  still required on top: a client certificate alone is not accepted.
- Bearer-only, no cookies: `/v1/*` has no CSRF surface.

## Envelope

Every response has `Content-Type: application/json`.

- **Success:** a JSON object. Clients must ignore keys they do not know. Today the object is `{}`;
  later versions may add keys (for example `tasks`) without a schema change.
- **Error:** `{"error": "<short message>"}`. The message is fixed text or describes the client's own
  input; it never carries internal detail. Never log or display it as trusted HTML.

A request for an unknown path (404) or with the wrong method (405) is answered by the HTTP router
with a plain-text body and an `Allow` header, not by this envelope.

## Endpoints

### `POST /v1/report`

Body: a `proto.Report` (spec 7.3), at most 1 MiB. Unknown JSON keys are accepted and dropped.

| Status | Meaning |
|---|---|
| 202 | Stored (or already stored: a retried report with the same `ts` is kept once). Body `{}`. |
| 400 | Invalid payload: not a JSON object, trailing data after the document, `schema` other than 1, missing or invalid `ts`, more than 32 tags, a tag that is empty, longer than 64 bytes or holds control characters, `host` longer than 253 bytes, `agent_version` longer than 64 bytes. |
| 401 | Missing, malformed, unknown, revoked or rotated-away token. Always the same body and `WWW-Authenticate: Bearer realm="clamfleet"`, whatever the cause. |
| 405 | Wrong method. |
| 413 | Body larger than 1 MiB. |
| 503 | The server cannot reach its database. Retry later. This is never a 401. |

Notes:
- Authentication is checked before the body is read, so an unauthenticated request is a 401 even
  when its body is too large.
- `ts` has one-second resolution; the server stores at most one report per host and `ts`.
- The server never rejects a report for clock skew. A `ts` more than five minutes ahead of the
  server clock is logged.
- The server's own clock decides `first_seen`, `last_seen` and retention. The agent's `ts` is only
  used to order reports.

### `POST /v1/event`

Body: a `proto.Event` (spec 7.4), at most 64 KiB. `path` 1 to 4096 bytes (no NUL), `signature` 1 to
256, `source` 1 to 32, `ts` required.

Status codes as for `/v1/report`. A duplicate event (same host, `ts`, `path` and `signature`) is
also a 202. An event does not count as a report: it does not move `last_seen`.

The agent side of events (the `event` command and the spool) arrives with Milestone 5; the endpoint
exists now.

### `GET /healthz`

No authentication. `200 {"status":"ok"}` when the database answers within two seconds, otherwise
`503 {"status":"unavailable"}`. It reveals nothing else.

## Logging

The server logs one line per request: method, path, status, the authenticated host name (empty for
a rejected request), duration and the client IP address (always, decision of the maintainers).
Successful requests are logged at info level (the default), except `GET /healthz`, which is logged at debug; 4xx at warn, 5xx at error. The `Authorization`
header, the query string and the body are never logged. The client address is the TCP peer, unless
the peer is listed in the server's `trusted_proxies`: then `X-Forwarded-For` (all header lines combined) is
read from right to left and the first address that is not itself a trusted proxy is logged, falling back to
the peer if there is none or an entry does not parse. From any other peer the header is ignored. The client
IP is for logging only and is never used for authentication. `trusted_proxies` must list the proxies' own
addresses, not networks the clients live in: an address inside a trusted range is skipped, so the logged IP
could be the proxy's or one the client chose.
