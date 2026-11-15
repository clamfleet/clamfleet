<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Console browser tests

Playwright (`@playwright/test` 1.63.0, Chromium revision 1243 only). Ten flows: login/logout and
forced password change, fleet states and inert hostile text, live state change (15 s poll), viewer
cannot reach admin actions (including `nav-alerts` and `/admin/alerts`), two alerting flows (below), and three two-factor flows: sign-in with a code and a one-use recovery
code (`totp-login`), enrolment (`totp-enrol`), forced enrolment (`totp-forced`), and detections with acknowledgement (`events`). Any browser console error fails a test.

Alerting (`alerts-admin`, `alerts-delivery`) uses the fixture's own webhook receiver on 127.0.0.1
(`alerts` in `fixture.json`, see `docs/testing.md`, "Alerts in the fixture"), not one started by the
spec. `alerts-admin` adds a target (key shown once on a `no-store` page, never again), sends a test
(htmx swaps the result in place under the CSP; the signature is verified in `tests/helpers.ts` with
`node:crypto`, Standard Webhooks, base64-decoded `whsec_` key) and a second test inside 10 s must show
the 429 message. Chromium logs that deliberate 429 as a console error, so that spec allows exactly
`status of 429`. `alerts-delivery` posts a clamd-down report for `alerts01` and expects one
`state_change` to CRIT at the seeded target's path and a `sent` row in its log; both specs filter
the receiver's requests by path, because the target `alerts-admin` creates has no tag filter and also
sees `alerts01`. The specs share one server and run in file order; `alerts01` is restored to OK at the end.

Detections (`events.spec.ts`, plus two assertions in `viewer-admin.spec.ts`) use the detections the fixture
posts through the real `/v1/event` (`events` in `fixture.json`, see `docs/testing.md`, "Detections in the
fixture"). The admin spec reads the five hostile names of `xss01` and checks that markup is text, that the
real U+202E and U+2028 are `.esc` elements while the literal text `\u{202E}` is plain text, that no raw bidi
character is in the DOM and no dialog opens; that `warn01` shows "x2"; and that acknowledging one `crit01`
detection swaps its row in place (a `window` marker survives, no console or CSP error), survives a reload (the
Open filter no longer lists it, All does), lowers the menu count by one and shows 1 in `fleet-open-crit01`. The
viewer spec sees the rows but no `event-ack-*` or `events-bulk-*`, and `POST /events/<id>/ack` and
`POST /events/ack` with a valid session and CSRF token answer 403. The acknowledged event is `crit01`'s first;
the viewer spec uses its second, because the specs share one server and run in file order.

Two fixtures run at once: the plain one (`CLAMFLEET_E2E_FIXTURE`, `_URL`) and one started with
`--totp-required` (`CLAMFLEET_E2E_FIXTURE_REQUIRED`, `_URL_REQUIRED`), so cookies never mix. The
server uses the real clock: `totp()` in `tests/helpers.ts` makes codes (RFC 6238, checked against
the RFC vector at load). Each 30 s step is accepted once per user, so a second sign-in of the same
user within 30 s passes `stepOffset` 1.

Run: `make e2e-web` from the repo root. It builds `bin/`, runs `npm ci`, and the suite starts
`bin/webfixture` on 127.0.0.1 itself and stops it afterwards (see `docs/testing.md`, "Browser
fixture"). `PLAYWRIGHT_BROWSERS_PATH` must hold chromium-1243 (`source /opt/env.sh`); no browser is
downloaded. The live-change spec takes about 15 s by design. `package.json` and the lockfile are
JSON and carry the licence in their metadata only.
