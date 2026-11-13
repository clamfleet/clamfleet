<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Console browser tests

Playwright (`@playwright/test` 1.63.0, Chromium revision 1243 only). Nine flows: login/logout and
forced password change, fleet states and inert hostile text, live state change (15 s poll), viewer
cannot reach admin actions (including `nav-alerts` and `/admin/alerts`), two alerting flows (below), and three two-factor flows: sign-in with a code and a one-use recovery
code (`totp-login`), enrolment (`totp-enrol`), forced enrolment (`totp-forced`). Any browser console error fails a test.

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
