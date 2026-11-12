<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Console browser tests

Playwright (`@playwright/test` 1.63.0, Chromium revision 1243 only). Seven flows: login/logout and
forced password change, fleet states and inert hostile text, live state change (15 s poll), viewer
cannot reach admin actions, and three two-factor flows: sign-in with a code and a one-use recovery
code (`totp-login`), enrolment (`totp-enrol`), forced enrolment (`totp-forced`). Any browser console error fails a test.

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
