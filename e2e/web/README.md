<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Console browser tests

Playwright (`@playwright/test` 1.63.0, Chromium revision 1243 only). Four flows: login/logout and
forced password change, fleet states and inert hostile text, live state change (15 s poll), viewer
cannot reach admin actions. Any browser console error fails a test.

Run: `make e2e-web` from the repo root. It builds `bin/`, runs `npm ci`, and the suite starts
`bin/webfixture` on 127.0.0.1 itself and stops it afterwards (see `docs/testing.md`, "Browser
fixture"). `PLAYWRIGHT_BROWSERS_PATH` must hold chromium-1243 (`source /opt/env.sh`); no browser is
downloaded. The live-change spec takes about 15 s by design. `package.json` and the lockfile are
JSON and carry the licence in their metadata only.
