// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Playwright config for the console's browser tests (docs/testing.md "Browser fixture").
// The throwaway server is started by global-setup.ts (it needs the random logins and tokens
// the fixture prints, so Playwright's webServer option, which wants a fixed URL, does not fit).
import { defineConfig, devices } from '@playwright/test';

// global-setup.ts exports the URL through the environment before any worker starts, and workers
// load this config again, so it is read at that point.
const baseURL = process.env.CLAMFLEET_E2E_URL;

export default defineConfig({
  testDir: './tests',
  globalSetup: './global-setup.ts',
  // One worker: the specs share one server and the live-update spec changes a host's state.
  workers: 1,
  fullyParallel: false,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [['list']],
  use: {
    baseURL,
    // The fixture serves throwaway certificates.
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
