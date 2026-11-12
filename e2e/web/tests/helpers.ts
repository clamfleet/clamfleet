// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Shared helpers: the fixture handoff, login, and a test fixture that fails any test that
// logs a browser console error (the console's CSP is strict, so a blocked inline script or
// style shows up there).
import { test as base, expect, type Page } from '@playwright/test';
import * as fs from 'node:fs';

export interface Login { email: string; password: string }
export interface FixtureInfo {
  url: string;
  admin: Login;
  viewer: Login;
  must_change: Login;
  hosts: Record<string, { token: string; initial_state: string }>;
}

export function fixture(): FixtureInfo {
  return JSON.parse(fs.readFileSync(process.env.CLAMFLEET_E2E_FIXTURE!, 'utf8'));
}

// allowedConsole: a test that navigates to a deliberate error page (403) lists the one message
// the browser logs for it; anything else still fails the test.
export const test = base.extend<{ consoleGuard: void; allowedConsole: RegExp[] }>({
  allowedConsole: [[], { option: true }],
  consoleGuard: [
    async ({ page, allowedConsole }, use) => {
      const problems: string[] = [];
      page.on('console', (m) => {
        if (m.type() === 'error' && !allowedConsole.some((re) => re.test(m.text()))) problems.push(`console: ${m.text()}`);
      });
      page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
      await use();
      expect(problems, 'browser console errors').toEqual([]);
    },
    { auto: true },
  ],
});
export { expect };

export async function login(page: Page, who: Login): Promise<void> {
  await page.goto('/login');
  await page.getByTestId('login-email').fill(who.email);
  await page.getByTestId('login-password').fill(who.password);
  await page.getByTestId('login-submit').click();
}
