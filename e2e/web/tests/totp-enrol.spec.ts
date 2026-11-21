// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Flow: a user without an authenticator enrols, then the next sign-in asks for a code.
import { test, expect, fixture, login, totp } from './helpers';

test('enrol user turns on two-factor sign-in and is asked for a code afterwards', async ({ page }) => {
  const fx = fixture();
  await login(page, fx.enrol);
  await expect(page.getByTestId('fleet-table')).toBeVisible();

  await page.getByTestId('nav-account').click();
  await expect(page.getByTestId('account-totp-status')).toContainText('Off');
  await page.getByTestId('account-totp-link').click();
  await page.getByTestId('totp-setup-password').fill(fx.enrol.password);
  await page.getByTestId('totp-setup-submit').click();

  await expect(page.getByTestId('totp-setup-page')).toBeVisible();
  const secret = ((await page.getByTestId('totp-secret').textContent()) ?? '').replace(/\s+/g, '');
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  await page.getByTestId('totp-confirm-code').fill(totp(secret));
  await page.getByTestId('totp-confirm-submit').click();

  await expect(page.getByTestId('recovery-codes-page')).toBeVisible();
  const codes = ((await page.getByTestId('recovery-codes').textContent()) ?? '').trim().split(/\s+/);
  expect(codes).toHaveLength(10);
  expect(new Set(codes).size).toBe(10);

  await page.getByTestId('logout-button').click();
  await login(page, fx.enrol);
  await expect(page).toHaveURL(/\/login\/totp/);
  await expect(page.getByTestId('fleet-table')).toHaveCount(0);
  // Enrolment confirmed the current step, and each step works once: use the next one (inside
  // the server's +-1 window).
  await page.getByTestId('totp-code').fill(totp(secret, 1));
  await page.getByTestId('totp-submit').click();
  await expect(page.getByTestId('fleet-table')).toBeVisible();
});
