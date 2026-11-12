// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Flow: on a console that requires two-factor sign-in, a user without one is held on the
// enrolment page until enrolled. Runs against the second fixture (--totp-required).
import { test, expect, fixtureRequired, login, totp } from './helpers';

const fx = fixtureRequired();
test.use({ baseURL: fx.url });

test('forced user is held on /account/totp until enrolled', async ({ page }) => {
  await login(page, fx.forced);
  await expect(page).toHaveURL(/\/account\/totp/);
  await expect(page.getByTestId('totp-required-notice')).toBeVisible();

  await page.goto('/');
  await expect(page).toHaveURL(/\/account\/totp/);
  await expect(page.getByTestId('fleet-table')).toHaveCount(0);

  // The gate must not block its own enrolment pages.
  await page.getByTestId('totp-setup-password').fill(fx.forced.password);
  await page.getByTestId('totp-setup-submit').click();
  await expect(page.getByTestId('totp-setup-page')).toBeVisible();
  const secret = ((await page.getByTestId('totp-secret').textContent()) ?? '').replace(/\s+/g, '');
  await page.getByTestId('totp-confirm-code').fill(totp(secret));
  await page.getByTestId('totp-confirm-submit').click();
  await expect(page.getByTestId('recovery-codes-page')).toBeVisible();

  await page.goto('/');
  await expect(page.getByTestId('fleet-table')).toBeVisible();
});
