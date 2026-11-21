// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Flow: two-step sign-in with an authenticator code, a wrong code, and a one-use recovery code.
import { test, expect, fixture, login, totp } from './helpers';

test('totp user: no session between the password and the code, wrong code refused, right code signs in', async ({ page }) => {
  const fx = fixture();
  await login(page, fx.totp);
  await expect(page).toHaveURL(/\/login\/totp/);
  await expect(page.getByTestId('totp-login-page')).toBeVisible();

  // Rule: a password alone is not a session. The fleet must stay out of reach.
  await page.goto('/');
  await expect(page).toHaveURL(/\/login/);
  await expect(page.getByTestId('fleet-table')).toHaveCount(0);

  // Start a fresh pending sign-in for the wrong-code check.
  await login(page, fx.totp);
  await expect(page).toHaveURL(/\/login\/totp/);
  await page.getByTestId('totp-code').fill('000000');
  await page.getByTestId('totp-submit').click();
  await expect(page.getByTestId('error')).toBeVisible();
  await expect(page.getByTestId('fleet-table')).toHaveCount(0);

  await page.getByTestId('totp-code').fill(totp(fx.totp.secret_base32));
  await page.getByTestId('totp-submit').click();
  await expect(page.getByTestId('fleet-table')).toBeVisible();
  await expect(page.getByTestId('current-user')).toContainText(fx.totp.email);
});

test('a recovery code signs in once and is refused the second time', async ({ page, browser }) => {
  const fx = fixture();
  const code = fx.totp.recovery_codes[0];
  await login(page, fx.totp);
  await page.getByTestId('totp-code').fill(code);
  await page.getByTestId('totp-submit').click();
  await expect(page.getByTestId('fleet-table')).toBeVisible();
  await expect(page.getByTestId('notice')).toContainText('9 recovery codes left');

  // A new context has no cookies: a second, independent sign-in with the same code.
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, baseURL: fx.url });
  try {
    const page2 = await ctx.newPage();
    await login(page2, fx.totp);
    await page2.getByTestId('totp-code').fill(code);
    await page2.getByTestId('totp-submit').click();
    await expect(page2.getByTestId('error')).toBeVisible();
    await expect(page2.getByTestId('fleet-table')).toHaveCount(0);
  } finally {
    await ctx.close();
  }
});
