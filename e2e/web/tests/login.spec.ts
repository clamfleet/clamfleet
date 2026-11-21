// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Flow 1: sign in, sign out, and the forced password change.
import { test, expect, fixture, login } from './helpers';

test('admin signs in, sees the fleet and the admin link, and signs out', async ({ page }) => {
  const fx = fixture();
  await login(page, fx.admin);
  await expect(page).toHaveURL(/\/(fleet)?$/);
  await expect(page.getByTestId('fleet-table')).toBeVisible();
  await expect(page.getByTestId('current-user')).toContainText(fx.admin.email);
  await expect(page.getByTestId('nav-admin')).toBeVisible();

  await page.getByTestId('logout-button').click();
  await expect(page).toHaveURL(/\/login/);
  await expect(page.getByTestId('login-form')).toBeVisible();
  // Back must not show the fleet again: the session is gone server-side.
  await page.goBack();
  await expect(page.getByTestId('fleet-table')).toHaveCount(0);
});

test('viewer signs in and has no admin link', async ({ page }) => {
  const fx = fixture();
  await login(page, fx.viewer);
  await expect(page.getByTestId('fleet-table')).toBeVisible();
  await expect(page.getByTestId('current-user')).toContainText(fx.viewer.email);
  await expect(page.getByTestId('nav-admin')).toHaveCount(0);
});

test('a wrong password shows an error and stays on the login page', async ({ page }) => {
  const fx = fixture();
  await login(page, { email: fx.viewer.email, password: 'definitely-not-the-password' });
  await expect(page.getByTestId('error')).toBeVisible();
  await expect(page.getByTestId('login-form')).toBeVisible();
  await expect(page).toHaveURL(/\/login/);
});

test('a user with a one-time password is forced to change it before seeing the fleet', async ({ page }) => {
  const fx = fixture();
  await login(page, fx.must_change);
  await expect(page).toHaveURL(/\/account/);
  await expect(page.getByTestId('must-change')).toBeVisible();
  // The fleet is off limits until the change is made.
  await page.goto('/');
  await expect(page).toHaveURL(/\/account/);
  await expect(page.getByTestId('fleet-table')).toHaveCount(0);

  const newPassword = 'a-brand-new-passphrase-2026';
  await page.getByTestId('account-current').fill(fx.must_change.password);
  await page.getByTestId('account-new').fill(newPassword);
  await page.getByTestId('account-new2').fill(newPassword);
  await page.getByTestId('account-submit').click();
  await expect(page.getByTestId('must-change')).toHaveCount(0);
  await page.goto('/');
  await expect(page.getByTestId('fleet-table')).toBeVisible();
});
