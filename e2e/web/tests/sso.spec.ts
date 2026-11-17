// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Flows: sign in with OpenID Connect and with LDAP.
//
// The console is https://127.0.0.1:<port> and the fake provider https://localhost:<port2>: two
// different SITES, because SameSite is about sites and ports do not make sites different. That
// is what makes the first test meaningful: the state cookie must come back on the provider's
// cross-site redirect (SameSite=Lax allows a top-level GET navigation; Strict would drop it and
// every sign-in would fail with "expired"). A router test cannot see this; only a browser can.
// The precondition is asserted first: the callback request really is cross-site.
import { test, expect, fixture, login } from './helpers';

test('OIDC: the provider on another site returns the browser and the state cookie survives (SameSite=Lax)', async ({ page, context }) => {
  const sso = fixture().sso!;
  const callbacks: Record<string, string>[] = [];
  page.on('response', async (res) => {
    const req = res.request();
    if (new URL(req.url()).pathname === '/login/oidc/callback') callbacks.push(await req.allHeaders());
  });

  await page.goto('/login');
  await expect(page.getByTestId('login-sso-submit')).toHaveText(sso.button_text);
  await page.getByTestId('login-sso-submit').click();

  // On the provider: a different host, a different site.
  await expect(page.getByTestId('idp-page')).toBeVisible();
  expect(new URL(page.url()).hostname).toBe('localhost');
  expect(new URL(page.url()).origin).toBe(sso.issuer_url);
  await page.getByTestId(`idp-user-${sso.oidc_admin}`).click();

  // Back on the console, signed in.
  await expect(page.getByTestId('fleet-table')).toBeVisible();
  expect(new URL(page.url()).hostname).toBe('127.0.0.1');
  await expect(page.getByTestId('current-user')).toContainText('sso-admin@sso.example (admin)');
  await expect(page.getByTestId('nav-admin')).toBeVisible();

  // The precondition: the callback was a cross-site navigation, so the Lax cookie was really tested.
  expect(callbacks.length).toBeGreaterThan(0);
  expect(callbacks[0]['sec-fetch-site']).toBe('cross-site');
  // The state cookie is spent (cleared by the callback); only the session cookie remains.
  const names = (await context.cookies()).map((c) => c.name);
  expect(names).toContain('__Host-clamfleet_session');
  expect(names).not.toContain('__Host-clamfleet_oidc');
});

// The deliberate 403 page is logged by the browser as a console error; allow exactly that message.
test.describe('no role', () => {
  test.use({ allowedConsole: [/status of 403/] });
  test('OIDC: a user in no group sees the "No role assigned" page and is not signed in', async ({ page }) => {
    const sso = fixture().sso!;
    await page.goto('/login');
    await page.getByTestId('login-sso-submit').click();
    await page.getByTestId(`idp-user-${sso.oidc_norole}`).click();
    await expect(page.getByTestId('error-no-role')).toBeVisible();
    await expect(page.getByTestId('fleet-table')).toHaveCount(0);
    await expect(page.getByTestId('current-user')).toHaveCount(0);
    await page.goto('/');
    await expect(page).toHaveURL(/\/login/);
  });
});

test('OIDC: a viewer from the provider has no admin link', async ({ page }) => {
  const sso = fixture().sso!;
  await page.goto('/login');
  await page.getByTestId('login-sso-submit').click();
  await page.getByTestId(`idp-user-${sso.oidc_viewer}`).click();
  await expect(page.getByTestId('fleet-table')).toBeVisible();
  await expect(page.getByTestId('current-user')).toContainText('(viewer)');
  await expect(page.getByTestId('nav-admin')).toHaveCount(0);
});

test('LDAP: a user name, not an email, signs in; the account page shows the source and no password card', async ({ page }) => {
  const sso = fixture().sso!;
  await page.goto('/login');
  // The label offers a user name, and the field takes one (it is not type=email).
  await expect(page.locator('label[for=email]')).toHaveText('Email or user name');
  await login(page, sso.ldap_admin);
  await expect(page.getByTestId('fleet-table')).toBeVisible();
  await expect(page.getByTestId('current-user')).toContainText('ldap-admin@sso.example (admin)');
  await page.getByTestId('nav-account').click();
  await expect(page.getByTestId('account-source')).toHaveText('LDAP');
  await expect(page.getByTestId('account-form')).toHaveCount(0);
  await expect(page.getByTestId('account-totp-card')).toHaveCount(0);
});

test('LDAP: a wrong password stays on the login page with the generic text', async ({ page }) => {
  const sso = fixture().sso!;
  await login(page, { email: sso.ldap_admin.email, password: 'definitely-not-the-password' });
  await expect(page.getByTestId('error')).toContainText('Invalid email or password.');
  await expect(page.getByTestId('login-form')).toBeVisible();
});
