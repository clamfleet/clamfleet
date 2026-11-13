// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Flows: an admin adds a webhook target (the signing key is shown once), and "Send test" swaps
// its result in place under the strict CSP, with a verifiable signature and a 429 on a repeat.
import { test, expect, fixture, login, receiverRequests, signatureValid } from './helpers';

// Chromium logs the deliberate 429 answer itself as a failed resource load; any other console
// message (a CSP violation, a script error) still fails the test.
test.use({ allowedConsole: [/status of 429/] });

test('add a webhook target, see the key once, send a test, and get the 429 message on a repeat', async ({ page, request }) => {
  const fx = fixture();
  const name = 'spec-hook';
  const hookPath = '/hook/spec';
  await login(page, fx.admin);
  await page.getByTestId('nav-alerts').click();
  await expect(page.getByTestId('admin-alerts-page')).toBeVisible();

  // Add the target.
  await page.getByTestId('alert-add-webhook').click();
  await page.getByTestId('alert-name').fill(name);
  await page.getByTestId('alert-url').fill(fx.alerts.receiver_url + hookPath);
  const created = page.waitForResponse((r) => r.request().method() === 'POST' && /\/admin\/alerts/.test(r.url()));
  await page.getByTestId('alert-submit').click();
  const res = await created;

  // The key page: shown once, never cached.
  await expect(page.getByTestId('secret-page')).toBeVisible();
  const key = (await page.getByTestId('secret-value').innerText()).trim();
  expect(key).toMatch(/^whsec_[A-Za-z0-9+/=_-]+$/);
  const cc = (res.headers()['cache-control'] ?? '').toLowerCase();
  expect(cc).toContain('no-store');

  // Done: the target page, then the list. Neither shows the key or the URL path again.
  await page.getByTestId('secret-done').click();
  await expect(page.getByTestId('alert-form-page')).toBeVisible();
  await expect(page.locator('body')).not.toContainText(key);
  await expect(page.locator('body')).not.toContainText(hookPath);
  await page.goto('/admin/alerts');
  await expect(page.getByTestId(`alert-row-${name}`)).toBeVisible();
  await expect(page.getByTestId(`alert-unencrypted-${name}`)).toBeVisible();
  await expect(page.getByTestId(`alert-destination-${name}`)).toContainText('http://127.0.0.1:');
  await expect(page.locator('body')).not.toContainText(key);
  await expect(page.locator('body')).not.toContainText(hookPath);
  await page.reload();
  await expect(page.locator('body')).not.toContainText(key);
  await expect(page.locator('body')).not.toContainText(hookPath);

  // Send test: swapped in place, no navigation. The document mark proves no page load.
  await page.evaluate(() => { (window as any).__noReload = true; });
  await page.getByTestId(`alert-test-${name}`).click();
  await expect(page.getByTestId(`test-result-text-${name}`)).toContainText(/Delivered: HTTP 2\d\d in \d+ ms/);
  await expect(page.getByTestId(`test-result-text-${name}`)).toHaveClass('ok');
  expect(await page.evaluate(() => (window as any).__noReload)).toBe(true);

  // The receiver got one test event for this target, signed with the key the page showed.
  const mine = (await receiverRequests(request, fx)).filter((r) => r.path === hookPath);
  expect(mine).toHaveLength(1);
  expect(JSON.parse(mine[0].body).kind).toBe('test');
  expect(mine[0].body).toContain('"kind":"test"');
  expect(signatureValid(mine[0], key)).toBe(true);
  // A wrong key must not verify: the check itself can fail.
  expect(signatureValid(mine[0], 'whsec_' + Buffer.from('not the key').toString('base64'))).toBe(false);

  // A second test within 10 s: htmx swaps the 429 body in place (the layout's responseHandling).
  await page.getByTestId(`alert-test-${name}`).click();
  await expect(page.getByTestId(`test-result-text-${name}`)).toContainText('wait 10 seconds');
  expect(await page.evaluate(() => (window as any).__noReload)).toBe(true);
  // And it sent nothing more.
  expect((await receiverRequests(request, fx)).filter((r) => r.path === hookPath)).toHaveLength(1);
});
