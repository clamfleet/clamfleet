// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Flow 2: the fleet page shows each seeded host's state, and hostile agent text is inert.
import { test, expect, fixture, login } from './helpers';

test('each seeded host shows its state; hostile HTML renders as text and runs nothing', async ({ page }) => {
  const fx = fixture();
  // Anything that executes would call alert() (a dialog) or set this flag.
  let dialogs = 0;
  page.on('dialog', async (d) => { dialogs++; await d.dismiss(); });
  await page.addInitScript(() => { (window as any).__pwned = false; });

  await login(page, fx.viewer);
  const expected: Record<string, string> = { ok01: 'OK', warn01: 'WARN', crit01: 'CRIT', pending01: 'pending' };
  for (const [host, state] of Object.entries(expected)) {
    await expect(page.getByTestId(`fleet-row-${host}`)).toHaveAttribute('data-state', state);
    await expect(page.getByTestId(`fleet-state-${host}`)).toHaveText(state);
  }
  await expect(page.getByTestId('fleet-reasons-crit01')).toContainText('clamd');

  const xss = page.getByTestId('fleet-row-xss01');
  await expect(xss).toHaveAttribute('data-state', 'WARN');
  // The hostile tag and host name are visible as literal text...
  await expect(xss).toContainText('<b>bold</b>');
  // ...and produced no element of their own.
  await expect(page.locator('table b')).toHaveCount(0);
  await expect(page.locator('img[src="x"]')).toHaveCount(0);

  // The host page also carries the hostile freshclam error: open it.
  await page.getByTestId('fleet-link-xss01').click();
  await expect(page.getByTestId('host-page')).toBeVisible();
  await expect(page.locator('script:not([src])')).toHaveCount(0);
  await expect(page.locator('main img[src="x"], main b')).toHaveCount(0);
  expect(dialogs).toBe(0);
  expect(await page.evaluate(() => (window as any).__pwned)).toBe(false);
});
