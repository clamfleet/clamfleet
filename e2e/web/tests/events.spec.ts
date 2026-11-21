// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Milestone 5, flow: the Detections page and acknowledgement.
// The fixture posts the detections through the real /v1/event; see docs/testing.md.
//
// What would turn it red: a route that is not mounted, the htmx swap blocked by the CSP (the
// console-guard fixture fails the test on any console error), a path that reaches the page as
// markup or as a raw bidi character, wrong counts.
import { test, expect, fixture, login } from './helpers';

test('an admin reads the detections, hostile names stay inert, and acknowledges one without a page load', async ({ page }) => {
  const fx = fixture();
  const dialogs: string[] = [];
  page.on('dialog', async (d) => {
    dialogs.push(d.message());
    await d.dismiss();
  });
  await login(page, fx.admin);

  // The menu carries the open count.
  await expect(page.getByTestId('nav-events')).toContainText('Detections');
  await expect(page.getByTestId('nav-events-count')).toHaveText(String(fx.events.open_count));

  // Hostile names (host xss01): rendered as text, with the invisible characters shown as escape elements.
  await page.getByTestId('nav-events').click();
  await expect(page.getByTestId('events-page')).toBeVisible();
  await page.getByTestId('events-filter-host').selectOption('xss01');
  await page.getByTestId('events-filter-submit').click();
  const [rlo, literal, ls, backslash, raw] = fx.events.ids_by_host['xss01'];
  await expect(page.getByTestId('events-count')).toContainText('5 matching');

  const rloPath = page.getByTestId(`event-path-${rlo}`);
  // The markup is text, never an element.
  await expect(rloPath).toContainText('<img src=x onerror=alert(1)>');
  await expect(rloPath.locator('img')).toHaveCount(0);
  // The real U+202E is a styled .esc element, not a raw character.
  await expect(rloPath.locator('.esc')).toHaveText('\\u{202E}');
  // The sibling with the literal text \u{202E} is plain text with no escape element.
  const literalPath = page.getByTestId(`event-path-${literal}`);
  await expect(literalPath).toContainText('literal\\u{202E}name');
  await expect(literalPath.locator('.esc')).toHaveCount(0);
  // A real U+2028, a real backslash and a raw non-UTF-8 byte.
  await expect(page.getByTestId(`event-path-${ls}`).locator('.esc')).toHaveText('\\u{2028}');
  await expect(page.getByTestId(`event-path-${backslash}`)).toContainText('back\\slash.txt');
  await expect(page.getByTestId(`event-path-${raw}`).locator('.esc')).toHaveText('\\xff');
  // The signature with HTML is text too.
  await expect(page.getByTestId(`event-sig-${rlo}`)).toContainText('<b>Win.Test.XSS</b>');
  await expect(page.getByTestId(`event-sig-${rlo}`).locator('b')).toHaveCount(0);
  // The raw characters are nowhere in the DOM, and nothing from the data ran.
  const html = await page.content();
  expect(html).not.toContain('‮');
  expect(html).not.toContain(' ');
  expect(dialogs, 'a dialog opened: data was executed').toEqual([]);

  // warn01: one row shown "x2" (two ids, same key).
  await page.getByTestId('events-filter-host').selectOption('warn01');
  await page.getByTestId('events-filter-submit').click();
  const dup = fx.events.ids_by_host['warn01'][0];
  await expect(page.getByTestId(`event-occurrences-${dup}`)).toHaveText('×2');

  // crit01: acknowledge one detection. The row swaps in place (no page load).
  await page.getByTestId('events-filter-host').selectOption('crit01');
  await page.getByTestId('events-filter-submit').click();
  const [first, second] = fx.events.ids_by_host['crit01'];
  await expect(page.getByTestId(`event-row-${first}`)).toHaveAttribute('data-ack', 'false');
  await page.evaluate(() => ((window as unknown as { __noReload: number }).__noReload = 1));
  await page.getByTestId(`event-ack-${first}`).click();
  await expect(page.getByTestId(`event-ackby-${first}`)).toHaveText(`Acknowledged by ${fx.admin.email}`);
  await expect(page.getByTestId(`event-row-${first}`)).toHaveAttribute('data-ack', 'true');
  await expect(page.getByTestId(`event-ack-${first}`)).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { __noReload?: number }).__noReload), 'the page reloaded').toBe(1);
  // The other one is untouched.
  await expect(page.getByTestId(`event-row-${second}`)).toHaveAttribute('data-ack', 'false');

  // A reload keeps the status (the default Open filter no longer lists it; All does), the menu
  // count is one lower, and the fleet column follows.
  await page.reload();
  await expect(page.getByTestId(`event-row-${first}`)).toHaveCount(0);
  await expect(page.getByTestId(`event-row-${second}`)).toBeVisible();
  await page.goto('/events?host=crit01&ack=all');
  await expect(page.getByTestId(`event-ackby-${first}`)).toHaveText(`Acknowledged by ${fx.admin.email}`);
  await expect(page.getByTestId('nav-events-count')).toHaveText(String(fx.events.open_count - 1));
  await page.getByTestId('nav-fleet').click();
  await expect(page.getByTestId('fleet-open-crit01')).toHaveText('1');
  await expect(page.getByTestId('fleet-count-open')).toContainText(`${fx.events.open_count - 1} open detections`);
});
