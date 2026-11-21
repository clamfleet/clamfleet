// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Flow 4: a viewer cannot reach admin actions, by UI or by direct request; an admin can.
import { test, expect, fixture, login } from './helpers';

// The browser logs the deliberate 403 page load; nothing else is allowed.
test.use({ allowedConsole: [/status of 403/] });

test('a viewer gets no admin controls and a 403 on every admin route', async ({ page }) => {
  const fx = fixture();
  await login(page, fx.viewer);
  await expect(page.getByTestId('fleet-table')).toBeVisible();
  await expect(page.getByTestId('nav-admin')).toHaveCount(0);
  await expect(page.getByTestId('nav-alerts')).toHaveCount(0);

  // Host page: the admin block is absent.
  await page.getByTestId('fleet-link-ok01').click();
  await expect(page.getByTestId('host-page')).toBeVisible();
  await expect(page.getByTestId('host-actions-ok01')).toHaveCount(0);
  await expect(page.getByTestId('host-admin')).toHaveCount(0);

  // Direct navigation.
  const nav = await page.goto('/admin/hosts');
  expect(nav!.status()).toBe(403);
  await expect(page.getByTestId('error-page')).toHaveAttribute('data-status', '403');
  await expect(page.getByTestId('admin-hosts-page')).toHaveCount(0);

  const alerts = await page.goto('/admin/alerts');
  expect(alerts!.status()).toBe(403);
  await expect(page.getByTestId('admin-alerts-page')).toHaveCount(0);

  // Direct writes with a valid session and a valid CSRF token: only the role stops them.
  await page.goto('/');
  const csrf = await page.locator('meta[name="csrf-token"]').getAttribute('content');
  expect(csrf).toBeTruthy();
  const headers = { 'X-CSRF-Token': csrf! };
  for (const path of [
    '/admin/hosts',
    '/admin/alerts/seeded-hook/test',
    '/admin/hosts/ok01/rotate-token',
    '/admin/hosts/ok01/revoke-token',
    '/admin/hosts/ok01/delete',
  ]) {
    const res = await page.request.post(path, { headers, form: { name: 'viewer-made-host' } });
    expect(res.status(), path).toBe(403);
  }

  // Nothing happened: ok01 still exists and still reports OK.
  await page.goto('/');
  await expect(page.getByTestId('fleet-row-ok01')).toHaveAttribute('data-state', 'OK');
  await expect(page.getByTestId('fleet-row-viewer-made-host')).toHaveCount(0);
});

// Milestone 5: a viewer sees every detection (paths included) and the menu item, but gets no
// acknowledgement markup, and the route itself refuses (admin class) with a valid session and token.
test('a viewer sees detections but cannot acknowledge them', async ({ page }) => {
  const fx = fixture();
  await login(page, fx.viewer);
  await expect(page.getByTestId('nav-events')).toBeVisible();
  await page.getByTestId('nav-events').click();
  await expect(page.getByTestId('events-page')).toBeVisible();
  await expect(page.getByTestId('events-table')).toBeVisible();
  // The second crit01 detection: events.spec.ts acknowledges the first one (specs share one server).
  const id = fx.events.ids_by_host['crit01'][1];
  await expect(page.getByTestId(`event-row-${id}`)).toBeVisible();
  await expect(page.locator('[data-testid^="event-ack-"]')).toHaveCount(0);
  await expect(page.locator('[data-testid^="events-bulk-"]')).toHaveCount(0);

  const csrf = await page.locator('meta[name="csrf-token"]').getAttribute('content');
  expect(csrf).toBeTruthy();
  const res = await page.request.post(`/events/${id}/ack`, { headers: { 'X-CSRF-Token': csrf! } });
  expect(res.status()).toBe(403);
  const bulk = await page.request.post('/events/ack', { headers: { 'X-CSRF-Token': csrf! }, form: { upto: '999', expected: '1' } });
  expect(bulk.status()).toBe(403);
  // Still open.
  await page.reload();
  await expect(page.getByTestId(`event-row-${id}`)).toHaveAttribute('data-ack', 'false');
});

test('an admin sees the admin controls', async ({ page }) => {
  const fx = fixture();
  await login(page, fx.admin);
  await page.getByTestId('nav-admin').click();
  await expect(page.getByTestId('admin-hosts-page')).toBeVisible();
  await expect(page.getByTestId('admin-register-form')).toBeVisible();
  await expect(page.getByTestId('admin-host-row-ok01')).toBeVisible();
});
