// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Flow 3: a state change reaches an open fleet page by itself (the 15 s poll), no reload.
import { test, expect, fixture, login } from './helpers';

test('a CRIT report for an OK host appears on the open page without a reload', async ({ page, request }) => {
  const fx = fixture();
  await login(page, fx.viewer);
  const row = page.getByTestId('fleet-row-ok01');
  await expect(row).toHaveAttribute('data-state', 'OK');

  // Mark the document: a reload would drop this, so it proves the row changed in place.
  await page.evaluate(() => { (window as any).__noReload = true; });

  // Same shape as the fixture's own reports (a real agent report). ts must be strictly newer than
  // the previous one: the fixture stamped "now" at start-up, so go ahead of it (one minute is
  // within the server's skew tolerance) and a bit further for the restore below.
  const post = (clamdUp: boolean, aheadMs: number) =>
    request.post(`${fx.url}/v1/report`, {
      headers: { Authorization: `Bearer ${fx.hosts.ok01.token}` },
      data: {
        schema: 1, host: 'ok01', agent_version: '0.1.0', tags: ['prod', 'web'], interval_seconds: 300,
        ts: new Date(Date.now() + aheadMs).toISOString().replace(/\.\d+Z$/, 'Z'),
        os: { id: 'debian', version: '13' },
        clamd: { up: clamdUp, version: clamdUp ? '1.4.3' : null, queue: 0, error: clamdUp ? null : 'ping: timeout' },
        sigs: {
          daily: { version: 28181, built: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), sigs: 355854 },
          main: { version: 63, built: '2025-12-16T23:18:22Z', sigs: 3287027 },
          bytecode: { version: 339, built: '2025-09-11T12:29:19Z', sigs: 80 },
        },
        freshclam: { last_ok: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), last_error: null, last_error_msg: null, source: 'journal' },
        services: { clamd: 'active', freshclam: 'active', clamonacc: 'inactive' },
        last_scan: null,
      },
    });
  try {
      expect((await post(false, 60_000)).status()).toBe(202);

    // The page polls every 15 s: allow one full period plus slack.
    await expect(row).toHaveAttribute('data-state', 'CRIT', { timeout: 25_000 });
    await expect(page.getByTestId('fleet-state-ok01')).toHaveText('CRIT');
    await expect(page.getByTestId('fleet-reasons-ok01')).toContainText('clamd');
    expect(await page.evaluate(() => (window as any).__noReload)).toBe(true);
  } finally {
    // Put ok01 back: the other specs share this server and expect it OK.
    await post(true, 120_000);
  }
});
