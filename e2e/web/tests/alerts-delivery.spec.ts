// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Flow: a state change of alerts01 reaches the seeded webhook target, and its log page says so.
import { test, expect, fixture, login, receiverRequests, signatureValid } from './helpers';

test('clamd going down on alerts01 delivers one state_change to CRIT and logs a sent row', async ({ page, request }) => {
  const fx = fixture();
  const a = fx.alerts;
  expect((await request.delete(a.requests_url)).ok()).toBe(true);

  const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z');
  // ts must be strictly newer than the seeding report (stamped at fixture start): one minute
  // ahead is inside the server's skew tolerance.
  const res = await request.post(`${fx.url}/v1/report`, {
    headers: { Authorization: `Bearer ${fx.hosts[a.host].token}` },
    data: {
      schema: 1, host: a.host, agent_version: '0.1.0', tags: ['alerts'], interval_seconds: 300,
      ts: iso(Date.now() + 60_000),
      os: { id: 'debian', version: '13' },
      clamd: { up: false, version: null, queue: 0, error: 'ping: timeout' },
      sigs: {
        daily: { version: 28181, built: iso(Date.now()), sigs: 355854 },
        main: { version: 63, built: '2025-12-16T23:18:22Z', sigs: 3287027 },
        bytecode: { version: 339, built: '2025-09-11T12:29:19Z', sigs: 80 },
      },
      freshclam: { last_ok: iso(Date.now()), last_error: null, last_error_msg: null, source: 'journal' },
      services: { clamd: 'active', freshclam: 'active', clamonacc: 'inactive' },
      last_scan: null,
    },
  });
  expect(res.status()).toBe(202);

  // Only the seeded target's path: other specs' targets may take alerts01 too.
  const seededPath = new URL(a.hook_url).pathname;
  await expect.poll(async () => (await receiverRequests(request, fx)).filter((r) => r.path === seededPath).length,
    { timeout: 20_000, message: 'the receiver should get the alert' }).toBeGreaterThanOrEqual(1);
  const got = (await receiverRequests(request, fx)).filter((r) => r.path === seededPath);
  expect(got).toHaveLength(1);
  const p = JSON.parse(got[0].body);
  expect(p.kind).toBe('state_change');
  expect(p.host).toBe('alerts01');
  expect(p.to).toBe('CRIT');
  expect(p.url).toBe(`${fx.url}/hosts/alerts01`);
  expect(signatureValid(got[0], a.signing_key)).toBe(true);

  // The target's page lists the delivery.
  await login(page, fx.admin);
  await page.goto(`/admin/alerts/${a.seeded_target}`);
  await expect(page.getByTestId('alert-log-table')).toBeVisible();
  await expect(page.getByTestId('alert-log-row').filter({ hasText: 'sent' })).toHaveCount(1);

  // Put the host back for the other specs (shared server).
  const back = await request.post(`${fx.url}/v1/report`, {
    headers: { Authorization: `Bearer ${fx.hosts[a.host].token}` },
    data: {
      schema: 1, host: a.host, agent_version: '0.1.0', tags: ['alerts'], interval_seconds: 300,
      ts: iso(Date.now() + 120_000),
      os: { id: 'debian', version: '13' },
      clamd: { up: true, version: '1.4.3', queue: 0, error: null },
      sigs: {
        daily: { version: 28181, built: iso(Date.now()), sigs: 355854 },
        main: { version: 63, built: '2025-12-16T23:18:22Z', sigs: 3287027 },
        bytecode: { version: 339, built: '2025-09-11T12:29:19Z', sigs: 80 },
      },
      freshclam: { last_ok: iso(Date.now()), last_error: null, last_error_msg: null, source: 'journal' },
      services: { clamd: 'active', freshclam: 'active', clamonacc: 'inactive' },
      last_scan: null,
    },
  });
  expect(back.status()).toBe(202);
});
