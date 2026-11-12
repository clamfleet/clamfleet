// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Shared helpers: the fixture handoff, login, and a test fixture that fails any test that
// logs a browser console error (the console's CSP is strict, so a blocked inline script or
// style shows up there).
import { test as base, expect, type Page } from '@playwright/test';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';

export interface Login { email: string; password: string }
export interface FixtureInfo {
  url: string;
  admin: Login;
  viewer: Login;
  must_change: Login;
  enrol: Login;
  totp: Login & { secret_base32: string; recovery_codes: string[] };
  forced?: Login;
  hosts: Record<string, { token: string; initial_state: string }>;
}

export function fixture(): FixtureInfo {
  return JSON.parse(fs.readFileSync(process.env.CLAMFLEET_E2E_FIXTURE!, 'utf8'));
}

// The fixture started with --totp-required (its own origin; has the `forced` user).
export function fixtureRequired(): FixtureInfo & { forced: Login } {
  return JSON.parse(fs.readFileSync(process.env.CLAMFLEET_E2E_FIXTURE_REQUIRED!, 'utf8'));
}

function base32Decode(s: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s.replace(/[\s=]/g, '').toUpperCase()) {
    const i = alphabet.indexOf(ch);
    if (i < 0) throw new Error(`bad base32 character ${ch}`);
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// RFC 6238 / 4226 HOTP over a time counter; an independent second implementation next to the
// server's Go one. `digits` is 6 for the console; the RFC test vector uses 8.
function hotp(key: Buffer, counter: number, digits: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = h.readUInt32BE(off) & 0x7fffffff;
  return String(bin % 10 ** digits).padStart(digits, '0');
}

// Rule: the server verifies against the real clock and accepts each 30 s step once per user.
// stepOffset 1 gives the next step's code (inside the server's +-1 window), for a second
// sign-in of the same user within 30 s.
export function totp(secretBase32: string, stepOffset = 0, nowMs = Date.now()): string {
  return hotp(base32Decode(secretBase32), Math.floor(nowMs / 1000 / 30) + stepOffset, 6);
}

// RFC 6238 appendix B: SHA1 secret "12345678901234567890" at T=59 gives 94287082 (8 digits).
// Checked at load so a broken generator fails every spec instead of looking like a server bug.
{
  const got = hotp(Buffer.from('12345678901234567890'), Math.floor(59 / 30), 8);
  if (got !== '94287082') throw new Error(`TOTP helper fails the RFC 6238 vector: got ${got}`);
}

// allowedConsole: a test that navigates to a deliberate error page (403) lists the one message
// the browser logs for it; anything else still fails the test.
export const test = base.extend<{ consoleGuard: void; allowedConsole: RegExp[] }>({
  allowedConsole: [[], { option: true }],
  consoleGuard: [
    async ({ page, allowedConsole }, use) => {
      const problems: string[] = [];
      page.on('console', (m) => {
        if (m.type() === 'error' && !allowedConsole.some((re) => re.test(m.text()))) problems.push(`console: ${m.text()}`);
      });
      page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
      await use();
      expect(problems, 'browser console errors').toEqual([]);
    },
    { auto: true },
  ],
});
export { expect };

export async function login(page: Page, who: Login): Promise<void> {
  await page.goto('/login');
  await page.getByTestId('login-email').fill(who.email);
  await page.getByTestId('login-password').fill(who.password);
  await page.getByTestId('login-submit').click();
}
