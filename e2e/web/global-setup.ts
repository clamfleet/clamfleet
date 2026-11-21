// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Starts bin/webfixture twice on 127.0.0.1 (plain, and with --totp-required), both with --sso, waits for the READY
// lines, and hands URL and logins to the specs through JSON files (CLAMFLEET_E2E_FIXTURE and
// CLAMFLEET_E2E_FIXTURE_REQUIRED, with _URL variants). The returned function is Playwright's
// global teardown: it stops both, and each deletes its own temp directory.
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

interface Started { url: string; json: string; stop: () => Promise<void> }

// Starts one fixture process and waits for its READY line.
async function startFixture(extraArgs: string[]): Promise<Started> {
  const root = path.resolve(__dirname, '..', '..');
  const bin = path.join(root, 'bin', 'webfixture');
  const serverBin = path.join(root, 'bin', 'clamfleet-server');
  for (const f of [bin, serverBin]) {
    if (!fs.existsSync(f)) throw new Error(`${f} missing: run "make e2e-web" (it builds the binaries)`);
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clamfleet-e2e-web-'));
  const json = path.join(dir, 'fixture.json');
  const child = spawn(bin, ['--server-bin', serverBin, '--json-out', json, ...extraArgs], {
    stdio: ['ignore', 'pipe', 'inherit'],
  });

  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = new Promise<void>((r) => child.once('exit', () => r()));
      child.kill('SIGTERM');
      const t = setTimeout(() => child.kill('SIGKILL'), 10_000);
      await exited;
      clearTimeout(t);
    }
    fs.rmSync(dir, { recursive: true, force: true });
  };

  try {
    const url = await new Promise<string>((resolve, reject) => {
      let buf = '';
      const timer = setTimeout(() => reject(new Error('webfixture did not print READY within 60 s')), 60_000);
      child.once('exit', (code) => reject(new Error(`webfixture exited early (code ${code})`)));
      child.stdout!.on('data', (d: Buffer) => {
        buf += d.toString();
        const m = /^READY (https:\/\/127\.0\.0\.1:\d+)\s*$/m.exec(buf);
        if (m) {
          clearTimeout(timer);
          resolve(m[1]);
        }
      });
    });
    return { url, json, stop };
  } catch (e) {
    await stop();
    throw e;
  }
}

// Two fixtures: the normal console (all specs but the forced-enrolment one) and one with
// auth.local.totp_required. Two origins, so the cookies of the two never meet in one test.
// Both run with --sso (the fake OpenID Connect provider and LDAP directory), so every local
// sign-in and two-factor spec also runs with the SSO button and the "Email or user name" field
// present: local sign-in must not regress when the form gained LDAP routing.
export default async function globalSetup(): Promise<() => Promise<void>> {
  const plain = await startFixture(['--sso']);
  let required: Started;
  try {
    required = await startFixture(['--sso', '--totp-required']);
  } catch (e) {
    await plain.stop();
    throw e;
  }
  process.env.CLAMFLEET_E2E_FIXTURE = plain.json;
  process.env.CLAMFLEET_E2E_URL = plain.url;
  process.env.CLAMFLEET_E2E_FIXTURE_REQUIRED = required.json;
  process.env.CLAMFLEET_E2E_URL_REQUIRED = required.url;
  return async () => {
    await Promise.all([plain.stop(), required.stop()]);
  };
}
