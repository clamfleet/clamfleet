// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Starts bin/webfixture on 127.0.0.1, waits for its READY line, and hands URL and logins to
// the specs through a JSON file (path in CLAMFLEET_E2E_FIXTURE). The returned function is
// Playwright's global teardown: it stops the fixture, which deletes its own temp directory.
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export default async function globalSetup(): Promise<() => Promise<void>> {
  const root = path.resolve(__dirname, '..', '..');
  const bin = path.join(root, 'bin', 'webfixture');
  const serverBin = path.join(root, 'bin', 'clamfleet-server');
  for (const f of [bin, serverBin]) {
    if (!fs.existsSync(f)) throw new Error(`${f} missing: run "make e2e-web" (it builds the binaries)`);
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clamfleet-e2e-web-'));
  const json = path.join(dir, 'fixture.json');
  const child = spawn(bin, ['--server-bin', serverBin, '--json-out', json], { stdio: ['ignore', 'pipe', 'inherit'] });

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
    process.env.CLAMFLEET_E2E_FIXTURE = json;
    process.env.CLAMFLEET_E2E_URL = url;
  } catch (e) {
    await stop();
    throw e;
  }
  return stop;
}
