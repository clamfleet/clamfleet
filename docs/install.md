<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Installing ClamFleet from packages

Two packages per format: **`clamfleet-server`** (one per site) and **`clamfleet-agent`** (one per ClamAV host).
Download them from the GitHub release (amd64 only in v1; check them first, see [Verifying a download](#verifying-a-download)) or build
them with `make packages VERSION=x.y.z` (see [testing.md](testing.md)).
Tested on **Debian 13** (a container and a VM with AppArmor enforcing) and **AlmaLinux 9** with SELinux
enforcing, as the RHEL 9 stand-in (RHEL itself needs a subscription). Debian 12 is untested; the binaries are
static and should work.

## Verifying a download

A release holds the tarball, the four packages, two SBOMs, `SHA256SUMS` and its signature `SHA256SUMS.asc`
(`clamfleet-agent_1.0.0-rc.1_amd64.deb`, `clamfleet-agent-1.0.0-rc.1-1.x86_64.rpm`, and so on; the package's own version is `1.0.0~rc.1`, but file names carry no `~`; see
the table "What a release is" in [releasing.md](releasing.md#what-a-release-is) lists every file). The signing key is `deploy/release/clamfleet-release.asc` in this repository.

The fingerprints, as published in the README and `SECURITY.md` (both keys expire 2028-11-19; UID `ClamFleet Release <hi@madalin.me>`):

- Primary (certify only): `EEF3 BD8A 0FDA 41C0 C451 8B44 36E3 A39F 1BE2 6893`
- Signing subkey: `9ADD 4EBC D2FA 7C59 7280 D078 5605 86D7 BCFD 57AF`

**Every download.** The key file is not a release asset: fetch it from the tag you are installing (a raw file of the
repository at `refs/tags/vX.Y.Z`), for example
`curl -fsSLO https://raw.githubusercontent.com/clamfleet/clamfleet/refs/tags/vX.Y.Z/deploy/release/clamfleet-release.asc`.
Then compare its fingerprints with the list above. The README and `SECURITY.md` carry the same list, but they are copies
in this same repository: they help only if you got the key file some other way, and a replaced repository replaces them
together. The independent copies are on keys.openpgp.org, which lists the key (verified for hi@madalin.me; fetch it by
fingerprint or by email, see below), and on the maintainer's website, which **will list** the fingerprint (it does
not yet). Compare with keys.openpgp.org now and with the website once it does. A replaced key file would otherwise
vouch for itself.

```sh
# The independent copy: both commands must give the same fingerprints as the list above.
curl -fsS https://keys.openpgp.org/vks/v1/by-fingerprint/EEF3BD8A0FDA41C0C4518B4436E3A39F1BE26893 | gpg --show-keys --with-subkey-fingerprints
curl -fsS https://keys.openpgp.org/vks/v1/by-email/hi%40madalin.me | gpg --show-keys --with-subkey-fingerprints

gpg --show-keys --with-subkey-fingerprints clamfleet-release.asc   # compare BEFORE importing: the "pub" fingerprint and the "sub" one
gpg --import clamfleet-release.asc
gpg --verify SHA256SUMS.asc SHA256SUMS   # must say "Good signature"; its "Primary key fingerprint" line must be the primary above
sha256sum -c --ignore-missing SHA256SUMS # every file you downloaded must say OK
```

**RPM** (AlmaLinux, RHEL family). The rpm files are signed themselves, which rpm checks:

```sh
sudo rpm --import clamfleet-release.asc
rpm -Kv clamfleet-agent-*.rpm
```

The output **must contain a line `Signature, key ID <id>: OK`**, where `<id>` is the signing subkey's, lowercase, ending in `bcfd57af` (the short key ID: the last 8 hex digits of the subkey's fingerprint, which is the form rpm prints). If it shows only `digests OK` and no signature line,
the package is **unsigned**, and `rpm -Kv` still exits 0: do not install it. Without the key you get `NOKEY` and exit
status 1. `dnf install ./package.rpm` is believed not to check the signature of a local file by default, so run
`rpm -Kv` first (recorded in the release rehearsal, see releasing.md).

**Debian.** Debian does not check a `.deb` signature (dpkg ships with `no-debsig`, and `dpkg-sig` is not in Debian 13),
so the signed `SHA256SUMS` above is the check: verify it, then install the files that `sha256sum -c` accepted
(`sudo apt install ./clamfleet-agent_*.deb`).

## What the packages do, and do not do

- They install the binary, the systemd units, the example configuration, a sysusers.d and a tmpfiles.d file, and
  the confinement for the event command (our AppArmor profile on Debian, an SELinux module on the RHEL family).
- Debian enables and starts the services (Debian practice). The RHEL family follows the system preset, normally
  disabled: start the server with `systemctl enable --now clamfleet-server`.
- The agent service has `ConditionPathExists=/etc/clamfleet/token`: without a token it shows "condition failed",
  not a restart loop.
- The first server install creates the secret key file `/etc/clamfleet/server-secret.key`
  (`root:clamfleet-server 0640`). An upgrade or a re-run never replaces it.
- **They never edit another package's files.** clamd's configuration (the `VirusEvent` line) and Debian's AppArmor
  local include for clamd are yours: the install notice prints the exact lines.
- The scan timer and the backup timer ship **disabled**.
- Removing or purging never deletes the server's database or key file (see [Removal](#removal-and-purge)).

## The server

```
apt-get install ./clamfleet-server_X.Y.Z_amd64.deb          # Debian
dnf install ./clamfleet-server-X.Y.Z-1.x86_64.rpm            # RHEL family
```

1. Review `/etc/clamfleet/server.yaml` ([configuration.md](configuration.md)). The default listens on
   `127.0.0.1:8443` in plaintext: put a reverse proxy with TLS in front, or set `tls.cert` and `tls.key` (`systemctl
   reload clamfleet-server` re-reads them, see [operations.md](operations.md#tls-reload)).
2. Admin commands run as the server user: `sudo -u clamfleet-server clamfleet-server host add NAME` prints the
   host's token once; `sudo -u clamfleet-server clamfleet-server user add you@example.org --role admin` creates the
   first console user.
3. Back up the key file apart from the database backups: without it, stored TOTP secrets and webhook URLs cannot
   be opened.
4. Optional: `systemctl enable --now clamfleet-server-backup.timer` (a daily database backup, see operations.md).

## The agent

```
apt-get install ./clamfleet-agent_X.Y.Z_amd64.deb            # needs clamav-daemon
dnf install ./clamfleet-agent-X.Y.Z-1.x86_64.rpm             # needs clamd (EPEL)
```

1. Edit `/etc/clamfleet/agent.yaml`: the server URL (https, or http to a loopback host). The RHEL family package
   ships `agent.rhel9.yaml.example` (clamd `scan` instance, EPEL paths) as the configuration. The file is
   `root:root 0644` **on purpose**: `clamfleet-agent event` runs as clamd's user and must read it.
2. Write the host's token to `/etc/clamfleet/token`, `root:clamfleet 0640`, then `systemctl start clamfleet-agent`
   (RHEL: `enable --now`).
3. **Detections.** Add one line to clamd's configuration and restart clamd:

   | | File | Line |
   |---|---|---|
   | Debian | `/etc/clamav/clamd.conf` | `VirusEvent /usr/bin/clamfleet-agent event` |
   | RHEL family | `/etc/clamd.d/scan.conf` (the line is commented out by default) | `VirusEvent /usr/bin/clamfleet-agent event` |

   On the RHEL family `LocalSocket` must be set too (it is commented out by default; the agent reads clamd through it).

   Also check that `clamd.conf` does not turn off `EnableVersionCommand` or `EnableStatsCommand` (upstream defaults
   both to yes; Ubuntu 22.04's ClamAV 1.5 package writes `false` for both). With either off clamd answers `COMMAND
   UNAVAILABLE`, and the report has no version or no queue and `clamd.error` says which option to set.
4. **Debian with AppArmor** (the default): add the two lines the install notice
   prints (also in `/usr/share/clamfleet-agent/usr.sbin.clamd.local`) to `/etc/apparmor.d/local/usr.sbin.clamd` and run
   `apparmor_parser -r /etc/apparmor.d/usr.sbin.clamd`. Without them clamd cannot even start the shell for
   `VirusEvent`. The package loads our profile `clamfleet-agent-event` itself.
5. **RHEL family with SELinux:** nothing to do. The module `clamfleet` (priority 300) is loaded by the package and
   labels `spool/events` and `spool/usage`. See [detections.md](detections.md#selinux).
6. **Scheduled scans (optional):** set `scan.paths` in `agent.yaml`, then `systemctl enable --now
   clamfleet-scan.timer`. The scan never starts clamd; clamd reads the files as its own user.

The agent's user is added to clamd's group (`clamav` on Debian, `clamscan` on the RHEL family) and to
`systemd-journal`. On the RHEL family it is also added to `virusgroup`: EPEL's `/run/clamd.scan` is
`clamscan:virusgroup 0710`, so without that group the agent cannot reach clamd's socket and every report says clamd is down.

## Upgrading

Upgrade the **server first**, then the agents. The package restarts the service. A server restart migrates the
database, and **backs it up first** (see [operations.md](operations.md#backup-before-a-migration)); if the backup
fails the server refuses to start and the old schema is untouched. Your configuration edits are kept (conffiles).

## Removal and purge

`apt-get remove` / `dnf remove` stop and disable the units. **The server's database and key file are never
deleted, not even by `apt-get purge`**: a purge prints where they are. The agent's purge removes its state
directory (`/var/lib/clamfleet`: the spool and `last_scan.json`) but never follows a symlink, and if a mount point is below it removes nothing and names the mount (one `rm -rf --one-file-system` walk, no per-entry checks).
Users and groups stay (the usual practice for system users that may own files).
