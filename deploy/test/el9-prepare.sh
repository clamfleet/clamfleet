#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# el9-prepare.sh - install the clamfleet-agent and clamfleet-server .rpm files in the AlmaLinux 9
# VM (SELinux enforcing, ClamAV from EPEL) and do what the install notice tells an
# administrator to do for detections: the VirusEvent line in clamd's configuration.
#
# Run after the snapshot reset (the suite calls it, with CFT_EXEC set to the VM's exec prefix):
#   1. the .rpm files named by CF_AGENT_RPM and CF_SERVER_RPM go over stdin to /root/pkgs and are
#      installed with dnf. Their %post loads the SELinux module at priority 300 and relabels the
#      spool: nothing in this script does, so a package that stops doing it fails the SELinux scenarios;
#   2. `VirusEvent /usr/bin/clamfleet-agent event` is written into /etc/clamd.d/scan.conf (it is
#      commented out in the stock file; the package never edits it), and clamd@scan restarted.
# The VM's snapshot already has LocalSocket enabled in scan.conf (the stock file has it commented
# out: docs/testing.md "The AlmaLinux 9 VM").
# Idempotent. Env: CFT_EXEC (required): the command prefix that runs a command in the VM;
# CF_AGENT_RPM, CF_SERVER_RPM (required): the packages to install.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Maintainer-specific names live in the gitignored local.env, never in the repo.
[ -f "$here/local.env" ] && . "$here/local.env"
CFT_EXEC="${CFT_EXEC:?set CFT_EXEC to the exec prefix of the AlmaLinux 9 VM, see docs/testing.md (make e2e-el9)}"
CF_AGENT_RPM="${CF_AGENT_RPM:?set CF_AGENT_RPM (the suite does it; make packages builds the file)}"
CF_SERVER_RPM="${CF_SERVER_RPM:?set CF_SERVER_RPM (the suite does it; make packages builds the file)}"
for f in "$CF_AGENT_RPM" "$CF_SERVER_RPM"; do
	[ -f "$f" ] || { echo "el9-prepare: $f does not exist (make packages)" >&2; exit 1; }
done

# One tar stream with both packages (no shell syntax in the arguments: ssh re-parses them).
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$CF_AGENT_RPM" "$CF_SERVER_RPM" "$work/"
echo 'rm -rf /root/pkgs; mkdir -p /root/pkgs' | $CFT_EXEC bash -s
tar -cf - -C "$work" . | $CFT_EXEC tar -xf - -C /root/pkgs --no-same-owner
{
	cat <<'CF_REST'
set -euo pipefail
dnf install -y /root/pkgs/*.rpm </dev/null
grep -q '^VirusEvent /usr/bin/clamfleet-agent event$' /etc/clamd.d/scan.conf || sed -i 's|^#VirusEvent .*|VirusEvent /usr/bin/clamfleet-agent event|' /etc/clamd.d/scan.conf
grep -q '^VirusEvent /usr/bin/clamfleet-agent event$' /etc/clamd.d/scan.conf || { echo "el9-prepare: could not set VirusEvent in /etc/clamd.d/scan.conf" >&2; exit 1; }
systemctl restart clamd@scan
CF_REST
} | $CFT_EXEC bash -s
echo "el9-prepare: ok"
