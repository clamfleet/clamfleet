#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# aa-prepare.sh - install the clamfleet-agent .deb in the AppArmor VM (Debian 13, AppArmor
# enforcing) and wire clamd the way an administrator does after it.
#
# Run after the snapshot reset and after prepare-agent.sh / prepare-server.sh (the suite calls
# them in that order, with CFT_EXEC set to the VM's exec prefix):
#   1. the .deb named by CF_AGENT_DEB is installed (dpkg -i). ITS POSTINSTALL loads the profile
#      clamfleet-agent-event: nothing in this script does, so a package that stops loading it
#      fails the transition scenarios. The package's own service is then disabled and stopped,
#      because the suite runs its own transient agent unit with a short interval and two agents
#      would fight for the spool lock;
#   2. the two lines of the installed /usr/share/clamfleet-agent/usr.sbin.clamd.local are
#      appended to /etc/apparmor.d/local/usr.sbin.clamd (once), as the install notice says: the
#      package never edits that file;
#   3. `VirusEvent /usr/bin/clamfleet-agent event` in /etc/clamav/clamd.conf, then
#      `dpkg-reconfigure -f noninteractive clamav-daemon`, and a check that the line
#      survived it (assumption A4 of the milestone 5 plan: Debian keeps a hand-added
#      line across a package reconfigure);
#   4. clamd's profile reloaded (the local include changed), clamd restarted;
#   5. kernel.printk_ratelimit=0: AppArmor's DENIED lines go through printk, which drops
#      more than 10 messages in 5 s, and an agent run under the profile is refused dozens of
#      times at once (every file and program it tries): without this a DENIED line the suite
#      looks for can be lost. Runtime only: the snapshot reset puts it back.
# Idempotent. Env: CFT_EXEC (required): the command prefix that runs a command in the VM;
# CF_AGENT_DEB (required): the path of the clamfleet-agent .deb to install.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Maintainer-specific names live in the gitignored local.env, never in the repo.
[ -f "$here/local.env" ] && . "$here/local.env"
CFT_EXEC="${CFT_EXEC:?set CFT_EXEC to the exec prefix of the AppArmor VM, see docs/testing.md (make e2e-apparmor)}"
CF_AGENT_DEB="${CF_AGENT_DEB:?set CF_AGENT_DEB to the clamfleet-agent .deb (the suite does it; make packages builds it)}"
[ -f "$CF_AGENT_DEB" ] || { echo "aa-prepare: $CF_AGENT_DEB does not exist (make packages)" >&2; exit 1; }

# The package goes over stdin to tee (no shell syntax in the arguments: ssh re-parses them).
$CFT_EXEC tee /root/clamfleet-agent.deb <"$CF_AGENT_DEB" >/dev/null
{
	cat <<'CF_REST'
set -euo pipefail
# stdin is this script: without </dev/null dpkg reads its conffile answer from it and swallows the
# lines that follow. --force-confold keeps the suite's own agent.yaml (prepare-agent.sh wrote one).
DEBIAN_FRONTEND=noninteractive dpkg --force-confold -i /root/clamfleet-agent.deb </dev/null
# The suite runs its own agent unit; a still-running packaged one would hold the spool lock.
systemctl stop clamfleet-agent.service
systemctl disable clamfleet-agent.service
if systemctl is-active --quiet clamfleet-agent.service; then echo "aa-prepare: the packaged clamfleet-agent.service is still running" >&2; exit 1; fi
touch /etc/apparmor.d/local/usr.sbin.clamd
if ! grep -q 'Px -> clamfleet-agent-event' /etc/apparmor.d/local/usr.sbin.clamd; then
	cat /usr/share/clamfleet-agent/usr.sbin.clamd.local >> /etc/apparmor.d/local/usr.sbin.clamd
fi
grep -q '^VirusEvent ' /etc/clamav/clamd.conf || echo 'VirusEvent /usr/bin/clamfleet-agent event' >> /etc/clamav/clamd.conf
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive clamav-daemon >/dev/null 2>&1 || true
grep -q '^VirusEvent /usr/bin/clamfleet-agent event$' /etc/clamav/clamd.conf || { echo "aa-prepare: the VirusEvent line did not survive dpkg-reconfigure" >&2; exit 1; }
aa-status --json | grep -q '"clamfleet-agent-event": *"enforce"' || { echo "aa-prepare: the package did not load the profile clamfleet-agent-event" >&2; exit 1; }
apparmor_parser -r /etc/apparmor.d/usr.sbin.clamd
systemctl restart clamav-daemon
sysctl -qw kernel.printk_ratelimit=0
CF_REST
} | $CFT_EXEC bash -s
echo "aa-prepare: ok"
