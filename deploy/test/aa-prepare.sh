#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# aa-prepare.sh - install the AppArmor files and the VirusEvent line in the
# AppArmor VM (Debian 13, AppArmor enforcing), the way the package will.
#
# Run after the snapshot reset and after prepare-agent.sh / prepare-server.sh
# (the suite calls them in that order, with CFT_EXEC set to the VM's exec prefix):
#   1. /etc/apparmor.d/clamfleet-agent-event from deploy/apparmor/clamfleet-agent-event;
#   2. the two lines of deploy/apparmor/usr.sbin.clamd.local appended to
#      /etc/apparmor.d/local/usr.sbin.clamd (once);
#   3. `VirusEvent /usr/bin/clamfleet-agent event` in /etc/clamav/clamd.conf, then
#      `dpkg-reconfigure -f noninteractive clamav-daemon`, and a check that the line
#      survived it (assumption A4 of the milestone 5 plan: Debian keeps a hand-added
#      line across a package reconfigure);
#   4. both profiles loaded with apparmor_parser -r, clamd restarted;
#   5. kernel.printk_ratelimit=0: AppArmor's DENIED lines go through printk, which drops
#      more than 10 messages in 5 s, and an agent run under the profile is refused dozens of
#      times at once (every file and program it tries): without this a DENIED line the suite
#      looks for can be lost. Runtime only: the snapshot reset puts it back.
# It does not install the agent binary: the suite pushes it to /usr/bin/clamfleet-agent.
# Idempotent. Env: CFT_EXEC (required): the command prefix that runs a command in the VM.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Maintainer-specific names live in the gitignored local.env, never in the repo.
[ -f "$here/local.env" ] && . "$here/local.env"
CFT_EXEC="${CFT_EXEC:?set CFT_EXEC to the exec prefix of the AppArmor VM, see docs/testing.md (make e2e-apparmor)}"
aa="$here/../apparmor"

remote() {
	echo 'set -euo pipefail'
	echo "cat > /etc/apparmor.d/clamfleet-agent-event <<'CF_PROFILE_EOF'"
	cat "$aa/clamfleet-agent-event"
	echo 'CF_PROFILE_EOF'
	echo 'touch /etc/apparmor.d/local/usr.sbin.clamd'
	echo "if ! grep -q 'Px -> clamfleet-agent-event' /etc/apparmor.d/local/usr.sbin.clamd; then"
	echo "cat >> /etc/apparmor.d/local/usr.sbin.clamd <<'CF_LOCAL_EOF'"
	cat "$aa/usr.sbin.clamd.local"
	echo 'CF_LOCAL_EOF'
	echo 'fi'
	cat <<'CF_REST'
grep -q '^VirusEvent ' /etc/clamav/clamd.conf || echo 'VirusEvent /usr/bin/clamfleet-agent event' >> /etc/clamav/clamd.conf
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive clamav-daemon >/dev/null 2>&1 || true
grep -q '^VirusEvent /usr/bin/clamfleet-agent event$' /etc/clamav/clamd.conf || { echo "aa-prepare: the VirusEvent line did not survive dpkg-reconfigure" >&2; exit 1; }
apparmor_parser -r /etc/apparmor.d/clamfleet-agent-event /etc/apparmor.d/usr.sbin.clamd
systemctl restart clamav-daemon
sysctl -qw kernel.printk_ratelimit=0
CF_REST
}
remote | $CFT_EXEC bash -s
echo "aa-prepare: ok"
