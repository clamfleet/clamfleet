#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# units_test.sh - static checks of the systemd units, sysusers.d and tmpfiles.d
# files in deploy/systemd (no systemd, no container). What it pins are the
# directives a mistake would silently remove: the token condition that stops an
# unconfigured agent from looping, the reload hook, the server's private state
# directory, the per-distribution clamd group and the M5 spool modes. The real
# proof that the units start under their hardening is the package e2e on Debian 13
# and AlmaLinux 9 (docs/testing.md).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
d="$here/../systemd"
fail() { echo "units_test: FAIL: $*" >&2; exit 1; }
has() { grep -q -E -- "$2" "$d/$1" || fail "$1 does not match /$2/"; }
hasnt() { if grep -q -E -- "$2" "$d/$1"; then fail "$1 matches /$2/"; fi; }

for f in "$d"/*.service "$d"/*.timer "$d"/sysusers/* "$d"/tmpfiles/*; do
	grep -q 'SPDX-License-Identifier: AGPL-3.0-only' "$f" || fail "$f has no SPDX identifier"
	grep -q 'SPDX-FileCopyrightText: The ClamFleet Authors' "$f" || fail "$f has no SPDX copyright"
done
for u in "$d"/*.service; do
	b="$(basename "$u")"
	hasnt "$b" '^User=root'
	has "$b" '^NoNewPrivileges=yes'
	has "$b" '^CapabilityBoundingSet=$'
	has "$b" '^ProtectSystem=strict'
done

# The agent waits for its token instead of looping.
has clamfleet-agent.service '^ConditionPathExists=/etc/clamfleet/token$'
has clamfleet-agent.service '^User=clamfleet$'
has clamfleet-agent.service '^ExecStart=/usr/bin/clamfleet-agent run$'
has clamfleet-agent.service '^Restart=on-failure$'
has clamfleet-agent.service '^ReadWritePaths=/var/lib/clamfleet$'

# The server: private state directory, reload, no new capabilities.
has clamfleet-server.service '^User=clamfleet-server$'
has clamfleet-server.service '^StateDirectory=clamfleet-server$'
has clamfleet-server.service '^StateDirectoryMode=0700$'
has clamfleet-server.service '^ExecReload=/bin/kill -HUP \$MAINPID$'
has clamfleet-server.service '^UMask=0077$'
has clamfleet-server.service '^MemoryDenyWriteExecute=yes$'

# The scan and the backup are one-shot services started by timers that ship disabled.
has clamfleet-scan.service '^Type=oneshot$'
has clamfleet-scan.service '^ExecStart=/usr/bin/clamfleet-agent scan$'
has clamfleet-scan.service '^TimeoutStartSec=73h$'
has clamfleet-scan.timer '^RandomizedDelaySec=2h$'
has clamfleet-scan.timer '^Persistent=true$'
has clamfleet-server-backup.service '^ExecStart=/usr/bin/clamfleet-server backup --verify$'
has clamfleet-server-backup.timer '^RandomizedDelaySec=1h$'
has clamfleet-server-backup.timer '^Persistent=true$'

# clamd's group differs per distribution: Debian clamav, EPEL clamscan.
has sysusers/clamfleet-agent.deb.conf '^m clamfleet clamav$'
has sysusers/clamfleet-agent.rpm.conf '^m clamfleet clamscan$'
# EPEL's socket directory belongs to virusgroup: the agent must be in it to reach clamd.
has sysusers/clamfleet-agent.rpm.conf '^m clamfleet virusgroup$'
hasnt sysusers/clamfleet-agent.deb.conf 'virusgroup'
for v in deb rpm; do
	has "sysusers/clamfleet-agent.$v.conf" '^m clamfleet systemd-journal$'
	has "sysusers/clamfleet-agent.$v.conf" '^u clamfleet - '
done
has tmpfiles/clamfleet-agent.deb.conf '^d /var/lib/clamfleet 0750 clamfleet clamav -$'
has tmpfiles/clamfleet-agent.deb.conf '^d /var/lib/clamfleet/spool 2750 clamfleet clamav -$'
has tmpfiles/clamfleet-agent.rpm.conf '^d /var/lib/clamfleet 0750 clamfleet clamscan -$'
has tmpfiles/clamfleet-agent.rpm.conf '^d /var/lib/clamfleet/spool 2750 clamfleet clamscan -$'
# The RHEL family pre-creates what clamd's domain writes, so it carries the SELinux label from the start.
has tmpfiles/clamfleet-agent.rpm.conf '^d /var/lib/clamfleet/spool/events 3770 clamfleet clamscan -$'
has tmpfiles/clamfleet-agent.rpm.conf '^f /var/lib/clamfleet/spool/usage 0660 clamfleet clamscan -$'
hasnt tmpfiles/clamfleet-agent.deb.conf '^d /var/lib/clamfleet/spool/events'
hasnt tmpfiles/clamfleet-agent.rpm.conf 'clamav'
hasnt sysusers/clamfleet-agent.rpm.conf 'clamav'
has sysusers/clamfleet-server.conf '^u clamfleet-server - '
has tmpfiles/clamfleet-server.conf '^d /var/lib/clamfleet-server 0700 clamfleet-server clamfleet-server -$'
echo "units_test: ok"
