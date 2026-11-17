#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# clamfleet-agent postinstall (deb postinst / rpm %post). One script for both formats,
# told apart by the first argument: deb "configure [previous-version]", rpm "1" (install)
# or "2" (upgrade). nfpm has no debhelper or rpm macros, so systemctl is called directly.
#
# Every step is idempotent, and a failing step exits non-zero: the package is then left
# half-configured and `dpkg --configure -a` (or `dnf reinstall`) completes it once the
# cause is fixed. Running the script twice changes nothing.
#
# This script never edits another package's files: clamd.conf (the VirusEvent line) and
# Debian's AppArmor local include for clamd belong to the clamd package and to the
# administrator. The notice at the end prints the exact lines to add.
#
# Paths are plain assignments, not environment overrides: a root shell with a stray
# variable must not redirect a maintainer script (deploy/test/packages_test.sh rewrites
# these lines in a copy).
ETC_DIR=/etc/clamfleet
STATE_DIR=/var/lib/clamfleet
SD_RUN=/run/systemd/system
SYSUSERS=/usr/lib/sysusers.d/clamfleet-agent.conf
TMPFILES=/usr/lib/tmpfiles.d/clamfleet-agent.conf
APPARMOR_PROFILE=/etc/apparmor.d/clamfleet-agent-event
SELINUX_MODULE=/usr/share/selinux/packages/clamfleet/clamfleet.cil

set -eu

# Runtime actions need a booted systemd; enable and preset work offline (a chroot, a container
# image build), so a package can still be installed there.
sd() {
	if [ -d "$SD_RUN" ]; then systemctl "$@"; fi
}

case "${1:-}" in
	configure) fmt=deb; if [ -z "${2:-}" ]; then first=1; else first=0; fi ;;
	1) fmt=rpm; first=1 ;;
	2) fmt=rpm; first=0 ;;
	*) echo "clamfleet-agent: unexpected argument '${1:-}'" >&2; exit 1 ;;
esac

# 1. The user and the directories (the M5 modes), then systemd.
systemd-sysusers "$SYSUSERS"
systemd-tmpfiles --create "$TMPFILES"
sd daemon-reload

# 2. The confinement of the event command: ours only, never clamd's own files.
if [ "$fmt" = deb ]; then
	# aa-enabled succeeds when AppArmor is enabled; absent or failing means "not here".
	if command -v aa-enabled >/dev/null 2>&1 && aa-enabled >/dev/null 2>&1; then
		apparmor_parser -r -W "$APPARMOR_PROFILE"
	fi
else
	# Priority 300 everywhere (install, remove, tests): a plain `semodule -r` removes at
	# the default priority and would leave this module loaded.
	if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
		semodule -X 300 -i "$SELINUX_MODULE"
		restorecon -R "$STATE_DIR"
	fi
fi

# 3. The service. A first install enables it (deb: Debian practice) or applies the
# preset (rpm: normally disabled). The unit has ConditionPathExists=/etc/clamfleet/token,
# so without a token it shows "condition failed" instead of looping. An upgrade restarts
# a running agent; the old package's scripts (rpm: run AFTER this one with "1") do nothing.
if [ "$first" = 1 ]; then
	if [ "$fmt" = deb ]; then
		systemctl enable clamfleet-agent.service
		sd start clamfleet-agent.service || echo "clamfleet-agent: could not start the service now; see 'systemctl status clamfleet-agent'" >&2
	else
		systemctl preset clamfleet-agent.service
	fi
else
	sd try-restart clamfleet-agent.service
fi

# 4. The configuration must be readable by clamd's user: `clamfleet-agent event` runs as
# clamd's user, reads agent.yaml with no fallback and spools nothing if it cannot (M5
# decision 3). An administrator may have tightened the file; detections would then stop
# silently, so say so.
for u in clamav clamscan; do
	if id -u "$u" >/dev/null 2>&1; then
		if ! runuser -u "$u" -- test -r "$ETC_DIR/agent.yaml"; then
			echo "clamfleet-agent: WARNING: $ETC_DIR/agent.yaml is not readable by $u. The event command runs as $u and spools nothing without it: chmod 0644 $ETC_DIR/agent.yaml" >&2
		fi
	fi
done

if [ "$first" = 1 ]; then
	cat >&2 <<NOTICE
clamfleet-agent: installed. Next steps (docs: /usr/share/doc/clamfleet-agent/):
  1. Edit $ETC_DIR/agent.yaml (server URL; on the RHEL family the clamd paths are in the example).
  2. Register this host on the server ("clamfleet-server host add NAME") and write its token to
     $ETC_DIR/token (root:clamfleet, mode 0640), then: systemctl start clamfleet-agent
  3. Detections: add this line to clamd's configuration (this package never edits it):
       VirusEvent /usr/bin/clamfleet-agent event
     and restart clamd.
NOTICE
	if [ "$fmt" = deb ]; then
		cat >&2 <<NOTICE
  4. Debian with AppArmor: add the two lines of /usr/share/doc/clamfleet-agent/usr.sbin.clamd.local
     to /etc/apparmor.d/local/usr.sbin.clamd and run: apparmor_parser -r /etc/apparmor.d/usr.sbin.clamd
  5. Scheduled scans (optional): set scan.paths, then systemctl enable --now clamfleet-scan.timer
NOTICE
	else
		cat >&2 <<NOTICE
  4. SELinux: the module clamfleet is loaded (priority 300) and labels the spool.
  5. Scheduled scans (optional): set scan.paths, then systemctl enable --now clamfleet-scan.timer
NOTICE
	fi
fi
exit 0
