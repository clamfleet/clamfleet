#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# clamfleet-agent postremove (deb postrm / rpm %postun).
#   deb "remove": unload our AppArmor profile (the file stays until purge).
#   deb "purge":  remove the agent's state directory (spool, last_scan.json); dpkg itself
#                 removes the conffile agent.yaml.
#   rpm "0":      unload the SELinux module at priority 300 (the SAME priority as the
#                 install: a plain `semodule -r` would leave it loaded).
#   deb "upgrade" and rpm "1": nothing. rpm runs this AFTER the new package's postinstall,
#                 so unloading the module or profile here would undo the upgrade.
# The server's database and key file are never touched by anything here.
STATE_DIR=/var/lib/clamfleet
APPARMOR_PROFILE=/etc/apparmor.d/clamfleet-agent-event

set -eu

# purge_tree removes the contents of $1 without ever following a symlink and without
# touching a mount point: a mounted directory (or a different st_dev) is left alone with
# a notice, so an operator's mount inside the spool survives a purge. Returns 1 when
# something was kept.
purge_tree() {
	# local is not POSIX but dash, bash and busybox all have it, and the recursion needs it.
	local dir kept entry
	dir=$1
	kept=0
	for entry in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
		if [ ! -e "$entry" ] && [ ! -L "$entry" ]; then continue; fi
		if [ -L "$entry" ]; then
			rm -f -- "$entry"
		elif [ -d "$entry" ]; then
			if is_mount "$entry" "$dir"; then
				echo "clamfleet-agent: not removing $entry: it is a mount point" >&2
				kept=1
				continue
			fi
			purge_tree "$entry" || kept=1
			rmdir "$entry" 2>/dev/null || kept=1
		else
			rm -f -- "$entry"
		fi
	done
	return $kept
}

# is_mount: a mount point, or a directory on another device than its parent.
is_mount() {
	if command -v mountpoint >/dev/null 2>&1 && mountpoint -q -- "$1"; then return 0; fi
	[ "$(stat -c %d -- "$1" 2>/dev/null)" != "$(stat -c %d -- "$2" 2>/dev/null)" ]
}

case "${1:-}" in
	remove)
		if command -v aa-enabled >/dev/null 2>&1 && aa-enabled >/dev/null 2>&1 && [ -e "$APPARMOR_PROFILE" ]; then
			apparmor_parser -R "$APPARMOR_PROFILE" || true
		fi
		systemctl daemon-reload || true
		;;
	0)
		if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
			if semodule -l | grep -q '^clamfleet\b'; then
				semodule -X 300 -r clamfleet
			fi
		fi
		systemctl daemon-reload || true
		;;
	purge)
		if [ -L "$STATE_DIR" ]; then
			rm -f -- "$STATE_DIR" # a symlink: the link only, never its target
		elif [ -d "$STATE_DIR" ]; then
			if is_mount "$STATE_DIR" "$(dirname "$STATE_DIR")"; then
				echo "clamfleet-agent: not removing $STATE_DIR: it is a mount point" >&2
			elif purge_tree "$STATE_DIR"; then
				rmdir "$STATE_DIR" 2>/dev/null || true
			else
				echo "clamfleet-agent: $STATE_DIR was kept because it holds a mount point or a file that could not be removed" >&2
			fi
		fi
		systemctl daemon-reload || true
		;;
esac
exit 0
