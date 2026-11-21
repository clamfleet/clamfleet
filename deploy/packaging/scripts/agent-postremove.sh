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
MOUNTINFO=/proc/self/mountinfo

set -eu

# mounts_under prints every mount point at or below $1, read from the kernel's mount table
# (field 5 of mountinfo). The paths keep mountinfo's octal escapes, which is fine for the
# prefix match and for printing.
mounts_under() {
	awk -v d="$1" '$5 == d || index($5, d "/") == 1 { print $5 }' "$MOUNTINFO"
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
		# The state directory is writable by the clamfleet user and, below spool/events, by clamd's
		# group, while this runs as root. So nothing here may check a path and then act on it in a
		# second step: a glob loop that tests "is this a directory" and then expands "$entry"/* can
		# be raced into deleting whatever a swapped-in symlink points at (/etc). rm does it in one
		# walk with openat and no symlink following, and --one-file-system never leaves the
		# filesystem of the directory it was given.
		if [ -L "$STATE_DIR" ]; then
			rm -f -- "$STATE_DIR" # a symlink: the link only, never its target
		elif [ -d "$STATE_DIR" ]; then
			mounts="$(mounts_under "$STATE_DIR")"
			if [ -n "$mounts" ]; then
				# A mount inside (or the directory itself): remove nothing, say what and where.
				echo "clamfleet-agent: not removing $STATE_DIR: it holds or is a mount point:" >&2
				printf '%s\n' "$mounts" | sed 's/^/  /' >&2
			else
				rm -rf --one-file-system -- "$STATE_DIR"
			fi
		fi
		systemctl daemon-reload || true
		;;
esac
exit 0
