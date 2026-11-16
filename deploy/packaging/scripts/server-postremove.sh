#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# clamfleet-server postremove (deb postrm / rpm %postun). The database and the key file are
# NEVER deleted here, not even on purge: dpkg's literal reading of "purge" would destroy a
# year of audit and detection history (and the key that opens every stored secret) with one
# command. Purge says where they are and leaves them. The users and groups stay too, the
# usual practice for system users that may own files.
STATE_DIR=/var/lib/clamfleet-server
KEY_FILE=/etc/clamfleet/server-secret.key
set -eu
case "${1:-}" in
	remove | 0 | purge)
		systemctl daemon-reload || true
		;;
esac
case "${1:-}" in
	purge | 0)
		echo "clamfleet-server: the database and backups in $STATE_DIR and the key file $KEY_FILE were NOT removed. Delete them yourself if you are sure (the key file cannot be recreated: stored secrets are lost with it)." >&2
		;;
esac
exit 0
