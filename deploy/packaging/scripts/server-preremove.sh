#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# clamfleet-server preremove (deb prerm / rpm %preun). Only a REAL removal (deb "remove",
# rpm "0") stops and disables the units. An upgrade does nothing here: on rpm the NEW
# package's postinstall has already restarted the server.
SD_RUN=/run/systemd/system
set -eu
case "${1:-}" in
	remove | 0) ;;
	*) exit 0 ;;
esac
if [ -d "$SD_RUN" ]; then systemctl stop clamfleet-server-backup.timer clamfleet-server-backup.service clamfleet-server.service || true; fi
systemctl disable clamfleet-server-backup.timer clamfleet-server.service || true
exit 0
