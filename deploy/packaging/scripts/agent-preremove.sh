#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# clamfleet-agent preremove (deb prerm / rpm %preun). Only a REAL removal stops and
# disables the units: deb "remove", rpm "0". An upgrade (deb "upgrade", rpm "1") does
# nothing here; on rpm the NEW package's postinstall has already run with "2" and
# restarted the service, so stopping it now would leave the upgraded agent down.
SD_RUN=/run/systemd/system
set -eu
case "${1:-}" in
	remove | 0) ;;
	*) exit 0 ;;
esac
if [ -d "$SD_RUN" ]; then systemctl stop clamfleet-scan.timer clamfleet-scan.service clamfleet-agent.service || true; fi
systemctl disable clamfleet-scan.timer clamfleet-agent.service || true
exit 0
