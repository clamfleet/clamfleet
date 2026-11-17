#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# Runs once at boot in the CI image (clamfleet-ci-freshclam-history.service): writes the recorded
# journal lines of a real freshclam run (testdata/freshclam-journal.txt) into the journal as
# entries of the clamav-freshclam unit, so `journalctl -u clamav-freshclam` shows them as it does
# on the Incus snapshot. The unit never runs: root may tag an entry with OBJECT_SYSTEMD_UNIT,
# which `journalctl -u` matches. One logger call per line keeps the order.
set -eu
while IFS= read -r line; do
	printf 'MESSAGE=%s\nOBJECT_SYSTEMD_UNIT=clamav-freshclam.service\nSYSLOG_IDENTIFIER=freshclam\n' "$line" | logger --journald
done </usr/share/clamfleet-ci/freshclam-journal.txt
