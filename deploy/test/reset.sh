#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
# reset.sh - return the ClamFleet e2e test container to its clean ClamAV state.
#
# Restores Incus snapshot "clean-clamav" of the test container (or, with CT and SNAP
# set, another instance such as the AppArmor VM) on the Incus host
# (Debian 13, distro clamav + clamav-daemon + clamav-freshclam, signatures loaded),
# then waits until clamd can really scan a file.
# Idempotent: restoring the same snapshot twice gives the same state.
# Needs ssh to the Incus host with passwordless sudo for incus.
# Env: INCUS_HOST (required: ssh target of the Incus host; set it in the
#      environment or deploy/test/local.env), CT (container, default
#      clamfleet-test), SNAP (default clean-clamav), TIMEOUT (seconds, default 180),
#      READY_FILE (the file the readiness scan reads, default /etc/hostname).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Maintainer-specific names live in the gitignored local.env, never in the repo.
[ -f "$here/local.env" ] && . "$here/local.env"
CT="${CT:-clamfleet-test}"
SNAP="${SNAP:-clean-clamav}"
INCUS_HOST="${INCUS_HOST:?set INCUS_HOST (environment or deploy/test/local.env), see docs/testing.md}"
TIMEOUT="${TIMEOUT:-180}"
# The file the readiness scan reads. /etc/hostname is fine for the container; under AppArmor
# (the VM) clamd's profile does not allow it and the scan answers "Access denied", so the
# AppArmor suite sets READY_FILE to a path the profile allows (/var/lib/clamav/**).
READY_FILE="${READY_FILE:-/etc/hostname}"

start=$(date +%s)
# </dev/null: incus over ssh misbehaves when it inherits stdin.
# A failed restore must fail the script. The braces matter: the old
# "restore && start || true" swallowed the restore status, and the suite then
# ran against whatever state the container happened to be in. Only the start
# (which fails harmlessly when the container is already running) may fail.
ssh "$INCUS_HOST" "sudo incus snapshot restore $CT $SNAP </dev/null && { sudo incus start $CT </dev/null 2>/dev/null || true; }"

# Readiness is a successful scan, not "clamdscan --ping": PONG arrives about 5 s
# before clamd has finished loading signatures (observed on Debian 13), and a
# report taken in that window says up=false. A scan needs the loaded engine.
# Same approach as waitClamd in the e2e suite.
#
# One ssh call per attempt, retried until the deadline: a restored VM (the
# AppArmor suite uses this script with CT=<vm>) reboots, and `incus exec` fails
# until its guest agent is up, which must count as "not ready yet", not as a failure.
deadline=$(( start + TIMEOUT ))
until ssh "$INCUS_HOST" "sudo incus exec $CT -- clamdscan --no-summary $READY_FILE </dev/null >/dev/null 2>&1"; do
	if [ "$(date +%s)" -ge "$deadline" ]; then
		echo "reset: clamd never became ready" >&2
		exit 1
	fi
	sleep 2
done
echo "reset: $CT ready in $(( $(date +%s) - start ))s"
