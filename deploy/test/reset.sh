#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
# reset.sh - return the ClamFleet e2e test container to its clean ClamAV state.
#
# Restores Incus snapshot "clean-clamav" of the test container on the Incus host
# (Debian 13, distro clamav + clamav-daemon + clamav-freshclam, signatures loaded),
# then waits until clamd can really scan a file.
# Idempotent: restoring the same snapshot twice gives the same state.
# Needs ssh to the Incus host with passwordless sudo for incus.
# Env: INCUS_HOST (required: ssh target of the Incus host; set it in the
#      environment or deploy/test/local.env), CT (container, default
#      clamfleet-test), SNAP (default clean-clamav), TIMEOUT (seconds, default 180).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Maintainer-specific names live in the gitignored local.env, never in the repo.
[ -f "$here/local.env" ] && . "$here/local.env"
CT="${CT:-clamfleet-test}"
SNAP="${SNAP:-clean-clamav}"
INCUS_HOST="${INCUS_HOST:?set INCUS_HOST (environment or deploy/test/local.env), see docs/testing.md}"
TIMEOUT="${TIMEOUT:-180}"

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
# Same approach as waitClamd in the e2e suite. The script goes over stdin
# because ssh re-parses arguments on the far side.
ssh "$INCUS_HOST" "sudo incus exec $CT --env TRIES=$((TIMEOUT / 2)) -- bash -s" <<'INNER'
for _ in $(seq 1 "$TRIES"); do
	clamdscan --no-summary /etc/hostname >/dev/null 2>&1 && exit 0
	sleep 2
done
echo "reset: clamd never became ready" >&2
exit 1
INNER
echo "reset: $CT ready in $(( $(date +%s) - start ))s"
