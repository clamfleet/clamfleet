#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
# reinstall.sh - purge and reinstall ClamAV in the ClamFleet e2e test container.
#
# Exercises a fresh package install (what a real server does) without hitting
# Cisco's signature CDN, which rate-limits heavy downloaders: signatures come
# from /var/cache/clamfleet-sigs inside the container instead of freshclam.
# Steps: apt purge clamav packages, reinstall them with service start blocked
# by policy-rc.d, copy cached sigs into /var/lib/clamav, start clamd, wait for PING.
# clamav-freshclam is left enabled but STOPPED so it does not download; set
# START_FRESHCLAM=1 to start it too (it will then contact the CDN).
# Idempotent: works whether or not the packages are currently installed.
# Needs ssh to the Incus host with passwordless sudo for incus.
# Env: CT (default clamfleet-test), INCUS_HOST (required, ssh target of the Incus
#      host; set it in the environment or deploy/test/local.env),
#      START_FRESHCLAM (0/1, default 0), TIMEOUT (seconds, default 180).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Maintainer-specific names live in the gitignored local.env, never in the repo.
[ -f "$here/local.env" ] && . "$here/local.env"
CT="${CT:-clamfleet-test}"
INCUS_HOST="${INCUS_HOST:?set INCUS_HOST (environment or deploy/test/local.env), see docs/testing.md}"
START_FRESHCLAM="${START_FRESHCLAM:-0}"
TIMEOUT="${TIMEOUT:-180}"

start=$(date +%s)
ssh "$INCUS_HOST" "sudo incus exec $CT --env START_FRESHCLAM=$START_FRESHCLAM --env TIMEOUT=$TIMEOUT -- bash -s" <<'INNER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
PKGS="clamav clamav-daemon clamav-freshclam clamav-base clamdscan"
CACHE=/var/cache/clamfleet-sigs

ls "$CACHE"/*.c[vl]d >/dev/null   # fail early if the cache is missing

apt-get purge -y -q $PKGS >/dev/null
apt-get autoremove -y -q >/dev/null

# Block service starts during install so freshclam cannot begin a download
# before the cached signatures are in place. Always removed on exit.
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
trap 'rm -f /usr/sbin/policy-rc.d' EXIT
apt-get install -y -q clamav clamav-daemon clamav-freshclam clamdscan >/dev/null
rm -f /usr/sbin/policy-rc.d

install -d -o clamav -g clamav /var/lib/clamav
cp -p "$CACHE"/*.c[vl]d /var/lib/clamav/
chown clamav:clamav /var/lib/clamav/*.c[vl]d

systemctl stop clamav-freshclam 2>/dev/null || true
systemctl restart clamav-daemon
[ "$START_FRESHCLAM" = 1 ] && systemctl start clamav-freshclam
clamdscan --ping $((TIMEOUT / 2)):2
INNER
echo "reinstall: $CT ready in $(( $(date +%s) - start ))s"
