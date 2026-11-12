#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# capture-remote.sh - the part of capture-fixtures.sh that runs INSIDE the
# clamfleet-test container (sent over stdin to "bash -s"; SKIP_FRESHCLAM is
# prepended by the caller). Writes everything under /tmp/cap. See
# capture-fixtures.sh for what is recorded and why freshclam is handled with care.
set -euo pipefail
cap=/tmp/cap
mkdir -p $cap/clamd $cap/cvd/initial $cap/freshclam $cap/services $cap/debian13

# --- clean-state items -------------------------------------------------------
cp /etc/os-release $cap/debian13/os-release
cp /etc/clamav/clamd.conf $cap/debian13/clamd.conf
cp /var/log/clamav/freshclam.log $cap/freshclam/initial-download.log   # from the snapshot: first full download
# Run as the agent user (not root) so socket permissions are part of the recording.
rm -rf /tmp/rec
runuser -u clamfleet -- clamd-record /run/clamav/clamd.ctl /tmp/rec
cp /tmp/rec/* $cap/clamd/
rm -rf /tmp/rec

snap_cvd() { # $1 = destination directory
  mkdir -p "$1"
  for f in /var/lib/clamav/{daily,main,bytecode}.c[vl]d; do
    [ -e "$f" ] || continue
    head -c 512 "$f" > "$1/$(basename "$f").hdr"
    sigtool --info="$f" > "$1/$(basename "$f").info"
  done
}
snap_cvd $cap/cvd/initial

show() { systemctl show --property=LoadState,ActiveState "$1" > "$cap/services/$2.show" || true; }
show clamav-daemon clamd-active
show clamav-freshclam freshclam-inactive
show clamav-clamonacc clamonacc-inactive
show clamav-no-such-unit not-found

# --- clamd stopped: the unit state, never a socket connection ------------------
systemctl stop clamav-daemon
show clamav-daemon clamd-inactive
systemctl start clamav-daemon
clamdscan --ping 90:2 >/dev/null

# --- forced failure: a unit whose command exits non-zero ------------------------
mkdir -p /run/systemd/system/clamav-freshclam.service.d
printf '[Service]\nExecStart=\nExecStart=/bin/false\n' > /run/systemd/system/clamav-freshclam.service.d/fail.conf
systemctl daemon-reload
systemctl start clamav-freshclam || true
sleep 1
show clamav-freshclam freshclam-failed
systemctl reset-failed clamav-freshclam || true
rm -f /run/systemd/system/clamav-freshclam.service.d/fail.conf
systemctl daemon-reload

if [ "$SKIP_FRESHCLAM" != 1 ]; then
  # --- freshclam daemon, real conf: contacts the CDN once --------------------
  since="$(date '+%Y-%m-%d %H:%M:%S')"
  systemctl start clamav-freshclam
  show clamav-freshclam freshclam-active
  # The run is over when a second dashed footer line has appeared in the log.
  for _ in $(seq 1 120); do
    [ "$(grep -c 'update process started' /var/log/clamav/freshclam.log)" -ge 2 ] && \
      tail -n 1 /var/log/clamav/freshclam.log | grep -q -- '-----' && break
    sleep 1
  done
  sleep 1
  systemctl stop clamav-freshclam
  cp /var/log/clamav/freshclam.log $cap/freshclam/after-rerun.log
  journalctl -u clamav-freshclam --since "$since" -o cat --no-pager -q > $cap/freshclam/journal-rerun.txt
  snap_cvd $cap/cvd/after-update

  # --- LogTime no, one more CDN contact (expected: up-to-date) --------------
  grep -v -E '^(NotifyClamd|UpdateLogFile|LogTime)' /etc/clamav/freshclam.conf > /tmp/fc-notime.conf
  printf 'UpdateLogFile /tmp/cap/freshclam/logtime-no.log\nLogTime no\n' >> /tmp/fc-notime.conf
  : > $cap/freshclam/logtime-no.log; chmod 666 $cap/freshclam/logtime-no.log
  runuser -u clamav -- freshclam --config-file=/tmp/fc-notime.conf >/dev/null 2>&1 || true

  # --- failure: unreachable loopback mirror, no CDN contact ----------------
  grep -v -E '^(NotifyClamd|UpdateLogFile|DatabaseMirror|DNSDatabaseInfo|MaxAttempts|ConnectTimeout)' /etc/clamav/freshclam.conf > /tmp/fc-fail.conf
  printf 'UpdateLogFile /tmp/cap/freshclam/failure.log\nPrivateMirror http://127.0.0.1:9\nMaxAttempts 1\nConnectTimeout 5\n' >> /tmp/fc-fail.conf
  : > $cap/freshclam/failure.log; chmod 666 $cap/freshclam/failure.log
  runuser -u clamav -- freshclam --config-file=/tmp/fc-fail.conf >/dev/null 2>&1 || true

  # The same failure through the real unit, to record what the journal holds.
  since="$(date '+%Y-%m-%d %H:%M:%S')"
  mkdir -p /run/systemd/system/clamav-freshclam.service.d
  printf '[Service]\nExecStart=\nExecStart=/usr/bin/freshclam -d --foreground=true --config-file=/tmp/fc-fail.conf\n' > /run/systemd/system/clamav-freshclam.service.d/fail.conf
  systemctl daemon-reload
  : > $cap/freshclam/failure.log
  systemctl start clamav-freshclam
  for _ in $(seq 1 30); do journalctl -u clamav-freshclam --since "$since" -o cat --no-pager -q | grep -q 'ERROR' && break; sleep 1; done
  sleep 1
  systemctl stop clamav-freshclam
  journalctl -u clamav-freshclam --since "$since" -o cat --no-pager -q > $cap/freshclam/journal-failure.txt
  rm -f /run/systemd/system/clamav-freshclam.service.d/fail.conf
  systemctl daemon-reload
fi
