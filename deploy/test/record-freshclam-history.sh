#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# record-freshclam-history.sh - re-record deploy/test/ci/testdata from the Incus test container
# (`make record-freshclam-history`). Never hand-edit the recorded files.
#
# Why: the e2e suite takes the snapshot's one real freshclam run as its premise (a log file and
# a journal entry of the clamav-freshclam unit). The CI image never runs freshclam, so it is built
# with this recording of a real run instead: freshclam.log is installed as a file and the journal
# lines are replayed at boot (deploy/test/ci/replay-freshclam-history.sh).
#
# It restores the snapshot (reset.sh), reads the two sources, scrubs private names with the same
# patterns as capture-fixtures.sh (plus deploy/test/scrub-private.txt), refuses to continue if
# any survive, and resets the container again.
# Env: CFT_EXEC and INCUS_HOST, as for reset.sh (environment or deploy/test/local.env).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$here/local.env" ] && . "$here/local.env"
CFT_EXEC="${CFT_EXEC:?set CFT_EXEC (environment or deploy/test/local.env), see docs/testing.md}"
out="$here/ci/testdata"

"$here/reset.sh"
mkdir -p "$out"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
$CFT_EXEC cat /var/log/clamav/freshclam.log </dev/null >"$tmp/freshclam.log"
# -o cat: the message text only, which is all the agent reads. One line per journal entry.
$CFT_EXEC journalctl -u clamav-freshclam -o cat --no-pager -q </dev/null >"$tmp/freshclam-journal.txt"
[ -s "$tmp/freshclam.log" ] && [ -s "$tmp/freshclam-journal.txt" ] || { echo "record-freshclam-history: the container has no freshclam history" >&2; exit 1; }
grep -q 'update process started' "$tmp/freshclam.log" || { echo "record-freshclam-history: no run in the log" >&2; exit 1; }

scrub_re='(10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|[A-Za-z0-9.-]+\.(incus|lan|internal|local)\b'
if [ -f "$here/scrub-private.txt" ]; then
	while IFS= read -r name; do
		case "$name" in '' | '#'*) continue ;; esac
		scrub_re="$scrub_re|$name"
	done <"$here/scrub-private.txt"
fi
scrub_re="$scrub_re)"
# db.local.clamav.net is the public Cisco name: shield it from the ".local" rule.
sed -i -E -e 's/db\.local\.clamav\.net/DBLOCALCLAMAV/g' -e "s/$scrub_re/mirror.example/g" -e 's/DBLOCALCLAMAV/db.local.clamav.net/g' "$tmp/freshclam.log" "$tmp/freshclam-journal.txt"
if grep -h -E "$scrub_re" "$tmp"/freshclam* | grep -v 'db\.local\.clamav\.net' | grep -q .; then
	echo "record-freshclam-history: private names survived scrubbing" >&2
	exit 1
fi
cp "$tmp/freshclam.log" "$tmp/freshclam-journal.txt" "$out/"
"$here/reset.sh"
echo "record-freshclam-history: done; review the diff before committing"
