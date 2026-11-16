#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# capture-fixtures.sh - record the agent's test fixtures from the real
# clamfleet-test container (Debian 13, distro ClamAV). `make fixtures` runs it.
#
# What it records (into internal/agent/testdata/, existing recordings are
# replaced):
#   clamd/        raw request and reply bytes of zPING, zVERSION, zSTATS, zFOO
#   cvd/<state>/  the first 512 bytes of every .cvd/.cld, plus `sigtool --info`
#                 of the full file (the independent oracle for the parser tests)
#   freshclam/    freshclam logs (LogTime yes and no; success, up-to-date,
#                 failure) and the matching systemd journal output
#   services/     `systemctl show` for active, inactive, failed, not-found units
#   clamdscan/    stdout, stderr, exit status and paths of `clamdscan --multiscan` (clean,
#                 infected, unreadable file, several paths, clamd down)
#   debian13/     /etc/os-release and /etc/clamav/clamd.conf
#
# Freshclam and the CDN: the real signature CDN rate-limits (HTTP 429/403) and
# freshclam then enforces a cool-down of hours. This script therefore contacts
# the CDN at most twice per run (one daemon start, one LogTime-no run) and
# provokes failures only against an unreachable loopback mirror. Do not run it
# in a loop. SKIP_FRESHCLAM=1 skips everything that touches the network.
#
# Scrubbing: any private address or lab host name is replaced by
# mirror.example, and the script aborts if one survives (spec 15a: no
# organisation-specific names in the repository).
#
# Ends with reset.sh, so the container is back in its clean state.
# Env: CFT_EXEC (required: the command prefix that runs a command inside the
#      container; set it in the environment or deploy/test/local.env),
#      SKIP_FRESHCLAM. Private names to scrub: deploy/test/scrub-private.txt.
# Remote scripts go over stdin ("bash -s") because ssh re-parses arguments.
set -euo pipefail

SKIP_FRESHCLAM="${SKIP_FRESHCLAM:-0}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Maintainer-specific names live in the gitignored local.env, never in the repo.
[ -f "$here/local.env" ] && . "$here/local.env"
CFT_EXEC="${CFT_EXEC:?set CFT_EXEC (environment or deploy/test/local.env), see docs/testing.md}"
root="$(cd "$here/../.." && pwd)"
out="$root/internal/agent/testdata"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Start from the known clean state, then create the agent user.
"$here/reset.sh"
"$here/prepare-agent.sh"

# Cross-compile the recorder (static, no CGO) and push it.
(cd "$root" && CGO_ENABLED=0 go build -o "$work/clamd-record" ./hack/clamd-record)
$CFT_EXEC rm -rf /tmp/cap </dev/null
tar -cf - -C "$work" clamd-record | $CFT_EXEC tar -xf - -C /usr/local/bin --no-same-owner

{ echo "SKIP_FRESHCLAM=$SKIP_FRESHCLAM"; cat "$here/capture-remote.sh"; } | $CFT_EXEC bash -s

# Pull the recordings back.
mkdir -p "$work/pull"
$CFT_EXEC tar -cf - -C /tmp/cap . </dev/null | tar -xf - -C "$work/pull"
$CFT_EXEC rm -rf /tmp/cap </dev/null

# Scrub: replace private addresses and lab host names, then refuse to continue
# if anything of the sort is left (see the header).
# The generic patterns (RFC 1918 addresses, .incus/.lan/.internal/.local names)
# live here. The maintainer's own host names come from the gitignored
# scrub-private.txt (one per line), so no private name is ever in the repo.
scrub_re='(10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|[A-Za-z0-9.-]+\.(incus|lan|internal|local)\b'
if [ -f "$here/scrub-private.txt" ]; then
	while IFS= read -r name; do
		case "$name" in '' | '#'*) continue ;; esac
		scrub_re="$scrub_re|$name"
	done <"$here/scrub-private.txt"
else
	echo "capture-fixtures: no deploy/test/scrub-private.txt, scrubbing generic patterns only" >&2
fi
scrub_re="$scrub_re)"
# db.local.clamav.net is the public Cisco name and must stay verbatim: shield it
# from the ".local" rule, then restore it.
find "$work/pull" -type f ! -name '*.hdr' ! -name '*.resp' ! -name '*.req' -print0 |
	xargs -0 sed -i -E -e 's/db\.local\.clamav\.net/DBLOCALCLAMAV/g' \
		-e "s/$scrub_re/mirror.example/g" -e 's/DBLOCALCLAMAV/db.local.clamav.net/g'
if grep -rIh -E "$scrub_re" "$work/pull" | grep -v 'db\.local\.clamav\.net' | grep -q .; then
	echo "capture-fixtures: private names survived scrubbing" >&2
	exit 1
fi

rm -rf "$out/clamd" "$out/cvd" "$out/freshclam" "$out/services" "$out/debian13" "$out/clamdscan"
mkdir -p "$out"
cp -r "$work/pull/." "$out/"
# Drop the second CVD snapshot when the update changed nothing.
if [ -d "$out/cvd/after-update" ] && diff -rq "$out/cvd/initial" "$out/cvd/after-update" >/dev/null; then
	rm -rf "$out/cvd/after-update"
fi

"$here/reset.sh"
echo "capture-fixtures: done; review the diff before committing"
