#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# signatures_test.sh - every CI container image takes its signature databases from the same
# pinned ClamAV image (deploy/test/ci/Dockerfile, deb/Dockerfile, rpm/Dockerfile).
#
# Why: the legs of the container matrix must scan with the same frozen databases, or a detection
# that passes on one release and fails on another could be a different database rather than the
# release. Dependabot opens one pull request per Dockerfile directory, so a bump of one digest is
# the expected way for them to drift; this test fails until the others follow.
#
# It proves itself: a copy of the three files with one digest changed must fail, and one with
# the pin removed must fail.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
files=(Dockerfile deb/Dockerfile rpm/Dockerfile)

# pins DIR: prints the image reference of the `AS signatures` stage of each Dockerfile, one per
# line, or "MISSING <file>" for a file that has none or has more than one.
pins() {
	local dir="$1" f n
	for f in "${files[@]}"; do
		n="$(grep -cE '^FROM [^ ]+ AS signatures$' "$dir/$f" || true)"
		if [ "$n" -ne 1 ]; then
			echo "MISSING $f"
			continue
		fi
		sed -n 's/^FROM \([^ ]*\) AS signatures$/\1/p' "$dir/$f"
	done
}

# check DIR: returns 0 when every Dockerfile has the pin, by digest, and all pins are equal.
check() {
	local got
	got="$(pins "$1")"
	if grep -q '^MISSING' <<<"$got"; then
		echo "$got" | grep '^MISSING' >&2
		return 1
	fi
	grep -qvE '^clamav/clamav-debian:[^@ ]+@sha256:[0-9a-f]{64}$' <<<"$got" && { echo "a signatures pin is not tag@digest: $got" >&2; return 1; }
	[ "$(sort -u <<<"$got" | wc -l)" -eq 1 ] || { echo "the signatures pins differ:" >&2; echo "$got" >&2; return 1; }
	return 0
}

check "$here" || { echo "signatures_test: FAIL on the real files" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/deb" "$tmp/rpm"
for f in "${files[@]}"; do cp "$here/$f" "$tmp/$f"; done
check "$tmp" || { echo "signatures_test: FAIL on the copy" >&2; exit 1; }

# One digest differs: must be refused.
sed -i '0,/^FROM clamav\/clamav-debian:\([^@]*\)@sha256:[0-9a-f]/s//FROM clamav\/clamav-debian:\1@sha256:0/' "$tmp/rpm/Dockerfile"
if check "$tmp" 2>/dev/null; then
	echo "signatures_test: FAIL: a differing digest was accepted" >&2
	exit 1
fi

# No signatures stage in one file: must be refused.
cp "$here/rpm/Dockerfile" "$tmp/rpm/Dockerfile"
sed -i 's/ AS signatures$/ AS other/' "$tmp/rpm/Dockerfile"
if check "$tmp" 2>/dev/null; then
	echo "signatures_test: FAIL: a missing signatures stage was accepted" >&2
	exit 1
fi

echo "signatures_test: ok"
