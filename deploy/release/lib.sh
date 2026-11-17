#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# lib.sh - the two rules release.sh and verify-tag.sh share, so that the build and the tag check cannot
# disagree about what a release version or a release's notes are. Sourced, never run. No dependency beyond
# bash, awk and grep.

# The version policy (docs/releasing.md): X.Y.Z or X.Y.Z-rc.N, numbers without leading zeros. Release
# candidates only: no other pre-release label and no build metadata, because a deb and an rpm each sort
# a suffix differently (`~` in a deb, a release field in an rpm) and two labels would double the cases
# to get right. Not a "v" prefix: that belongs to the tag, not the version.
RELEASE_VERSION_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?$'

# release_version_ok VERSION: exit 0 when VERSION follows the policy.
release_version_ok() {
	[[ "$1" =~ $RELEASE_VERSION_RE ]]
}

# changelog_section VERSION FILE: prints the body of the `## [VERSION] - YYYY-MM-DD` section of FILE (up to
# the next `## ` heading), with leading and trailing blank lines removed. Exit 1, printing nothing, when
# there is no such section or its body is empty: a release must say what it contains. The version is
# matched literally (the dots are not wildcards), and an `Unreleased` heading never matches.
changelog_section() {
	local version="$1" file="$2" body
	body="$(awk -v v="$version" '
		BEGIN { want = "## [" v "] - " }
		/^## / { if (insec) exit; insec = (index($0, want) == 1 && substr($0, length(want) + 1) ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/); next }
		insec { print }
	' "$file")"
	# Strip blank edges, then insist on something left.
	body="$(printf '%s\n' "$body" | awk 'NF { started = 1 } started { lines[++n] = $0 } END { while (n > 0 && lines[n] ~ /^[ \t]*$/) n--; for (i = 1; i <= n; i++) print lines[i] }')"
	[ -n "$body" ] || return 1
	printf '%s\n' "$body"
}
