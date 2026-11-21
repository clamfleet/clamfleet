#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# l1-required.sh BASE HEAD - does the change BASE...HEAD need a level-1 (L1) run, that is the real
# packages on the maintainer's VMs with the mandatory access control enforcing? Prints one line,
# `L1 required: <paths>` (the paths that matched) or `L1 not required`. The globs are in
# deploy/test/l1-paths.txt (format in its header); the `l1-paths` CI job appends this line to the
# job summary and the maintainer decides at merge (R1 decision 7). The verdict is advisory: the
# script exits 0 for both answers.
#
# The script and the globs come from the checkout, which in a pull request is the PR's own code, so a PR
# can edit the rule that judges it. When the diff touches this script, the globs file or a workflow, a
# second line says so: "the rule itself changed: read it before trusting this verdict".
#
# The paths are those of `git diff --name-only BASE...HEAD`, i.e. against the merge base, as a pull
# request is reviewed. `--no-renames` lists both sides of a rename: moving a file OUT of a watched
# directory changes what ships just as moving one in, and rename detection would show only the new name.
#
# A BASE or HEAD that is not in the repository FAILS (exit 2), like hack/ci/dco.sh: in CI a shallow
# checkout would otherwise give an empty diff and a confident "L1 not required". So does a missing
# or unreadable paths file. Exit status: 0 verdict printed, 2 bad use, unfetched range or no globs.
#
# Environment: L1_PATHS_FILE overrides the globs file (for tests only).
set -euo pipefail

if [ "$#" -ne 2 ]; then
	echo "usage: l1-required.sh BASE_SHA HEAD_SHA" >&2
	exit 2
fi
base="$1"
head="$2"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
globs="${L1_PATHS_FILE:-$here/../../deploy/test/l1-paths.txt}"

for sha in "$base" "$head"; do
	if ! git cat-file -e "${sha}^{commit}" 2>/dev/null; then
		echo "l1-required: $sha is not a commit in this repository (shallow checkout? the workflow needs fetch-depth: 0)" >&2
		exit 2
	fi
done
if [ ! -r "$globs" ]; then
	echo "l1-required: cannot read the globs file $globs" >&2
	exit 2
fi

patterns=()
while IFS= read -r line || [ -n "$line" ]; do
	line="${line%"${line##*[![:space:]]}"}"
	case "$line" in '' | '#'*) continue ;; esac
	patterns+=("$line")
done <"$globs"
if [ "${#patterns[@]}" -eq 0 ]; then
	# An empty list would answer "not required" for everything.
	echo "l1-required: $globs holds no patterns" >&2
	exit 2
fi

# The diff runs on its own line, not inside a process substitution, so a git failure stops the script
# (set -e does not see a failure inside <(...)).
names="$(git diff --name-only -z --no-renames "$base...$head" | tr '\0' '\n')"

matched=()
while IFS= read -r path || [ -n "$path" ]; do
	[ -n "$path" ] || continue
	hit=0
	for pat in "${patterns[@]}"; do
		if [ "${pat:0:1}" = "!" ]; then
			# shellcheck disable=SC2053 # the unquoted right side is the glob, on purpose
			[[ "$path" == ${pat:1} ]] && hit=0
		else
			# shellcheck disable=SC2053
			[[ "$path" == $pat ]] && hit=1
		fi
	done
	if [ "$hit" = 1 ]; then matched+=("$path"); fi
done <<<"$names"

if [ "${#matched[@]}" -gt 0 ]; then
	echo "L1 required: ${matched[*]}"
else
	echo "L1 not required"
fi

# Self-modification: independent of the verdict (these paths need not match any glob).
while IFS= read -r path || [ -n "$path" ]; do
	case "$path" in
	hack/ci/l1-required.sh | deploy/test/l1-paths.txt | .github/workflows/*)
		echo "the rule itself changed: read it before trusting this verdict"
		break
		;;
	esac
done <<<"$names"
