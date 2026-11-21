#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# l1-guard.sh - the first step of every make target that installs and runs the checked-out commit as root
# on the maintainer's machines (the Incus host): e2e, e2e-apparmor, e2e-el9, e2e-idp, fixtures and
# record-freshclam-history. Refuse unless the commit is code a maintainer put on the canonical repository.
# Running a fork's pull request there by habit is the thing to prevent (R1 decision 6).
#
# The rule: HEAD passes without approval only when `origin` demonstrably is the canonical repository and
# a branch of it contains HEAD. That is an allowlist, because "a ref under refs/remotes/origin" proves
# nothing by itself: a clone of a fork has the fork as origin, and a refspec such as
# `+refs/pull/*/head:refs/remotes/origin/pr/*` puts a stranger's pull request there. So BOTH must hold:
#   1. `git remote get-url origin` is github.com/clamfleet/clamfleet (https or ssh, optional .git);
#   2. every `remote.origin.fetch` value is exactly `+refs/heads/*:refs/remotes/origin/*`, so that
#      everything under refs/remotes/origin/ was mapped from a branch (only maintainers can push
#      branches to the canonical repository).
# Otherwise it passes only when L1_APPROVED equals the full SHA of HEAD: approval is per commit, so a
# later push to the fork needs a new one. Only the maintainer's approval message justifies setting it: an
# agent never sets L1_APPROVED on its own, the main session sets it after the maintainer has read the diff
# and said so.
#
# Environment: L1_GUARD_CANONICAL_URL replaces the canonical URL (exact match), for the test's fixture only.
#
# This is a SPEED BUMP against a slip, not a security boundary: whoever controls the shell can set the
# variable, push a branch, or call `go test` directly. It also looks at HEAD only: uncommitted changes
# in the work tree are the person's own.
#
# Run from inside the repository. Exit status: 0 allowed, 1 refused, 2 not a git work tree.
set -euo pipefail

if ! head="$(git rev-parse --verify --quiet 'HEAD^{commit}')"; then
	echo "l1-guard: not inside a git work tree with a commit" >&2
	exit 2
fi

# Rule 1 and 2 above. `git config --get-all` prints one value per line; none at all (origin has no fetch
# line) is not canonical either.
canonical=0
url="$(git remote get-url origin 2>/dev/null || true)"
if [ -n "${L1_GUARD_CANONICAL_URL:-}" ]; then
	[ "$url" = "$L1_GUARD_CANONICAL_URL" ] && canonical=1
else
	[[ "$url" =~ ^(https://github\.com/|git@github\.com:|ssh://git@github\.com/)clamfleet/clamfleet(\.git)?$ ]] && canonical=1
fi
if [ "$canonical" = 1 ]; then
	fetch="$(git config --get-all remote.origin.fetch || true)"
	[ "$fetch" = '+refs/heads/*:refs/remotes/origin/*' ] || canonical=0
fi

if [ "$canonical" = 1 ]; then
	on_origin="$(git for-each-ref --contains "$head" --format='%(refname)' refs/remotes/origin | grep -v '^refs/remotes/origin/pull/' || true)"
	if [ -n "$on_origin" ]; then
		exit 0
	fi
fi

if [ "${L1_APPROVED:-}" = "$head" ]; then
	echo "l1-guard: $head is on no origin branch; running because L1_APPROVED names it" >&2
	exit 0
fi

echo "l1-guard: refusing: $head is on no branch of origin, so it may be a fork's code (or origin is not the canonical repository), and an L1 run executes it as root in the maintainer's VMs." >&2
echo "l1-guard: read the diff; if the maintainer approves this exact commit, rerun with L1_APPROVED=$head" >&2
exit 1
