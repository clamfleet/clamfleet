#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# l1-guard.sh - the first step of the level-1 make targets (e2e-apparmor, e2e-el9): refuse to run the
# checked-out commit in the VMs on the maintainer's machines unless it is code a maintainer put on this
# repository. An L1 run executes the commit as root in VMs on those machines, so running a fork's
# pull request by habit is the thing to prevent (R1 decision 6).
#
# The rule: HEAD must be contained in a branch of the remote `origin` (only maintainers can push branches
# to the canonical repository; a fetched pull/N/head ref of a fork is not one). Otherwise it passes only
# when L1_APPROVED equals the full SHA of HEAD: approval is per commit, so a later push to the fork
# needs a new one. Only the maintainer's approval message justifies setting it: an agent never sets
# L1_APPROVED on its own, the main session sets it after the maintainer has read the diff and said so.
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

# refs/remotes/origin/pull/* is excluded: someone who maps the pull refs into the remote's namespace
# (fetch = +refs/pull/*/head:refs/remotes/origin/pull/*) would otherwise make every fork's commit "pushed".
on_origin="$(git for-each-ref --contains "$head" --format='%(refname)' refs/remotes/origin | grep -v '^refs/remotes/origin/pull/' || true)"
if [ -n "$on_origin" ]; then
	exit 0
fi

if [ "${L1_APPROVED:-}" = "$head" ]; then
	echo "l1-guard: $head is on no origin branch; running because L1_APPROVED names it" >&2
	exit 0
fi

echo "l1-guard: refusing: $head is on no branch of origin, so it may be a fork's code, and an L1 run executes it as root in the maintainer's VMs." >&2
echo "l1-guard: read the diff; if the maintainer approves this exact commit, rerun with L1_APPROVED=$head" >&2
exit 1
