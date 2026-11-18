#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# l1guard_test.sh - deploy/test/l1-guard.sh against temporary repositories standing in for the local
# clone and its `origin` (`make check` runs it): a commit on an origin branch passes; a detached commit
# on no origin branch is refused; it passes only with L1_APPROVED equal to the FULL SHA of that commit
# (not a prefix, not another commit's SHA); a commit reachable only through a pull ref is still refused.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
guard="$here/l1-guard.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "l1guard_test: FAIL: $*" >&2; exit 1; }
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

git init -q -b main "$tmp/origin"
git -C "$tmp/origin" -c user.name=x -c user.email=x@example.com -c commit.gpgsign=false commit -q --allow-empty -m pushed
git clone -q "$tmp/origin" "$tmp/work"
cd "$tmp/work"
git config user.name x
git config user.email x@example.com
git config commit.gpgsign false

# run [VAR=VALUE]: the guard's exit status, its output in $tmp/out.
run() {
	local code=0
	env "$@" "$guard" >"$tmp/out" 2>&1 || code=$?
	echo "$code"
}

pushed="$(git rev-parse HEAD)"
[ "$(run L1_APPROVED=)" = 0 ] || fail "a commit on origin/main was refused: $(cat "$tmp/out")"

# A local commit that was never pushed: on no origin branch.
git commit -q --allow-empty -m local
local_sha="$(git rev-parse HEAD)"
[ "$(run L1_APPROVED=)" = 1 ] || fail "an unpushed commit was allowed"
grep -q 'refusing' "$tmp/out" || fail "the refusal does not say why"
[ "$(run L1_APPROVED=)" = 1 ] || fail "again"

# A detached commit, as `git checkout <sha>` of a fetched fork leaves it.
git checkout -q --detach
[ "$(run L1_APPROVED=)" = 1 ] || fail "a detached unpushed commit was allowed"

# Approval is the full SHA of this commit and nothing else.
[ "$(run "L1_APPROVED=$local_sha")" = 0 ] || fail "the exact SHA was refused: $(cat "$tmp/out")"
[ "$(run "L1_APPROVED=${local_sha:0:12}")" = 1 ] || fail "a SHA prefix was accepted"
[ "$(run "L1_APPROVED=$pushed")" = 1 ] || fail "another commit's SHA was accepted"
[ "$(run L1_APPROVED=1)" = 1 ] || fail "L1_APPROVED=1 was accepted"

# A ref in origin's pull namespace does not make a commit "pushed by a maintainer".
git update-ref refs/remotes/origin/pull/7 "$local_sha"
[ "$(run L1_APPROVED=)" = 1 ] || fail "a commit reachable only through a pull ref was allowed"

# A branch of some other remote (a fork added to review it) is not the canonical repository.
git update-ref refs/remotes/fork/main "$local_sha"
[ "$(run L1_APPROVED=)" = 1 ] || fail "a commit on another remote's branch was allowed"

# Once the commit is on a real origin branch it passes without approval.
git update-ref refs/remotes/origin/feature/x "$local_sha"
[ "$(run L1_APPROVED=)" = 0 ] || fail "a commit on an origin branch was refused: $(cat "$tmp/out")"

# Outside a work tree: exit 2.
cd "$tmp"
mkdir plain
cd plain
code=0
GIT_CEILING_DIRECTORIES="$tmp" "$guard" >"$tmp/out" 2>&1 || code=$?
[ "$code" = 2 ] || fail "outside a work tree: exit $code, wanted 2"

echo "l1guard_test: ok"
