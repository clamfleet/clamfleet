#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# dco_test.sh - hack/ci/dco.sh against a temporary repository (`make check` runs it). Each way the
# check can be wrong has a case: a missing sign-off, a sign-off by someone else, a range that was
# never fetched (must fail, not pass as empty), the exempt commits (Dependabot, merges), and a
# sign-off that is only text in the middle of the message.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dco="$here/../../hack/ci/dco.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "dco_test: FAIL: $*" >&2; exit 1; }

cd "$tmp"
git init -q -b main .
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
git config user.name x
git config user.email x@example.com
git config commit.gpgsign false

# commit AUTHOR_NAME AUTHOR_EMAIL MESSAGE: an empty commit by that author.
commit() {
	GIT_AUTHOR_NAME="$1" GIT_AUTHOR_EMAIL="$2" git commit -q --allow-empty -m "$3"
}
n=0
ok=$'\n\nSigned-off-by: Ann Dev <ann@example.com>'
commit "Ann Dev" ann@example.com "root"
root="$(git rev-parse HEAD)"

# expect_ok / expect_fail NAME BASE HEAD [status]
expect_ok() { "$dco" "$2" "$3" >"$tmp/out" 2>&1 || fail "$1: refused:
$(cat "$tmp/out")"; }
expect_fail() {
	local want="${4:-1}" code=0
	"$dco" "$2" "$3" >"$tmp/out" 2>&1 || code=$?
	[ "$code" = "$want" ] || fail "$1: exit $code, wanted $want:
$(cat "$tmp/out")"
}

commit "Ann Dev" ann@example.com "feat: signed$ok"
expect_ok "a signed-off commit" "$root" HEAD

# The same author's email in another case still matches.
commit "Ann Dev" ann@example.com "feat: case"$'\n\nSigned-off-by: Ann Dev <ANN@Example.com>'
expect_ok "a sign-off in another case" "$root" HEAD

good="$(git rev-parse HEAD)"
commit "Ann Dev" ann@example.com "feat: no sign-off"
expect_fail "a commit with no sign-off" "$good" HEAD
grep -q 'no Signed-off-by' "$tmp/out" || fail "the refusal does not say why"

git reset -q --hard "$good"
commit "Ann Dev" ann@example.com "feat: someone else signed"$'\n\nSigned-off-by: Bob Other <bob@example.com>'
expect_fail "a sign-off by someone else" "$good" HEAD

git reset -q --hard "$good"
commit "Ann Dev" ann@example.com "feat: text, not a trailer"$'\n\nSigned-off-by: Ann Dev <ann@example.com>\n\nA closing paragraph, so the sign-off is not in the final trailer block'
expect_fail "a sign-off that is not in the trailer block" "$good" HEAD

# One bad commit in a range of good ones fails the range.
git reset -q --hard "$good"
commit "Ann Dev" ann@example.com "feat: ok"$'\n\nSigned-off-by: Ann Dev <ann@example.com>'
commit "Ann Dev" ann@example.com "feat: forgot"
commit "Ann Dev" ann@example.com "feat: ok again"$'\n\nSigned-off-by: Ann Dev <ann@example.com>'
expect_fail "one unsigned commit among signed ones" "$good" HEAD

# A range that is not in the repository must FAIL (exit 2), not look empty.
git reset -q --hard "$good"
zero=0000000000000000000000000000000000000000
expect_fail "an unknown base" "$zero" HEAD 2
expect_fail "an unknown head" "$good" "$zero" 2
expect_fail "no arguments" "" "" 2

# Nothing between base and head is fine.
expect_ok "an empty range" "$good" "$good"

# Exempt: Dependabot, and merge commits.
commit "dependabot[bot]" "49699333+dependabot[bot]@users.noreply.github.com" "build(deps): bump x"
expect_ok "a Dependabot commit" "$good" HEAD
dep="$(git rev-parse HEAD)"
git checkout -q -b side "$good"
commit "Ann Dev" ann@example.com "feat: on the side"$'\n\nSigned-off-by: Ann Dev <ann@example.com>'
git checkout -q main
GIT_AUTHOR_NAME="Ann Dev" GIT_AUTHOR_EMAIL=ann@example.com git merge -q --no-ff -m "Merge branch side" side
expect_ok "a merge commit with no sign-off" "$dep" HEAD

# A human pretending nothing: a commit by a non-bot with no sign-off is still refused after a bot's.
commit "Cy" cy@example.com "feat: unsigned"
expect_fail "an unsigned human commit after a bot's" "$dep" HEAD
echo "dco_test: ok"
