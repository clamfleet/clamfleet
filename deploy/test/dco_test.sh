#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# dco_test.sh - hack/ci/dco.sh against a temporary repository (`make check` runs it). Each way the
# check can be wrong has a case: a missing sign-off, a sign-off by someone else, a range that was
# never fetched (must fail, not pass as empty), the exempt commits (Dependabot, merges), and a
# sign-off that is only text in the middle of the message, and the cut-off (R1 decision 12): an unsigned
# commit at or before the pinned one passes, one after it fails, a pin missing from the repository exits 2.
# The real script pins a SHA of this project's history, which a temporary repository does not have, so the
# cases run a copy with the constant replaced (an environment override would be a second way to switch the
# exemption off or move it in CI, which a pull request must not have); the real pin is checked for its shape.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
real="$here/../../hack/ci/dco.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "dco_test: FAIL: $*" >&2; exit 1; }

# with_cutoff SHA: points `dco` at a copy of the script pinned to SHA.
with_cutoff() {
	sed "s/^DCO_CUTOFF=.*/DCO_CUTOFF=$1/" "$real" >"$tmp/dco.sh"
	chmod +x "$tmp/dco.sh"
	grep -q "^DCO_CUTOFF=$1\$" "$tmp/dco.sh" || fail "the pin was not replaced in the copy"
	dco="$tmp/dco.sh"
}
grep -Eq '^DCO_CUTOFF=[0-9a-f]{40}$' "$real" || fail "hack/ci/dco.sh has no 40-hex DCO_CUTOFF line"

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
with_cutoff "$root"

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
# The cut-off. History: a root, old1 and old2 (unsigned; old2 is the pin), new1 (unsigned), then a signed one.
git checkout -q --orphan hist
commit "Ann Dev" ann@example.com "old: unsigned one"
old1="$(git rev-parse HEAD)"
commit "Ann Dev" ann@example.com "old: unsigned two"
old2="$(git rev-parse HEAD)"
with_cutoff "$old2"
expect_ok "an unsigned commit strictly before the cut-off" "$root" "$old1"
expect_ok "the pinned commit itself" "$old1" "$old2"
commit "Ann Dev" ann@example.com "new: unsigned"
new1="$(git rev-parse HEAD)"
expect_fail "an unsigned commit after the cut-off" "$old2" "$new1"
grep -q 'new: unsigned' "$tmp/out" || fail "the refusal does not name the commit after the cut-off"
commit "Ann Dev" ann@example.com "new: signed$ok"
expect_fail "a range that holds both old unsigned and new unsigned commits" "$old1" HEAD
grep -q 'old: unsigned' "$tmp/out" && fail "an old commit was named, it is exempt"
# The same range with the pin moved past the new commit passes: the exemption is the pin, nothing else.
with_cutoff "$new1"
expect_ok "the pin moved past the unsigned commit" "$old1" HEAD
# A pin that is not in the repository fails as a shallow clone does.
with_cutoff "$zero"
expect_fail "a missing pin" "$old1" HEAD 2

# A trailer with no closing `>` is not a sign-off, even when the text before it is the author's email.
git checkout -q -f main
git reset -q --hard "$good"
commit "Ann Dev" ann@example.com "feat: unclosed"$'\n\nSigned-off-by: Ann Dev <ann@example.com'
with_cutoff "$root"
expect_fail "a sign-off with no closing >" "$good" HEAD
grep -q 'no Signed-off-by' "$tmp/out" || fail "the malformed trailer was not named as unsigned"
git reset -q --hard "$good"
commit "Ann Dev" ann@example.com "feat: bare"$'\n\nSigned-off-by: ann@example.com'
expect_fail "a sign-off with no angle brackets" "$good" HEAD

# A rev-list that fails must fail the check (exit 2), never "ok (0 commits)". The range is made unreadable by
# deleting the loose object of a commit between BASE and HEAD in a separate repository.
mkdir "$tmp/broken"
git -C "$tmp/broken" init -q -b main
git -C "$tmp/broken" config user.name x
git -C "$tmp/broken" config user.email x@example.com
git -C "$tmp/broken" config commit.gpgsign false
git -C "$tmp/broken" commit -q --allow-empty -m a
b0="$(git -C "$tmp/broken" rev-parse HEAD)"
git -C "$tmp/broken" commit -q --allow-empty -m b
mid="$(git -C "$tmp/broken" rev-parse HEAD)"
git -C "$tmp/broken" commit -q --allow-empty -m c
b2="$(git -C "$tmp/broken" rev-parse HEAD)"
rm "$tmp/broken/.git/objects/${mid:0:2}/${mid:2}"
with_cutoff "$b0"
code=0
(cd "$tmp/broken" && "$dco" "$b0" "$b2") >"$tmp/out" 2>&1 || code=$?
[ "$code" = 2 ] || fail "an unreadable range: exit $code, wanted 2:
$(cat "$tmp/out")"
grep -q 'ok (' "$tmp/out" && fail "an unreadable range reported ok"
echo "dco_test: ok"
