#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# verify-tag.sh TAG - decides whether a pushed tag may start a release. The `verify` job of release.yml runs
# it first; nothing is built from a tag it refuses.
#
# It requires, in this order:
#   1. TAG is `v` + a version of the policy (lib.sh);
#   2. TAG is an annotated tag object (a lightweight tag has no signature and no signer);
#   3. its signature is good and made by a key in RELEASE_ALLOWED_SIGNERS (an SSH allowed-signers file,
#      held as an admin-only repository variable: the tag is the maintainer's word, so who may speak is
#      configuration that a contributor cannot edit by pull request);
#   4. a successful push run of ci.yml on branch main for EXACTLY the tagged commit (`head_sha`), full CI with
#      the e2e suite included. "An ancestor of main passed" is not enough: a commit that only reached main
#      as a descendant of a green one has never been tested;
#   5. CHANGELOG.md at that commit has the section for the version.
#
# Environment: GITHUB_REPOSITORY (owner/name), RELEASE_ALLOWED_SIGNERS (file CONTENT, not a path), and
# `gh` authenticated (GH_TOKEN) for the Actions API (read-only: actions: read).
# Stdout: exactly two lines, `tag_object=<sha>` and `commit=<sha>`, which the workflow appends to
# GITHUB_OUTPUT; later jobs check out `commit` and publish only while the tag still points at `tag_object`.
# Everything else goes to stderr. Exit 0 accepted, 1 refused.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

die() { echo "verify-tag.sh: refused: $*" >&2; exit 1; }

[ "$#" -eq 1 ] || die "usage: verify-tag.sh TAG"
tag="$1"
[ -n "${GITHUB_REPOSITORY:-}" ] || die "GITHUB_REPOSITORY is not set"
[ -n "${RELEASE_ALLOWED_SIGNERS:-}" ] || die "RELEASE_ALLOWED_SIGNERS is empty: no key may sign a release"

[[ "$tag" == v* ]] || die "tag '$tag' does not start with v"
version="${tag#v}"
release_version_ok "$version" || die "tag '$tag' is outside the version policy (vX.Y.Z or vX.Y.Z-rc.N)"

# Rule: an annotated tag. `git cat-file -t` says "commit" for a lightweight tag.
kind="$(git cat-file -t "refs/tags/$tag" 2>/dev/null)" || die "no tag $tag in this repository (fetch it with its refs/tags/ name)"
[ "$kind" = "tag" ] || die "$tag is a lightweight tag: a release tag must be annotated and signed"
tag_object="$(git rev-parse "refs/tags/$tag")"
# Rule: the name the maintainer signed is the name being released. The signature covers the tag object,
# including its `tag` header, but not the ref that points at it: without this, a ref v1.0.0-rc.1 could be
# pointed at an object signed as another tag (an older one, say) and still verify. Only the header block
# (before the first blank line) is read, so the message cannot fake it.
signed_name="$(git cat-file tag "refs/tags/$tag" | awk '/^$/ { exit } /^tag / { print substr($0, 5); exit }')"
[ "$signed_name" = "$tag" ] || die "the tag object behind $tag was signed as '${signed_name:-nothing}': a release tag must carry its own name"
commit="$(git rev-parse "refs/tags/$tag^{commit}")"

signers="$(mktemp)"
trap 'rm -f "$signers"' EXIT
printf '%s\n' "$RELEASE_ALLOWED_SIGNERS" >"$signers"
# An unsigned tag, a bad signature and an unlisted signer all fail here. verify-tag reads the signature
# format from the tag itself; only the allowed-signers file is ours.
if ! sigout="$(git -c "gpg.ssh.allowedSignersFile=$signers" verify-tag "$tag" 2>&1)"; then
	die "the signature of $tag is missing, bad, or by a key that is not in RELEASE_ALLOWED_SIGNERS: $sigout"
fi
echo "verify-tag.sh: $tag: $sigout" >&2

# CI evidence for this exact commit. The filter is repeated here and not only in the query: the answer is
# data we parse, so a wrong or widened query still cannot admit a run for another commit.
runs="$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/ci.yml/runs?event=push&branch=main&head_sha=$commit&per_page=100")" ||
	die "cannot read the Actions runs of ci.yml"
n="$(jq --arg sha "$commit" '[.workflow_runs[]? | select(.event == "push" and .head_branch == "main" and .head_sha == $sha and .status == "completed" and .conclusion == "success")] | length' <<<"$runs")"
[ "$n" -ge 1 ] || die "no successful push run of ci.yml on main for commit $commit (full CI must have passed on exactly this commit)"
run_url="$(jq -r --arg sha "$commit" '[.workflow_runs[] | select(.event == "push" and .head_branch == "main" and .head_sha == $sha and .conclusion == "success")][0].html_url' <<<"$runs")"
echo "verify-tag.sh: accepted CI run $run_url for $commit" >&2

# The notes must exist at the tagged commit (not in the worktree: this checkout may be on any commit).
tmp_cl="$(mktemp)"
trap 'rm -f "$signers" "$tmp_cl"' EXIT
git show "$commit:CHANGELOG.md" >"$tmp_cl" 2>/dev/null || die "CHANGELOG.md is missing at $commit"
changelog_section "$version" "$tmp_cl" >/dev/null || die "CHANGELOG.md at $commit has no non-empty section '## [$version] - YYYY-MM-DD'"

echo "tag_object=$tag_object"
echo "commit=$commit"
