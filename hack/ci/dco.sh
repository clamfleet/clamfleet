#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# dco.sh BASE HEAD - every commit in BASE..HEAD carries a Developer Certificate of Origin
# sign-off (M6c decision 13: DCO, checked by this script rather than by a third-party app that
# would process contributors' names and emails).
#
# The rule: a `Signed-off-by: Name <email>` line in the commit's trailer block (what `git commit -s`
# writes), whose email equals the commit author's email, compared case-insensitively. Exempt: merge
# commits (GitHub's "update branch" button makes one, and it holds no contribution), and Dependabot's
# commits (a bot cannot certify anything; a human merges its pull request). The bot exemption is by
# author email, which an author can write anything into: that gains nothing, because a sign-off is
# a statement by the contributor and the maintainer reviews every change; this check is a reminder
# and a record, not authentication.
#
# Cut-off (R1 decision 12): the project adopted the sign-off rule only when this script was added, so 192
# commits before it, all milestone work, carry none, and a pull request into `main` (the first release) spans
# all of them. A commit that is an ancestor of, or equal to, DCO_CUTOFF is exempt; every later commit is
# checked. The pin is permanent: history is not rewritten to add sign-offs nobody gave at the time.
#
# A BASE or HEAD that is not in the repository FAILS. In CI the range comes from the pull request
# event, and a checkout that did not fetch it (a shallow clone) would otherwise make the range look
# empty and the check pass. The workflow checks out with fetch-depth: 0 for the same reason.
#
# Exit status: 0 all commits are signed off (or the range is empty), 1 some are not, 2 bad use or an
# unfetched range. Names the commits by SHA and subject only (both are public in the pull request).
set -euo pipefail

if [ "$#" -ne 2 ]; then
	echo "usage: dco.sh BASE_SHA HEAD_SHA" >&2
	exit 2
fi
base="$1"
head="$2"
# The last commit without a sign-off before the rule existed (b072a15, "test(server): wait for the TLS
# server to be listening before replacing its files"), found as the newest of the unsigned commits of
# the history at the time; every unsigned commit of it is an ancestor of this one.
DCO_CUTOFF=b072a15dbc120f5a53a06db31b0e9c8d68bc0b32
# The pin is checked like BASE and HEAD: a checkout that lacks it (shallow clone) must fail, not leave
# every old commit looking non-exempt or, worse, the exemption silently absent.
for sha in "$base" "$head" "$DCO_CUTOFF"; do
	# ^{commit}: a name that is not a commit (or a missing object) fails; the SHA must resolve here.
	if ! git cat-file -e "${sha}^{commit}" 2>/dev/null; then
		echo "dco: $sha is not a commit in this repository (shallow checkout? the workflow needs fetch-depth: 0)" >&2
		exit 2
	fi
done

bad=0
n=0
while IFS= read -r c; do
	[ -n "$c" ] || continue
	# Exempt: at or before the cut-off (R1 decision 12). --is-ancestor is true for equal commits too.
	if git merge-base --is-ancestor "$c" "$DCO_CUTOFF"; then continue; fi
	n=$((n + 1))
	author="$(git log -1 --format=%ae "$c" | tr '[:upper:]' '[:lower:]')"
	case "$author" in
	*+dependabot\[bot\]@users.noreply.github.com | dependabot\[bot\]@users.noreply.github.com) continue ;;
	esac
	signed=0
	# --only-trailers --parse prints one "Key: value" per trailer of the final block, nothing else:
	# a "Signed-off-by:" written in the middle of the message text is not a sign-off.
	while IFS= read -r t; do
		case "$t" in
		[Ss]igned-off-by:*)
			email="${t##*<}"
			email="${email%>*}"
			if [ "$(printf '%s' "$email" | tr '[:upper:]' '[:lower:]')" = "$author" ]; then signed=1; fi
			;;
		esac
	done < <(git log -1 --format=%B "$c" | git interpret-trailers --only-trailers --parse)
	if [ "$signed" = 0 ]; then
		echo "dco: $(git log -1 --format='%h %s' "$c"): no Signed-off-by with the author's email (use git commit -s; to fix: git rebase --signoff)" >&2
		bad=1
	fi
done < <(git rev-list --no-merges "$base..$head")

if [ "$bad" != 0 ]; then
	exit 1
fi
echo "dco: ok ($n commits checked)"
