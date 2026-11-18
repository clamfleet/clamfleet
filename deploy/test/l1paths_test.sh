#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# l1paths_test.sh - hack/ci/l1-required.sh with the real deploy/test/l1-paths.txt, against a temporary
# repository (`make check` runs it). A table of paths and verdicts covers each glob class, each
# exclusion, go.mod, and a documentation-only change; separate cases cover a rename out of a watched
# directory, a range that was never fetched (must fail, not look empty) and a missing or empty globs
# file. A glob dropped from l1-paths.txt turns a row of the table red.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/../../hack/ci/l1-required.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "l1paths_test: FAIL: $*" >&2; exit 1; }

cd "$tmp"
git init -q -b main .
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
git config user.name x
git config user.email x@example.com
git config commit.gpgsign false
git commit -q --allow-empty -m root
root="$(git rev-parse HEAD)"

# touch_commit PATH...: one commit that adds each path.
touch_commit() {
	local p
	for p in "$@"; do
		mkdir -p "$(dirname "$p")"
		echo "$RANDOM" >"$p"
		git add -- "$p"
	done
	git commit -q -m change
}

# verdict: the script's line for root..HEAD.
verdict() { "$script" "$root" HEAD; }

# row WANT PATH: a commit of PATH alone on top of root must give WANT ("yes" or "no").
row() {
	local want="$1" path="$2" out
	git reset -q --hard "$root"
	touch_commit "$path"
	out="$(verdict)" || fail "$path: the script failed"
	case "$want:$out" in
	"yes:L1 required: $path" | "no:L1 not required") ;;
	*) fail "$path: wanted $want, got '$out'" ;;
	esac
}

# Each glob class of l1-paths.txt.
row yes deploy/packaging/nfpm-agent.yaml
row yes deploy/packaging/scripts/agent.postinst
row yes deploy/apparmor/clamfleet-agent-event
row yes deploy/selinux/clamfleet.te
row yes deploy/systemd/clamfleet-agent.service
row yes deploy/agent.yaml.example
row yes deploy/agent.rhel9.yaml.example
row yes deploy/server.yaml.example
row yes cmd/clamfleet-agent/main.go
row yes internal/agent/report.go
row yes internal/agent/sub/deep.go
row yes internal/config/config.go
row yes go.mod
row yes Makefile
# The L1 harness, including the files later pull requests add.
row yes e2e/apparmor_e2e_test.go
row yes e2e/el_e2e_test.go
row yes e2e/el9_e2e_test.go
row yes e2e/distro_e2e_test.go
row yes e2e/distro_test.go
row yes e2e/package_e2e_test.go
row yes e2e/agent_e2e_test.go
row yes e2e/event_e2e_test.go
row yes deploy/test/aa-prepare.sh
row yes deploy/test/el-prepare.sh
row yes deploy/test/el9-prepare.sh
row yes deploy/test/host-reset.sh
row yes deploy/test/runner-prepare.sh
row yes deploy/test/prepare-agent.sh
row yes deploy/test/prepare-server.sh
row yes deploy/test/reset.sh

# The exclusions: tests and recordings of internal/agent cannot change what ships.
row no internal/agent/report_test.go
row no internal/agent/sub/deep_test.go
row no internal/agent/testdata/clamd.json
row no internal/agent/testdata/sub/x.bin
row no internal/config/config_test.go
# Not on the list: documentation, the server's code, other tests and other scripts, the lockfile.
row no docs/testing.md
row no README.md
row no go.sum
row no internal/server/server.go
row no e2e/server_e2e_test.go
row no deploy/test/dco_test.sh
row no deploy/release/sign.sh
row no cmd/clamfleet-server/main.go
# A look-alike: the glob for the examples must not match another directory's file.
row no docs/deploy/agent.yaml.example
row no docs/deploy/server.yaml.example

# Several paths: only the matching ones are listed, in diff order.
git reset -q --hard "$root"
touch_commit docs/a.md Makefile internal/agent/x_test.go go.mod
out="$(verdict)"
[ "$out" = "L1 required: Makefile go.mod" ] || fail "a mixed change: got '$out'"

# A doc-only change over several files.
git reset -q --hard "$root"
touch_commit docs/a.md docs/b.md CHANGELOG.md
out="$(verdict)"
[ "$out" = "L1 not required" ] || fail "a doc-only change: got '$out'"

# An empty range is "not required".
out="$("$script" "$root" "$root")"
[ "$out" = "L1 not required" ] || fail "an empty range: got '$out'"

# The diff is against the merge base: a change that is only on the base side is not part of the PR.
git reset -q --hard "$root"
git checkout -q -b side
touch_commit docs/side.md
git checkout -q main
touch_commit go.mod
out="$("$script" main side)"
[ "$out" = "L1 not required" ] || fail "a base-side change leaked into the verdict: '$out'"
git reset -q --hard "$root"

# A rename OUT of a watched directory still counts (both sides are listed).
git reset -q --hard "$root"
touch_commit deploy/systemd/clamfleet-agent.service
before="$(git rev-parse HEAD)"
mkdir -p docs
git mv deploy/systemd/clamfleet-agent.service docs/moved.txt
git commit -q -m move
out="$("$script" "$before" HEAD)"
[ "$out" = "L1 required: deploy/systemd/clamfleet-agent.service" ] || fail "a rename out of a watched directory: got '$out'"

# Last match wins, through a globs file of its own: a carve-out followed by a re-inclusion.
printf 'a/*\n!a/b/*\na/b/c\n' >"$tmp/lastwins.txt"
for want in "a/b/c:L1 required: a/b/c" "a/b/d:L1 not required" "a/x:L1 required: a/x"; do
	git reset -q --hard "$root"
	touch_commit "${want%%:*}"
	out="$(L1_PATHS_FILE="$tmp/lastwins.txt" "$script" "$root" HEAD)"
	[ "$out" = "${want#*:}" ] || fail "last match wins, ${want%%:*}: got '$out'"
done

# A range that is not in the repository must FAIL (exit 2), not look empty.
zero=0000000000000000000000000000000000000000
for args in "$zero HEAD" "HEAD $zero" ""; do
	code=0
	# shellcheck disable=SC2086 # word splitting of the case's arguments is the point
	"$script" $args >"$tmp/out" 2>&1 || code=$?
	[ "$code" = 2 ] || fail "arguments '$args': exit $code, wanted 2: $(cat "$tmp/out")"
done

# A missing or empty globs file fails: it must never mean "nothing needs L1".
code=0
L1_PATHS_FILE="$tmp/none.txt" "$script" "$root" HEAD >"$tmp/out" 2>&1 || code=$?
[ "$code" = 2 ] || fail "a missing globs file: exit $code, wanted 2"
printf '# only a comment\n\n' >"$tmp/empty.txt"
code=0
L1_PATHS_FILE="$tmp/empty.txt" "$script" "$root" HEAD >"$tmp/out" 2>&1 || code=$?
[ "$code" = 2 ] || fail "an empty globs file: exit $code, wanted 2"

echo "l1paths_test: ok"
