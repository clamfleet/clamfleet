#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# webtests_test.sh - the browser suite cannot quietly run less than it contains (`make check` runs it).
# The Go test gate refuses skips, but Playwright is outside it: a committed test.only runs one test and
# passes, and test.skip / test.fixme / test.fail make a test report success without checking anything.
# So e2e/web/playwright.config.ts must set forbidOnly: true, and no spec may use .only, .skip, .fixme
# or .fail (a runtime skip on a condition is the same hole). A test that cannot run in CI is excluded in
# a reviewed change, not skipped. The checks run on the real tree, then on a temporary copy with each
# forbidden call planted, to show they can fail.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fail() { echo "webtests_test: FAIL: $*" >&2; exit 1; }

# check DIR: prints a finding per problem in the web suite under DIR.
check() {
	local d="$1"
	grep -qE '(^|[{,[:space:]])forbidOnly:[[:space:]]*true' "$d/playwright.config.ts" || echo "playwright.config.ts: forbidOnly: true is missing"
	grep -rnE '\.(only|skip|fixme|fail)\(|\b(xit|xdescribe|xtest)\(' "$d/tests" "$d/global-setup.ts" 2>/dev/null || true
}

out="$(check "$here/../../e2e/web")"
[ -z "$out" ] || fail "the browser suite can run less than it contains:
$out"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/tests"
printf 'export default { forbidOnly: true, retries: 0 };\n' >"$tmp/playwright.config.ts"
printf "test('a', async () => {});\n" >"$tmp/tests/a.spec.ts"
[ -z "$(check "$tmp")" ] || fail "self-test: a clean suite was refused"
for planted in "test.only('b', async () => {});" "test.skip('b', async () => {});" "test.fixme('b', async () => {});" "test.skip(process.env.X === '1', 'why');" "test.describe.skip('g', () => {});"; do
	printf '%s\n' "$planted" >"$tmp/tests/b.spec.ts"
	[ -n "$(check "$tmp")" ] || fail "self-test: '$planted' was not refused"
done
rm "$tmp/tests/b.spec.ts"
printf 'export default { retries: 0 };\n' >"$tmp/playwright.config.ts"
[ -n "$(check "$tmp")" ] || fail "self-test: a config without forbidOnly was not refused"
echo "webtests_test: ok"
