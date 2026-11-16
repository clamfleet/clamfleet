#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# workflows_test.sh - the workflow rules that neither actionlint nor GitHub's settings enforce
# (docs/testing.md, "CI"). `make check` runs it, and `make ci` runs actionlint next to it.
#
# This is a GUARDRAIL over a list of patterns, not a proof that a workflow is safe: actionlint does
# the semantic checks (including untrusted input in `run:`), and the repository settings (only
# GitHub-owned actions, SHA pinning, a read-only default token) are the other layer. What it adds:
#
#   1. every `uses:` is `actions/<name>@<40 hex>` followed by a `# vX.Y.Z` comment: GitHub-owned
#      actions only, pinned by commit, with the tag a reader and Dependabot can see;
#   2. no `pull_request_target` and no `workflow_run`: both run with the base repository's token
#      and secrets on a pull request's behalf;
#   3. a top-level `permissions:`, and a `permissions:` on every job (least privilege per job);
#   4. no `runs-on: *-latest`: the runner image must not change under a green workflow;
#   5. `persist-credentials: false` on every `actions/checkout`: the token must not stay in .git/config
#      where every later step, and a malicious test, can read it;
#   6. a job-level `if:` on a REQUIRED check only in the two forms below. A job skipped by `if:`
#      reports success to a required check, so any other condition could silently let a merge through;
#   7. `secrets` is mentioned only in release.yml's `sign` job, and that job runs no go, make, npm
#      or setup action: the signing key must never meet a build tool (plan 4.6; the key is the
#      thing a compromised dependency would come for). Use `github.token`, not `secrets.GITHUB_TOKEN`,
#      for the API token elsewhere.
#
# The workflows are parsed line by line with awk and assume the two-space indentation every
# workflow here uses (jobs at 2, job keys at 4, steps `- ` at 6). A workflow in another style is
# refused by rule 3 or 1 rather than waved through, because the keys would not be found.
# Each rule is proven by a bad workflow below; the real workflows must also pass.
#
# Usage: workflows_test.sh            (checks .github/workflows of the repository, then self-tests)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

# The jobs a ruleset requires (docs/releasing.md lists them) and the one `if:` each may carry.
# A draft pull request cannot be merged and ready_for_review starts a full run, so skipping the
# expensive jobs on a draft is safe; dco only has a meaning on a pull request.
DRAFT="github.event_name != 'pull_request' || !github.event.pull_request.draft"
PRONLY="github.event_name == 'pull_request'"
REQUIRED="check e2e web dco release-dry-run"
ALLOWED="e2e=$DRAFT;web=$DRAFT;release-dry-run=$DRAFT;dco=$PRONLY"

# findings FILE...: prints one "file:line: rule N: message" per violation.
findings() {
	local f
	for f in "$@"; do
		awk -v file="$f" -v base="$(basename "$f")" -v required="$REQUIRED" -v allowed="$ALLOWED" '
		function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
		function bad(n, msg) { printf "%s:%d: rule %d: %s\n", file, FNR, n, msg; found = 1 }
		function endstep() {
			if (instep && checkout && !persist) bad(5, "actions/checkout without persist-credentials: false (step starting at line " stepline ")")
			instep = 0; checkout = 0; persist = 0
		}
		function endjob(   n, i, parts, kv, cond) {
			endstep()
			if (job == "") return
			if (!jobperm) bad(3, "job " job " has no permissions:")
			if (index(" " required " ", " " job " ") && jobif != "") {
				cond = ""
				n = split(allowed, parts, ";")
				for (i = 1; i <= n; i++) { split(parts[i], kv, "="); if (kv[1] == job) cond = substr(parts[i], length(kv[1]) + 2) }
				if (jobif != cond) bad(6, "required job " job " has if: " jobif " (only the one documented condition is allowed)")
			}
			job = ""
		}
		FNR == 1 { section = ""; job = ""; instep = 0; seenjobs = 0; topperm = 0 }
		{
			raw = $0
			code = raw
			sub(/^[ \t]*#.*$/, "", code)       # whole-line comment
			sub(/[ \t]+#.*$/, "", code)        # trailing comment (never inside the strings we look at)
			if (trim(code) == "") next
			ind = match(code, /[^ ]/) - 1
			t = trim(code)

			if (ind == 0) {
				endjob()
				section = t; sub(/:.*$/, "", section)
				if (section == "permissions") topperm = 1
				if (section == "jobs") seenjobs = 1
			}
			if (section == "jobs" && ind == 2 && t ~ /^[A-Za-z0-9_-]+:$/) {
				endjob()
				job = t; sub(/:$/, "", job); jobperm = 0; jobif = ""
			}
			if (section == "jobs" && ind == 4) {
				if (t ~ /^permissions:/) jobperm = 1
				if (t ~ /^if:/) {
					jobif = trim(substr(t, 4))
					if (jobif ~ /^\${{.*}}$/) jobif = trim(substr(jobif, 4, length(jobif) - 5))
					if (jobif ~ /^".*"$/ || jobif ~ /^\047.*\047$/) jobif = substr(jobif, 2, length(jobif) - 2)
				}
			}
			# Steps: "- " at indent 6 starts one.
			if (section == "jobs" && ind == 6 && t ~ /^- /) { endstep(); instep = 1; stepline = FNR }

			# Rule 2
			if (code ~ /(^|[^A-Za-z0-9_])(pull_request_target|workflow_run)([^A-Za-z0-9_]|$)/) bad(2, "pull_request_target and workflow_run are not allowed")
			# Rule 4
			if (t ~ /^(- )?runs-on:.*-latest/) bad(4, "runs-on uses a -latest image: " t)
			# Rule 1 (the pin and its version comment are read from the raw line)
			if (t ~ /^(- )?uses:/) {
				u = raw; sub(/^[ \t]*(- )?uses:[ \t]*/, "", u); u = trim(u)
				ok = 0
				if (u ~ /^actions\/[A-Za-z0-9._-]+(\/[A-Za-z0-9._\/-]+)?@[0-9a-f]+ # v[0-9]+\.[0-9]+\.[0-9]+$/) {
					sha = u; sub(/^[^@]*@/, "", sha); sub(/ .*$/, "", sha)
					if (length(sha) == 40) ok = 1
				}
				if (!ok) bad(1, "uses must be actions/<name>@<40 hex sha> # vX.Y.Z, got: " u)
				if (u ~ /^actions\/checkout@/) checkout = 1
				if (job == "sign" && base == "release.yml" && u ~ /^actions\/setup-/) bad(7, "the sign job must not use " u)
			}
			# Rule 5
			if (t ~ /^persist-credentials:[ \t]*false$/) persist = 1
			# Rule 7
			if (code ~ /(^|[^A-Za-z0-9_])secrets([^A-Za-z0-9_]|$)/ && !(base == "release.yml" && job == "sign")) bad(7, "secrets outside release.yml job sign: " t)
			if (base == "release.yml" && job == "sign" && ind > 4 && t !~ /^(- )?name:/ && t !~ /^(- )?uses:/ &&
			    code ~ /(^|[^A-Za-z0-9_.\/-])(go|make|npm|npx|node|yarn|pnpm)([ \t]|$)/) bad(7, "the sign job runs a build tool: " t)
		}
		END {
			endjob()
			if (seenjobs && !topperm) { printf "%s:1: rule 3: no top-level permissions:\n", file; found = 1 }
			exit 0
		}' "$f"
	done
}

fail() { echo "workflows_test: FAIL: $*" >&2; exit 1; }

# 1. The real workflows (none yet is fine: the check comes before the first workflow).
shopt -s nullglob
real=("$repo"/.github/workflows/*.yml "$repo"/.github/workflows/*.yaml)
if [ "${#real[@]}" -gt 0 ]; then
	out="$(findings "${real[@]}")"
	[ -z "$out" ] || fail "the workflows break the rules:
$out"
fi

# 2. Each rule must be able to fail. A good workflow first, so a rule that fires on everything
# cannot pass the bad cases below by accident.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
SHA=0123456789abcdef0123456789abcdef01234567
good() {
	cat <<YAML
name: t
on:
  pull_request:
    types: [opened]
permissions: {}
jobs:
  check:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: false
      - run: make ci
  e2e:
    if: $DRAFT
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          persist-credentials: false
  dco:
    if: $PRONLY
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - run: echo ok
YAML
}
good >"$tmp/good.yml"
out="$(findings "$tmp/good.yml")"
[ -z "$out" ] || fail "self-test: the good workflow was refused:
$out"

# expect NAME RULE SEDSCRIPT [FILE]: the good workflow with one edit must be refused under rule RULE.
expect() {
	local name="$1" rule="$2" edit="$3" file="${4:-bad.yml}" out
	good | sed -e "$edit" >"$tmp/$file"
	out="$(findings "$tmp/$file")"
	grep -q "rule $rule:" <<<"$out" || fail "self-test: '$name' was not refused under rule $rule (got: ${out:-nothing})"
}
expect "a tag instead of a sha"           1 "0,/@$SHA # v7.0.1/s//@v4/"
expect "a short sha"                      1 "0,/@$SHA/s//@0123456/"
expect "a sha without the version"        1 "0,/@$SHA # v7.0.1/s//@$SHA/"
expect "a third-party action"             1 "0,/actions\/checkout@/s//someone\/checkout@/"
expect "pull_request_target"              2 "s/^  pull_request:/  pull_request_target:/"
expect "workflow_run"                     2 "s/^  pull_request:/  workflow_run:/"
expect "no top-level permissions"         3 "/^permissions: {}/d"
expect "a job without permissions"        3 "0,/^    permissions:/{/^    permissions:/,/contents: read/d}"
expect "runs-on latest"                   4 "0,/ubuntu-24.04/s//ubuntu-latest/"
expect "checkout keeping credentials"     5 "0,/persist-credentials: false/s//persist-credentials: true/"
expect "an if on the check job"           6 "0,/^    runs-on: ubuntu-24.04/s//    if: github.ref == 'refs\/heads\/main'\n    runs-on: ubuntu-24.04/"
expect "the wrong if on e2e"              6 "s/^    if: github.event_name != 'pull_request' .*/    if: github.event_name == 'push'/"
expect "the draft if on dco"              6 "s/^    if: github.event_name == 'pull_request'/    if: $DRAFT/"
expect "secrets in ci.yml"                7 "s/- run: make ci/- run: echo \${{ secrets.TOKEN }}/" ci.yml

# release.yml: secrets belong to the sign job and to no other, and the sign job runs no build tool.
rel() { # $1 = steps of the sign job, $2 = steps of the build job
	cat <<YAML
name: r
on:
  push:
    tags: ['v*']
permissions: {}
jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
$2
  sign:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
$1
YAML
}
rel '      - run: ./deploy/release/sign.sh
        env:
          KEY: ${{ secrets.RELEASE_SIGNING_SUBKEY }}' '      - run: ./deploy/release/release.sh' >"$tmp/release.yml"
out="$(findings "$tmp/release.yml")"
[ -z "$out" ] || fail "self-test: the good release.yml was refused:
$out"
chk() { # NAME SIGN-STEPS BUILD-STEPS
	rel "$2" "$3" >"$tmp/release.yml"
	grep -q 'rule 7:' <<<"$(findings "$tmp/release.yml")" || fail "self-test: '$1' was not refused under rule 7"
}
chk "secrets in the build job" '      - run: ./sign.sh' '      - run: ./release.sh
        env:
          KEY: ${{ secrets.RELEASE_SIGNING_SUBKEY }}'
chk "make in the sign job" '      - run: make sign
        env:
          KEY: ${{ secrets.K }}' '      - run: ./release.sh'
chk "go in the sign job" '      - run: go run ./tool
        env:
          KEY: ${{ secrets.K }}' '      - run: ./release.sh'
chk "npm in a later line of the sign job" '      - run: |
          ./sign.sh
          npm ci
        env:
          KEY: ${{ secrets.K }}' '      - run: ./release.sh'
chk "a setup action in the sign job" "      - uses: actions/setup-go@$SHA # v7.0.0
        env:
          KEY: \${{ secrets.K }}" '      - run: ./release.sh'
echo "workflows_test: ok"
