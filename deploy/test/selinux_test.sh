#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# selinux_test.sh - static check of deploy/selinux/clamfleet.cil (no SELinux, no VM).
#
# antivirus_t is the domain of clamd, freshclam and clamonacc alike, so every allow rule
# in this module reaches all three. The module's contract (M6 decision 10) is that
# it grants access ONLY on its own type, clamfleet_spool_t; a rule on a stock type needs
# the maintainer's sign-off. This test makes that mechanical: any allow rule whose target
# is not clamfleet_spool_t, any other source domain, and any rule class beyond dir and
# file fails here. The behavioural proof (the module is needed, and nothing more is
# opened) is `make e2e-el9` (TestSELinuxRuleSet, TestSELinuxModuleIsNeeded).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cil="$here/../selinux/clamfleet.cil"
fail() { echo "selinux_test: FAIL: $*" >&2; exit 1; }

grep -q 'SPDX-License-Identifier: AGPL-3.0-only' "$cil" || fail "no SPDX identifier"
grep -q 'SPDX-FileCopyrightText: The ClamFleet Authors' "$cil" || fail "no SPDX copyright"

# Strip comments, then look at every statement that is not the type declaration.
body="$(sed 's/;.*$//' "$cil" | grep -v '^[[:space:]]*$')"

# Only allow rules from antivirus_t onto clamfleet_spool_t, of class dir or file.
rules="$(printf '%s\n' "$body" | grep -E '^\((allow|neverallow|dontaudit|auditallow|typetransition|typeattributeset|typeattribute|roletype|type|filecon|typemember|typechange)' || true)"
bad="$(printf '%s\n' "$body" | grep -E '^\(allow' | grep -v -E '^\(allow antivirus_t clamfleet_spool_t \((dir|file) \([a-z_ ]+\)\)\)$' || true)"
[ -z "$bad" ] || fail "an allow rule outside 'allow antivirus_t clamfleet_spool_t (dir|file ...)':
$bad"
# No other kind of statement that widens anything: transitions, attributes other than file_type, booleans, includes.
other="$(printf '%s\n' "$body" | grep -v -E '^\((allow antivirus_t clamfleet_spool_t |type clamfleet_spool_t\)|roletype object_r clamfleet_spool_t\)|typeattributeset file_type \(clamfleet_spool_t\)\)|filecon )' || true)"
[ -z "$other" ] || fail "an unexpected statement in the module:
$other"
# Every filecon labels the spool and nothing else.
fc="$(printf '%s\n' "$body" | grep '^(filecon' | grep -v -E '"/var/lib/clamfleet/spool/(events\(/\.\*\)\?|usage)"' || true)"
[ -z "$fc" ] || fail "a filecon outside the event spool: $fc"
[ "$(printf '%s\n' "$body" | grep -c '^(filecon')" -eq 2 ] || fail "expected exactly two filecon rules"
# Permission lists: nothing like execute, execmod, entrypoint, ioctl, mounton, relabel*, or the net classes.
if printf '%s\n' "$body" | grep -E '^\(allow' | grep -q -E '\b(execute|execute_no_trans|entrypoint|execmod|relabelfrom|relabelto|mounton|ioctl|map|rename|create_files_pattern)\b'; then
	fail "a permission beyond the reviewed set (execute, relabel, mount, ioctl, map, rename)"
fi
echo "selinux_test: ok"
