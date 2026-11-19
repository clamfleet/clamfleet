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
# file fails here. The two rules must also sit inside one `optional` block, and nothing else may
# (EL10 has no antivirus_t in its base policy). The behavioural proof (the module is needed, and nothing more is
# opened) is `make e2e-el9` (TestSELinuxRuleSet, TestSELinuxModuleIsNeeded).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cil="$here/../selinux/clamfleet.cil"
fail() { echo "selinux_test: FAIL: $*" >&2; exit 1; }

grep -q 'SPDX-License-Identifier: AGPL-3.0-only' "$cil" || fail "no SPDX identifier"
grep -q 'SPDX-FileCopyrightText: The ClamFleet Authors' "$cil" || fail "no SPDX copyright"

# Strip comments and indentation, then look at every statement.
body="$(sed -e 's/;.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$cil" | grep -v '^$')"

# The two reviewed rules, literally. Anything looser (another class, another permission, another
# source or target) is a new rule and needs the maintainer's sign-off, so it fails here.
rule_dir='(allow antivirus_t clamfleet_spool_t (dir (search getattr open read write add_name remove_name)))'
rule_file='(allow antivirus_t clamfleet_spool_t (file (create open read write getattr setattr lock link unlink)))'

# Only allow rules from antivirus_t onto clamfleet_spool_t, of class dir or file.
bad="$(printf '%s\n' "$body" | grep -E '^\(allow' | grep -v -E '^\(allow antivirus_t clamfleet_spool_t \((dir|file) \([a-z_ ]+\)\)\)$' || true)"
[ -z "$bad" ] || fail "an allow rule outside 'allow antivirus_t clamfleet_spool_t (dir|file ...)':
$bad"
[ "$(printf '%s\n' "$body" | grep -c '^(allow')" -eq 2 ] || fail "expected exactly two allow rules"
printf '%s\n' "$body" | grep -qxF -- "$rule_dir" || fail "the dir rule is not the reviewed one"
printf '%s\n' "$body" | grep -qxF -- "$rule_file" || fail "the file rule is not the reviewed one"

# The rules live in ONE optional block and nowhere else. antivirus_t is absent from a stock EL10 policy
# (R1 decision 9): outside the block the module would not load there. The block is exactly four lines:
# its opening, the two rules, its closing parenthesis. A third rule inside it, or a rule moved out of
# it, changes that sequence.
[ "$(printf '%s\n' "$body" | grep -c '^(optional')" -eq 1 ] || fail "expected exactly one optional block"
block="$(printf '%s\n' "$body" | grep -A3 -x '(optional clamfleet_antivirus' || true)"
[ "$block" = "(optional clamfleet_antivirus
$rule_dir
$rule_file
)" ] || fail "the optional block is not 'optional clamfleet_antivirus' holding exactly the two reviewed rules:
$block"
[ "$(printf '%s\n' "$body" | grep -c '^)$')" -eq 1 ] || fail "a stray closing parenthesis (a second block or a nested one)"
# No other kind of statement that widens anything: transitions, attributes other than file_type, booleans, includes.
other="$(printf '%s\n' "$body" | grep -v -x -F -e "$rule_dir" -e "$rule_file" -e '(optional clamfleet_antivirus' -e ')' -e '(type clamfleet_spool_t)' -e '(roletype object_r clamfleet_spool_t)' -e '(typeattributeset file_type (clamfleet_spool_t))' | grep -v '^(filecon ' || true)"
[ -z "$other" ] || fail "an unexpected statement in the module:
$other"
# Every filecon labels the spool and nothing else: the two lines are compared literally, so a changed path, file type or
# context fails here and not only a path outside the spool.
fc="$(printf '%s\n' "$body" | grep '^(filecon' || true)"
want_fc='(filecon "/var/lib/clamfleet/spool/events(/.*)?" any (system_u object_r clamfleet_spool_t ((s0) (s0))))
(filecon "/var/lib/clamfleet/spool/usage" file (system_u object_r clamfleet_spool_t ((s0) (s0))))'
[ "$fc" = "$want_fc" ] || fail "the filecon lines are not exactly the two reviewed ones: $fc"
# Permission lists: nothing like execute, execmod, entrypoint, ioctl, mounton, relabel*, or the net classes.
if printf '%s\n' "$body" | grep -E '^\(allow' | grep -q -E '\b(execute|execute_no_trans|entrypoint|execmod|relabelfrom|relabelto|mounton|ioctl|map|rename|create_files_pattern)\b'; then
	fail "a permission beyond the reviewed set (execute, relabel, mount, ioctl, map, rename)"
fi
echo "selinux_test: ok"
