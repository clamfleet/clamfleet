#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# reset_test.sh - checks reset.sh against a fake "ssh" (no container needed;
# `make check` runs it). Guards two review findings: a failed snapshot restore
# must fail the script, and readiness must be a real scan, not "clamdscan --ping".
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Fakes: "ssh" really evaluates the remote command string (that is what the
# "&& { ...; }" grouping is about), but "sudo" and "incus" are stubs. incus logs
# its arguments and stdin, and fails the restore when FAKE_RESTORE_FAILS=1.
printf '#!/usr/bin/env bash\nshift\nexec bash -c "$1"\n' >"$tmp/ssh"
printf '#!/usr/bin/env bash\nexec "$@"\n' >"$tmp/sudo"
cat >"$tmp/incus" <<'FAKE'
#!/usr/bin/env bash
echo "INCUS: $*" >>"$FAKE_LOG"
if [ "$1" = exec ]; then cat >>"$FAKE_LOG"; fi
if [ "$1 $2" = "snapshot restore" ] && [ "${FAKE_RESTORE_FAILS:-0}" = 1 ]; then exit 1; fi
if [ "$1" = start ]; then exit 1; fi # "already running" must stay harmless
exit 0
FAKE
chmod +x "$tmp/ssh" "$tmp/sudo" "$tmp/incus"
run() { # $1 = FAKE_RESTORE_FAILS
	: >"$tmp/log"
	PATH="$tmp:$PATH" FAKE_LOG="$tmp/log" FAKE_RESTORE_FAILS="$1" INCUS_HOST=fake-host \
		"$here/reset.sh" >"$tmp/out" 2>&1 </dev/null
}

if run 1; then
	echo "FAIL: reset.sh succeeded although the snapshot restore failed" >&2
	exit 1
fi
if grep -q 'clamdscan' "$tmp/log"; then
	echo "FAIL: reset.sh waited for clamd after a failed restore" >&2
	exit 1
fi
run 0 || { echo "FAIL: reset.sh failed on a healthy run" >&2; cat "$tmp/out" >&2; exit 1; }
grep -q 'clamdscan --no-summary' "$tmp/log" || { echo "FAIL: readiness is not a real scan" >&2; exit 1; }
if grep -q -- '--ping' "$tmp/log"; then
	echo "FAIL: readiness still uses clamdscan --ping" >&2
	exit 1
fi
echo "reset_test: ok"
