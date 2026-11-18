#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# reset_test.sh - checks reset.sh against a fake "ssh" and a fake "docker" (no container needed;
# `make check` runs it). Guards two review findings: a failed snapshot restore
# must fail the script, and readiness must be a real scan, not "clamdscan --ping".
# For the Docker runtime (CI): a failed `docker run` must fail before any scan, the container
# must have NO network (the flag is passed and the result is inspected), and INCUS_HOST is
# needed only by the Incus runtime.
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

# ---- Docker runtime. The script is copied next to no local.env, so a developer's own settings
# (INCUS_HOST, CT) cannot change what is tested.
iso="$tmp/iso"
mkdir -p "$iso"
cp "$here/reset.sh" "$here/save-journal.sh" "$iso/"
# The fake docker is stateful where it matters: `run` records the network it was given and
# `inspect` reports it back (FAKE_NETMODE overrides, to play a daemon that ignored the flag).
cat >"$tmp/docker" <<'FAKE'
#!/usr/bin/env bash
echo "DOCKER: $*" >>"$FAKE_LOG"
case "$1" in
run)
	[ "${FAKE_RUN_FAILS:-0}" = 1 ] && exit 125
	net=bridge
	while [ $# -gt 0 ]; do [ "$1" = --network ] && net="$2"; shift; done
	echo "$net" >"$FAKE_STATE"
	;;
exec)
	if [ "$3" = systemctl ] && [ "${FAKE_HISTORY_INACTIVE:-0}" = 1 ]; then exit 3; fi
	if [ "$3" = journalctl ]; then
		[ "${FAKE_JOURNAL_FAILS:-0}" = 1 ] && exit 1
		echo "journal line of the old container"
	fi
	;;
inspect) echo "${FAKE_NETMODE:-$(cat "$FAKE_STATE" 2>/dev/null || echo none)}" ;;
esac
exit 0
FAKE
chmod +x "$tmp/docker"
drun() { # extra environment as arguments, e.g. FAKE_RUN_FAILS=1
	: >"$tmp/log"
	rm -f "$tmp/state"
	env -u INCUS_HOST PATH="$tmp:$PATH" FAKE_LOG="$tmp/log" FAKE_STATE="$tmp/state" \
		RESET_RUNTIME=docker E2E_IMAGE=clamfleet-e2e:test "$@" \
		"$iso/reset.sh" >"$tmp/out" 2>&1 </dev/null
}

drun || { echo "FAIL: the Docker reset failed on a healthy run (INCUS_HOST must not be needed)" >&2; cat "$tmp/out" >&2; exit 1; }
grep -q 'DOCKER: exec clamfleet-ci clamdscan --no-summary /etc/hostname' "$tmp/log" || { echo "FAIL: Docker readiness is not a real scan" >&2; cat "$tmp/log" >&2; exit 1; }
run_line="$(grep '^DOCKER: run ' "$tmp/log")"
case "$run_line" in
*"--network none"*) ;;
*) echo "FAIL: docker run is not given --network none: $run_line" >&2; exit 1 ;;
esac
case "$run_line" in
*"--name clamfleet-ci"*"clamfleet-e2e:test") ;;
*) echo "FAIL: docker run does not start the image under the default name: $run_line" >&2; exit 1 ;;
esac
# The old container is removed first, so no state of an earlier test survives.
[ "$(grep -n '^DOCKER:' "$tmp/log" | head -1 | cut -d' ' -f2-3)" = "rm -f" ] || { echo "FAIL: the old container is not removed first" >&2; exit 1; }

if drun FAKE_RUN_FAILS=1; then
	echo "FAIL: the Docker reset succeeded although docker run failed" >&2
	exit 1
fi
if grep -q 'clamdscan' "$tmp/log"; then
	echo "FAIL: the Docker reset waited for clamd after a failed docker run" >&2
	exit 1
fi

if drun FAKE_NETMODE=bridge; then
	echo "FAIL: the Docker reset accepted a container with network mode bridge" >&2
	exit 1
fi
grep -q "network mode 'bridge'" "$tmp/out" || { echo "FAIL: the refusal does not name the network mode" >&2; cat "$tmp/out" >&2; exit 1; }
if grep -q 'clamdscan' "$tmp/log"; then
	echo "FAIL: the Docker reset scanned inside a container that has a network" >&2
	exit 1
fi

# The journal of the container that is replaced is kept, when asked; and a journal that cannot be
# read (no container yet) neither fails the reset nor leaves an empty file behind.
jd="$tmp/journals"
drun E2E_JOURNAL_DIR="$jd" || { echo "FAIL: the Docker reset failed with E2E_JOURNAL_DIR set" >&2; cat "$tmp/out" >&2; exit 1; }
grep -rq 'journal line of the old container' "$jd" || { echo "FAIL: the old container's journal was not saved" >&2; exit 1; }
[ "$(grep -n 'journalctl' "$tmp/log" | cut -d: -f1)" -lt "$(grep -n 'DOCKER: rm -f' "$tmp/log" | cut -d: -f1)" ] || { echo "FAIL: the journal is read after the container was removed" >&2; exit 1; }
rm -rf "$jd"
drun E2E_JOURNAL_DIR="$jd" FAKE_JOURNAL_FAILS=1 || { echo "FAIL: an unreadable journal stopped the Docker reset" >&2; exit 1; }
[ -z "$(ls -A "$jd")" ] || { echo "FAIL: an unreadable journal left a file behind" >&2; exit 1; }
drun || { echo "FAIL: the Docker reset failed without E2E_JOURNAL_DIR" >&2; exit 1; }
if grep -q 'journalctl' "$tmp/log"; then
	echo "FAIL: the journal was read without E2E_JOURNAL_DIR" >&2
	exit 1
fi

# The exit trap of `make e2e-docker` runs save-journal.sh on its own, for the container that is still
# there when the run is killed or times out: it must save that journal, and never fail.
: >"$tmp/log"; rm -rf "$jd"
PATH="$tmp:$PATH" FAKE_LOG="$tmp/log" CT=clamfleet-ci E2E_JOURNAL_DIR="$jd" "$iso/save-journal.sh" || { echo "FAIL: save-journal.sh failed" >&2; exit 1; }
grep -rq 'journal line of the old container' "$jd" || { echo "FAIL: save-journal.sh did not save the last container's journal" >&2; exit 1; }
rm -rf "$jd"
PATH="$tmp:$PATH" FAKE_LOG="$tmp/log" FAKE_JOURNAL_FAILS=1 E2E_JOURNAL_DIR="$jd" "$iso/save-journal.sh" || { echo "FAIL: save-journal.sh failed on an unreadable journal" >&2; exit 1; }
[ -z "$(ls -A "$jd")" ] || { echo "FAIL: save-journal.sh left a file for a journal it could not read" >&2; exit 1; }

# And the Makefile's trap really does it, before the container is removed.
grep -qE "trap '[^']*save-journal\\.sh[^']*docker rm" "$here/../../Makefile" || { echo "FAIL: make e2e-docker's exit trap does not save the journal before removing the container" >&2; exit 1; }

# Ready also means the replay of the recorded freshclam history has finished.
if drun FAKE_HISTORY_INACTIVE=1 TIMEOUT=3; then
	echo "FAIL: the Docker reset was ready while the freshclam history replay was not active" >&2
	exit 1
fi
if grep -q 'clamdscan' "$tmp/log"; then
	echo "FAIL: the Docker reset scanned before the freshclam history replay was active" >&2
	exit 1
fi

# READY_UNIT names another replay unit, and an empty one drops the wait (an image without the unit:
# the L2 distribution images). Without the empty case such an image would never become "ready".
drun READY_UNIT=other-replay.service || { echo "FAIL: the Docker reset failed with READY_UNIT set" >&2; cat "$tmp/out" >&2; exit 1; }
grep -q 'DOCKER: exec clamfleet-ci systemctl is-active --quiet other-replay.service' "$tmp/log" || { echo "FAIL: READY_UNIT is not the unit waited for" >&2; cat "$tmp/log" >&2; exit 1; }
drun READY_UNIT= FAKE_HISTORY_INACTIVE=1 TIMEOUT=3 || { echo "FAIL: an empty READY_UNIT still waited for a replay unit" >&2; cat "$tmp/out" >&2; exit 1; }
if grep -q 'systemctl' "$tmp/log"; then
	echo "FAIL: an empty READY_UNIT still asked systemd about a unit" >&2
	exit 1
fi
grep -q 'clamdscan --no-summary' "$tmp/log" || { echo "FAIL: an empty READY_UNIT skipped the scan too" >&2; exit 1; }

if drun E2E_IMAGE=; then
	echo "FAIL: the Docker reset ran without E2E_IMAGE" >&2
	exit 1
fi
if drun RESET_RUNTIME=podman; then
	echo "FAIL: an unknown RESET_RUNTIME was accepted" >&2
	exit 1
fi
# The Incus runtime still needs INCUS_HOST.
if env -u INCUS_HOST PATH="$tmp:$PATH" FAKE_LOG="$tmp/log" "$iso/reset.sh" >"$tmp/out" 2>&1 </dev/null; then
	echo "FAIL: the Incus reset ran without INCUS_HOST" >&2
	exit 1
fi
grep -q 'INCUS_HOST' "$tmp/out" || { echo "FAIL: the Incus refusal does not mention INCUS_HOST" >&2; exit 1; }
echo "reset_test: ok"
