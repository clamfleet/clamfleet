#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
# reset.sh - return the ClamFleet e2e test container to its clean ClamAV state.
#
# Two runtimes, chosen by RESET_RUNTIME:
#
# incus (default): restores Incus snapshot "clean-clamav" of the test container (or, with
#   CT and SNAP set, another instance such as the AppArmor VM) on the Incus host
#   (Debian 13, distro clamav + clamav-daemon + clamav-freshclam, signatures loaded).
#   Idempotent: restoring the same snapshot twice gives the same state.
#   Needs ssh to the Incus host with passwordless sudo for incus.
# docker (CI, `make e2e-docker`): removes the container and starts a new one from the image in
#   E2E_IMAGE (deploy/test/ci/Dockerfile). A new container is the whole reset: nothing of the
#   last test survives. It runs with NO network (--network none, asserted below), so nothing in
#   the suite can reach the ClamAV CDN or anything else; the binaries and packages go in over
#   `docker exec` stdin.
#
# Either way it then waits until clamd can really scan a file.
# Env: RESET_RUNTIME (incus|docker, default incus),
#      INCUS_HOST (required for incus only: ssh target of the Incus host; set it in the
#      environment or deploy/test/local.env),
#      E2E_IMAGE (required for docker: the image to run),
#      CT (instance; default clamfleet-test for incus, clamfleet-ci for docker),
#      SNAP (incus only, default clean-clamav), TIMEOUT (seconds, default 180),
#      READY_FILE (the file the readiness scan reads, default /etc/hostname),
#      READY_UNIT (docker only: a oneshot unit that must be active before the container counts as ready;
#      default the freshclam-history replay unit of the Debian 13 image, empty means "clamd scans" only,
#      for images that do not carry that unit: the distribution images of the L2 matrix),
#      E2E_JOURNAL_DIR (docker only: a directory that receives the journal of each container
#      just before it is replaced; unset keeps nothing).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Maintainer-specific names live in the gitignored local.env, never in the repo.
[ -f "$here/local.env" ] && . "$here/local.env"
RESET_RUNTIME="${RESET_RUNTIME:-incus}"
TIMEOUT="${TIMEOUT:-180}"
# The file the readiness scan reads. /etc/hostname is fine for the container; under AppArmor
# (the VM) clamd's profile does not allow it and the scan answers "Access denied", so the
# AppArmor suite sets READY_FILE to a path the profile allows (/var/lib/clamav/**).
READY_FILE="${READY_FILE:-/etc/hostname}"
# `${READY_UNIT-default}`, not `:-`: an explicitly empty READY_UNIT must stay empty.
READY_UNIT="${READY_UNIT-clamfleet-ci-freshclam-history.service}"

case "$RESET_RUNTIME" in
incus)
	CT="${CT:-clamfleet-test}"
	SNAP="${SNAP:-clean-clamav}"
	INCUS_HOST="${INCUS_HOST:?set INCUS_HOST (environment or deploy/test/local.env), see docs/testing.md}"
	;;
docker)
	CT="${CT:-clamfleet-ci}"
	E2E_IMAGE="${E2E_IMAGE:?set E2E_IMAGE (the image built by make e2e-image), see docs/testing.md}"
	;;
*)
	echo "reset: RESET_RUNTIME must be incus or docker, not '$RESET_RUNTIME'" >&2
	exit 1
	;;
esac

start=$(date +%s)
# </dev/null: incus over ssh misbehaves when it inherits stdin.
# A failed restore must fail the script. The braces matter: the old
# "restore && start || true" swallowed the restore status, and the suite then
# ran against whatever state the container happened to be in. Only the start
# (which fails harmlessly when the container is already running) may fail.
if [ "$RESET_RUNTIME" = incus ]; then
	ssh "$INCUS_HOST" "sudo incus snapshot restore $CT $SNAP </dev/null && { sudo incus start $CT </dev/null 2>/dev/null || true; }"
else
	# E2E_JOURNAL_DIR: keep the journal of the container that is about to be replaced. After a failed
	# test the container is gone by the time anyone looks (the next reset, or the suite's final one,
	# replaces it), and the journal is the only record of what systemd and clamd did. Best effort: a
	# first reset has no container, and a journal that cannot be read must not stop the run. The name
	# is the end time, so the files sort in the order the containers lived.
	"$here/save-journal.sh"
	# `rm -f` succeeds when there is no such container, and fails when the daemon is unreachable,
	# which must stop the run. A failed `run` stops it here too, before any readiness check: a
	# leftover container from an earlier run would otherwise pass the scan below.
	docker rm -f "$CT" >/dev/null </dev/null
	# --privileged: the suite mounts a tmpfs (TestEventFullStorage, the package purge test) and
	# systemd needs the cgroup tree. That is root on the runner VM, accepted because the VM is
	# discarded after the job, which has no secrets (docs/testing.md, "The e2e suite in Docker").
	# The cgroup and tmpfs flags are what the CI spike confirmed for systemd as PID 1.
	docker run -d --name "$CT" --network none --privileged --cgroupns=private \
		--tmpfs /run --tmpfs /run/lock "$E2E_IMAGE" >/dev/null </dev/null
	# The guarantee that makes "no test can reach the network" true is checked, not assumed.
	mode="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$CT")"
	if [ "$mode" != none ]; then
		echo "reset: $CT has network mode '$mode', not none" >&2
		exit 1
	fi
fi

# Readiness is a successful scan, not "clamdscan --ping": PONG arrives about 5 s
# before clamd has finished loading signatures (observed on Debian 13), and a
# report taken in that window says up=false. A scan needs the loaded engine.
# Same approach as waitClamd in the e2e suite.
#
# One call per attempt, retried until the deadline: a restored VM (the AppArmor suite
# uses this script with CT=<vm>) reboots, and `incus exec` fails until its guest agent
# is up, and a new Docker container fails `exec` until systemd has started clamd's socket;
# both must count as "not ready yet", not as a failure.
ready() {
	if [ "$RESET_RUNTIME" = incus ]; then
		ssh "$INCUS_HOST" "sudo incus exec $CT -- clamdscan --no-summary $READY_FILE </dev/null >/dev/null 2>&1"
	else
		# The image replays a recorded freshclam run into the journal at boot (deploy/test/ci): tests
		# read it, so "ready" means that oneshot has finished too, not only that clamd scans. An image
		# without the unit sets READY_UNIT empty, and only the scan counts.
		{ [ -z "$READY_UNIT" ] || docker exec "$CT" systemctl is-active --quiet "$READY_UNIT" </dev/null >/dev/null 2>&1; } &&
			docker exec "$CT" clamdscan --no-summary "$READY_FILE" </dev/null >/dev/null 2>&1
	fi
}
deadline=$(( start + TIMEOUT ))
until ready; do
	if [ "$(date +%s)" -ge "$deadline" ]; then
		echo "reset: clamd never became ready" >&2
		exit 1
	fi
	sleep 2
done
echo "reset: $CT ready in $(( $(date +%s) - start ))s"
