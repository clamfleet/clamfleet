#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# save-journal.sh - write the journal of the e2e Docker container to $E2E_JOURNAL_DIR, named by the
# current time. Used by reset.sh before it replaces a container, and by `make e2e-docker`'s exit trap
# before it removes the last one (a timeout or a cancelled job kills the suite before any further
# reset, and that last container is the one that failed). Best effort, never fails: with no
# E2E_JOURNAL_DIR it does nothing, and a container that is gone leaves no file.
# Env: E2E_JOURNAL_DIR, CT (default clamfleet-ci).
set -uo pipefail
[ -n "${E2E_JOURNAL_DIR:-}" ] || exit 0
CT="${CT:-clamfleet-ci}"
mkdir -p "$E2E_JOURNAL_DIR"
j="$E2E_JOURNAL_DIR/$(date -u +%Y%m%dT%H%M%S.%N).$CT.journal"
docker exec "$CT" journalctl --no-pager -o short-iso </dev/null >"$j" 2>/dev/null || rm -f "$j"
exit 0
