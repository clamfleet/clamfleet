#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# prepare-agent.sh - create the unprivileged agent user and config in the
# clamfleet-test container, the way the .deb will on a real host.
#
# Creates system user "clamfleet" (supplementary groups clamav and
# systemd-journal, no shell, no home), /var/lib/clamfleet owned by it, and
# /etc/clamfleet/agent.yaml from deploy/test/agent.yaml.
# Idempotent. reset.sh restores a snapshot that predates all of this, so run
# it again after every reset.
# Env: CFT_EXEC (required), the command prefix that runs a command inside the
#      container; set it in the environment or deploy/test/local.env.
# The remote script goes over stdin ("bash -s") because ssh re-parses
# arguments on the far side, which breaks quoting.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Maintainer-specific names live in the gitignored local.env, never in the repo.
[ -f "$here/local.env" ] && . "$here/local.env"
CFT_EXEC="${CFT_EXEC:?set CFT_EXEC (environment or deploy/test/local.env), see docs/testing.md}"

{
	cat <<'REMOTE'
set -euo pipefail
getent passwd clamfleet >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin clamfleet
usermod -a -G clamav,systemd-journal clamfleet
install -d -o clamfleet -g clamfleet -m 750 /var/lib/clamfleet
install -d -m 755 /etc/clamfleet
cat > /etc/clamfleet/agent.yaml <<'YAML'
REMOTE
	cat "$here/agent.yaml"
	printf 'YAML\nchmod 644 /etc/clamfleet/agent.yaml\n'
} | $CFT_EXEC bash -s
echo "prepare-agent: ok"
