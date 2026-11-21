#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# prepare-agent.sh - create the unprivileged agent user and config in the
# clamfleet-test container, the way the .deb will on a real host.
#
# Creates system user "clamfleet" (supplementary groups clamav and
# systemd-journal, no shell, no home), /var/lib/clamfleet (clamfleet:clamav 0750)
# and the spool directory under it (clamfleet:clamav 2750), the way the package will,
# and /etc/clamfleet/agent.yaml from deploy/test/agent.yaml.
#
# The group is clamav because clamd runs the VirusEvent command as its own user
# and that user must reach spool/events: /var/lib/clamfleet and spool/ only need
# to be traversable by the group (r-x), the setgid bit makes the subdirectories
# inherit it, and `run` creates spool/events (3770, sticky) and the agent-only
# directories itself.
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
install -d -o clamfleet -g clamav -m 750 /var/lib/clamfleet
install -d -o clamfleet -g clamav -m 2750 /var/lib/clamfleet/spool
install -d -m 755 /etc/clamfleet
cat > /etc/clamfleet/agent.yaml <<'YAML'
REMOTE
	cat "$here/agent.yaml"
	printf 'YAML\nchmod 644 /etc/clamfleet/agent.yaml\n'
} | $CFT_EXEC bash -s
echo "prepare-agent: ok"
