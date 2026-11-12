#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# prepare-server.sh - create the server user, state directory and config in the
# clamfleet-test container, the way a package will on a real host.
#
# Creates system user "clamfleet-server" (no shell, no home), the state
# directory /var/lib/clamfleet-server (0700, owned by it) and
# /etc/clamfleet/server.yaml from deploy/test/server.yaml. The server is a
# different user from the agent's "clamfleet" on purpose: an agent and a
# server on one host must not share an identity or a directory.
# Certificates, the binary and the running unit are the test suite's business.
# Idempotent. reset.sh restores a snapshot that predates all of this, so run
# it again after every reset.
# Env: CFT_EXEC (required), the command prefix that runs a command inside the
#      container; set it in the environment or deploy/test/local.env.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Maintainer-specific names live in the gitignored local.env, never in the repo.
[ -f "$here/local.env" ] && . "$here/local.env"
CFT_EXEC="${CFT_EXEC:?set CFT_EXEC (environment or deploy/test/local.env), see docs/testing.md}"

{
	cat <<'REMOTE'
set -euo pipefail
getent passwd clamfleet-server >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin clamfleet-server
install -d -o clamfleet-server -g clamfleet-server -m 700 /var/lib/clamfleet-server
install -d -m 755 /etc/clamfleet
cat > /etc/clamfleet/server.yaml <<'YAML'
REMOTE
	cat "$here/server.yaml"
	printf 'YAML\nchmod 644 /etc/clamfleet/server.yaml\n'
} | $CFT_EXEC bash -s
echo "prepare-server: ok"
