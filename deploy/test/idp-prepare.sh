#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# idp-prepare.sh - return the clamfleet-idp container (milestone 6b, `make e2e-idp`) to its `clean`
# snapshot and wait until both identity providers answer. The suite calls it before every scenario
# and once more at the end, so the container is left as it was found.
#
# What the container holds (Debian 13, an Incus container made by the sysadmin agent; it is NOT
# built by this script, see docs/testing.md "The IdP container" for its contents and for how it was
# made). Everything listens on the container's loopback only:
#   - OpenLDAP (slapd) on ldap://127.0.0.1:389 with StartTLS, the memberOf overlay and a test CA in
#     /etc/clamfleet-idp/ca.crt; base dc=example,dc=test; users alice, bob, carol; groups
#     clamfleet-admins (alice) and clamfleet-viewers (bob); a read-only service account;
#   - Keycloak (start-dev) on http://127.0.0.1:8080, realm "clamfleet", a confidential client
#     "clamfleet" with PKCE S256 required and a groups mapper; the same three users.
# All the credentials are test-only and live in the suite (e2e/idp_e2e_test.go), not here.
#
# Needs ssh to the Incus host with passwordless sudo for incus.
# Env: INCUS_HOST (required: ssh target of the Incus host; environment or deploy/test/local.env),
#      CT (default clamfleet-idp), SNAP (default clean), TIMEOUT (seconds, default 240: Keycloak's
#      dev mode takes about a minute to come up after a restore).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Maintainer-specific names live in the gitignored local.env, never in the repo.
[ -f "$here/local.env" ] && . "$here/local.env"
CT="${CT:-clamfleet-idp}"
SNAP="${SNAP:-clean}"
INCUS_HOST="${INCUS_HOST:?set INCUS_HOST (environment or deploy/test/local.env), see docs/testing.md}"
TIMEOUT="${TIMEOUT:-240}"

start=$(date +%s)
# </dev/null: incus over ssh misbehaves when it inherits stdin. A failed restore must fail the
# script (the braces matter, see reset.sh); only the start may fail, harmlessly, when it runs already.
ssh "$INCUS_HOST" "sudo incus snapshot restore $CT $SNAP </dev/null && { sudo incus start $CT </dev/null 2>/dev/null || true; }"

# Ready means both providers ANSWER, not that systemd says "active": Keycloak is "active" long
# before its realm is served. One ssh call per attempt, retried to the deadline: a just-restored
# container has no working `incus exec` for a moment, which counts as "not ready yet".
probe='systemctl is-active --quiet slapd && systemctl is-active --quiet keycloak && curl -fsS -o /dev/null http://127.0.0.1:8080/realms/clamfleet/.well-known/openid-configuration && ldapsearch -Y EXTERNAL -H ldapi:/// -b dc=example,dc=test -s base -LLL dn >/dev/null 2>&1'
deadline=$(( start + TIMEOUT ))
until ssh "$INCUS_HOST" "sudo incus exec $CT -- bash -c '$probe' </dev/null >/dev/null 2>&1"; do
	if [ "$(date +%s)" -ge "$deadline" ]; then
		echo "idp-prepare: OpenLDAP and Keycloak did not both answer within ${TIMEOUT}s" >&2
		exit 1
	fi
	sleep 3
done
echo "idp-prepare: $CT ready in $(( $(date +%s) - start ))s"
