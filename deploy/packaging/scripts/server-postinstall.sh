#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# clamfleet-server postinstall (deb postinst / rpm %post). One script for both formats:
# deb "configure [previous-version]", rpm "1" (install) or "2" (upgrade). Every step is
# idempotent; a failing step exits non-zero and the package completes on the next
# `dpkg --configure -a` / `dnf reinstall`.
#
# The key file (decision 9): created only on the FIRST install and only if it is absent,
# so an upgrade or a re-run never replaces the key that protects stored secrets (replacing
# it would make every sealed TOTP secret and webhook URL unreadable). It lives outside the
# database on purpose: back it up separately (docs/operations.md).
#
# An upgrade restarts the server, which migrates the database; the server writes a
# verified backup first and refuses to migrate when that fails.
ETC_DIR=/etc/clamfleet
KEY_FILE=/etc/clamfleet/server-secret.key
SYSUSERS=/usr/lib/sysusers.d/clamfleet-server.conf
TMPFILES=/usr/lib/tmpfiles.d/clamfleet-server.conf
SERVER_BIN=/usr/bin/clamfleet-server
SD_RUN=/run/systemd/system

set -eu

# Runtime actions need a booted systemd; enable and preset work offline (a chroot, a container
# image build), so a package can still be installed there.
sd() {
	if [ -d "$SD_RUN" ]; then systemctl "$@"; fi
}

case "${1:-}" in
	configure) fmt=deb; if [ -z "${2:-}" ]; then first=1; else first=0; fi ;;
	1) fmt=rpm; first=1 ;;
	2) fmt=rpm; first=0 ;;
	*) echo "clamfleet-server: unexpected argument '${1:-}'" >&2; exit 1 ;;
esac

systemd-sysusers "$SYSUSERS"
systemd-tmpfiles --create "$TMPFILES"

# The configuration ships root:root 0640 (the group does not exist before this script runs
# on a first install, and dpkg cannot chown to a missing group). Give it to the server
# group now, on every run, because a changed packaged file replaces it with root:root.
if [ -e "$ETC_DIR/server.yaml" ]; then
	chgrp clamfleet-server "$ETC_DIR/server.yaml"
	chmod 0640 "$ETC_DIR/server.yaml"
fi

if [ "$first" = 1 ] && [ ! -e "$KEY_FILE" ]; then
	"$SERVER_BIN" key generate --file "$KEY_FILE"
	chgrp clamfleet-server "$KEY_FILE"
	chmod 0640 "$KEY_FILE"
fi

sd daemon-reload

if [ "$first" = 1 ]; then
	if [ "$fmt" = deb ]; then
		systemctl enable clamfleet-server.service
		sd start clamfleet-server.service || echo "clamfleet-server: could not start the service now; see 'systemctl status clamfleet-server'" >&2
	else
		systemctl preset clamfleet-server.service
	fi
else
	sd try-restart clamfleet-server.service
fi

if [ "$first" = 1 ]; then
	cat >&2 <<NOTICE
clamfleet-server: installed. Next steps (docs: /usr/share/doc/clamfleet-server/):
  1. Review $ETC_DIR/server.yaml. The default listens on 127.0.0.1:8443 in plaintext: put a reverse
     proxy with TLS in front, or set tls.cert and tls.key.
  2. Admin commands run as the server user: sudo -u clamfleet-server clamfleet-server host add NAME
                                            sudo -u clamfleet-server clamfleet-server user add EMAIL --role admin
  3. The secret key file is $KEY_FILE. Back it up apart from the database backups:
     without it, stored TOTP secrets and webhook URLs cannot be opened.
  4. Optional: systemctl enable --now clamfleet-server-backup.timer (daily database backup).
NOTICE
	if [ "$fmt" = rpm ]; then
		echo "  (RHEL family: the service follows the system preset; start it with: systemctl enable --now clamfleet-server)" >&2
	fi
fi
exit 0
