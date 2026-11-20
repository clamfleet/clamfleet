# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# The level-2 container of the Debian family legs (docs/testing.md, "The distribution containers"):
# Debian 12 and Ubuntu 22.04 with systemd as PID 1, the distribution's ClamAV and a frozen copy of
# the signature databases. Debian 13 stays with ../Dockerfile (the `e2e` job).
#
# One file for both releases: the build argument LEG picks the base (`make e2e-l2-image LEG=...`),
# the install steps are identical. A container shares the runner's kernel and has no MAC of its own,
# so this level checks installation, units, groups, modes and the static profile parse, never
# confinement (that is level 1, on VMs).
#
# ClamAV floor: the packages Depend on clamav-daemon and the suite needs clamd >= 1.4 (the
# release's claim). The release pocket of Ubuntu 22.04 carries 0.103.5; the image's default
# sources already include jammy-updates and jammy-security, which carry 1.5.x, and Debian 12 has
# 1.4.x in main. The build fails below if apt resolved anything older, instead of letting the
# suite fail later for a reason that looks like ours.
#
# The signatures come from the official ClamAV image, the same digest as ../Dockerfile (pinned
# in both: deploy/test/ci/signatures_test.sh fails when they differ) and are never updated:
# freshclam is not run and its unit is disabled (not masked: one scenario starts it with a
# drop-in). Dependabot moves the digests monthly (.github/dependabot.yml).
#
# A CI fixture, built in the job and never pushed (M6 decision 13). Freshclam history is not
# replayed: the e2e-distro target starts with an empty READY_UNIT, and the TestDistro* scenarios
# do not take a freshclam run as their premise.

ARG LEG=debian-12

FROM clamav/clamav-debian:1.5.4@sha256:6982509b9e1415bf23cb49d0c55872fdd57fd2b92be33fa26d487da42d322076 AS signatures

# Tags carry no date and move, so the pin is the digest; the tag is for the reader and Dependabot.
FROM debian:bookworm@sha256:268fb24c39bca92d326dd83ea3abebe4a3f7751c804ffef23bb6d857dd343ff8 AS base-debian-12
FROM ubuntu:jammy@sha256:9abcaffc92a5279fff3a6a41635c0800ea33e528425fb389658806476e7defde AS base-ubuntu-22.04

FROM base-${LEG}

ENV DEBIAN_FRONTEND=noninteractive \
    container=docker

# policy-rc.d (exit 101 = "do not start services") exists only while packages install, so no
# postinst tries to start clamd or freshclam in a build without systemd.
# The tools are what the suite calls inside the container: ss and ps for the listener and process
# assertions, curl for /healthz, sudo and visudo for the sudoers scenario, apparmor for
# apparmor_parser and aa-enabled (the static profile parse), diffutils for cmp. ca-certificates
# is not needed: there is no network and the tests bring their own CA.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
 && chmod 0755 /usr/sbin/policy-rc.d \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus \
        clamav clamav-daemon clamdscan clamav-freshclam \
        apparmor sudo curl iproute2 procps util-linux logrotate diffutils \
 && rm -f /usr/sbin/policy-rc.d \
 && rm -rf /var/lib/apt/lists/*

# The version floor (see the header). clamd prints "ClamAV 1.4.3/27xxx/date".
RUN set -eu; \
    v=$(clamd --version | sed -n 's|^ClamAV \([0-9]*\)\.\([0-9]*\)\..*|\1 \2|p'); \
    set -- $v; \
    [ "${1:-0}" -gt 1 ] || { [ "${1:-0}" -eq 1 ] && [ "${2:-0}" -ge 4 ]; } \
 || { echo "clamd is older than 1.4 (got: $(clamd --version))" >&2; exit 1; }

# Never `freshclam` here (see the header). Only the database files are copied, with the owner the
# package gives its own, from a bind mount so no layer carries the rest of the image. The detached
# .cvd.sign files go along: ClamAV 1.5 (Ubuntu 22.04's backport) refuses a .cvd without its .sign
# ("Unable to verify CVD with detached signature file", clamd exits 1), while 1.4 (Debian 12)
# ignores them.
# clamd is enabled explicitly: Debian's package enables it itself, but Ubuntu 22.04's backport of
# ClamAV 1.5 does not (its postinst only calls update-rc.d, no deb-systemd-helper), so the unit sat
# unloaded and nothing ever started it. The rpm image does the same for clamd@scan. Enabling is
# idempotent where the package already did it; the socket comes along through Also= in the unit.
RUN --mount=type=bind,from=signatures,source=/var/lib/clamav,target=/sig \
    set -eu; \
    for f in /sig/*.cvd /sig/*.cld /sig/*.sign; do [ -e "$f" ] || continue; install -o clamav -g clamav -m 0644 "$f" /var/lib/clamav/; done; \
    ls /var/lib/clamav/main.c[vl]d /var/lib/clamav/daily.c[vl]d /var/lib/clamav/bytecode.c[vl]d >/dev/null \
 && systemctl disable clamav-freshclam.service \
 && systemctl enable clamav-daemon.service

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
