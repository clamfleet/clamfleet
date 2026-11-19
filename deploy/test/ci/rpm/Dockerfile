# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# The level-2 container of the RHEL family legs (docs/testing.md, "The distribution containers"):
# Rocky Linux 9 and AlmaLinux 10 with systemd as PID 1, ClamAV from EPEL and a frozen copy of the
# signature databases.
#
# One file for both releases: the build argument LEG picks the base (`make e2e-l2-image LEG=...`),
# the install steps are identical. A container shares the runner's kernel, which has no SELinux
# enforcing for it, so this level checks installation, units, groups, modes and the static policy
# comparison (the module with and without), never confinement (level 1, on VMs). The policy
# packages are installed for that static comparison: sesearch, semodule and the policy store.
#
# ClamAV floor: clamd >= 1.4 (the release's claim); EPEL 9 and 10 carry 1.4.x. The build fails
# below if the repository ever resolves older.
#
# The signatures come from the official ClamAV image, the same digest as ../Dockerfile (pinned in
# every Dockerfile: deploy/test/ci/signatures_test.sh fails when they differ) and are never
# updated: freshclam is not run and its unit is disabled (not masked: one scenario starts it with
# a drop-in). Dependabot moves the digests monthly (.github/dependabot.yml).
#
# No network at test time: the scenarios install the two ClamFleet packages with dnf, whose
# dependencies (clamd, systemd) are already here, so every repository is disabled at the end of the
# build. A dnf that still tried the mirrors would fail the suite for a reason that looks like ours.
#
# A CI fixture, built in the job and never pushed (M6 decision 13).

ARG LEG=rocky-9

FROM clamav/clamav-debian:1.5.4@sha256:6982509b9e1415bf23cb49d0c55872fdd57fd2b92be33fa26d487da42d322076 AS signatures

# The org's own repository: the library `rockylinux` is the deprecated name of the same image.
FROM rockylinux/rockylinux:9@sha256:bb5755f96bec05ff26165e779ec843d7167544be9e50770508f307019a6d05c4 AS base-rocky-9
FROM almalinux:10@sha256:ccf217024b3d5e268cc208d1edb384a1edee6359370cf6ea1ecbc42254e57375 AS base-almalinux-10

FROM base-${LEG}

ENV container=docker

# epel-release is in the extras repository of both. Tools the suite calls inside the container:
# ps (procps-ng), ss (iproute), cmp (diffutils), sudo and visudo, getenforce (libselinux-utils),
# semodule (policycoreutils) and sesearch (setools-console) with the targeted policy store they read.
# curl is already there (curl-minimal on Rocky: do not install `curl`, it conflicts).
# The clamav-update name of older docs is not an EPEL 9 or 10 package: freshclam is clamav-freshclam.
RUN dnf install -y epel-release \
 && dnf install -y --setopt=install_weak_deps=False \
        systemd clamd clamav clamav-freshclam \
        sudo procps-ng iproute util-linux diffutils shadow-utils logrotate \
        selinux-policy-targeted policycoreutils libselinux-utils setools-console \
 && dnf clean all

# The version floor (see the header). clamd prints "ClamAV 1.4.6/27xxx/date".
RUN set -eu; \
    v=$(clamd --version | sed -n 's|^ClamAV \([0-9]*\)\.\([0-9]*\)\..*|\1 \2|p'); \
    set -- $v; \
    [ "${1:-0}" -gt 1 ] || { [ "${1:-0}" -eq 1 ] && [ "${2:-0}" -ge 4 ]; } \
 || { echo "clamd is older than 1.4 (got: $(clamd --version))" >&2; exit 1; }

# Never `freshclam` here (see the header). EPEL owns /var/lib/clamav as clamupdate, not clamav, and
# its clamav-data package ships stub databases: they go first so a stub .cvd cannot sit beside a
# .cld of the same name. Only the database files are copied, from a bind mount so no layer carries
# the rest of the image.
RUN --mount=type=bind,from=signatures,source=/var/lib/clamav,target=/sig \
    set -eu; \
    rm -f /var/lib/clamav/*.cvd /var/lib/clamav/*.cld; \
    for f in /sig/*.cvd /sig/*.cld; do [ -e "$f" ] || continue; install -o clamupdate -g clamupdate -m 0644 "$f" /var/lib/clamav/; done; \
    ls /var/lib/clamav/main.c[vl]d /var/lib/clamav/daily.c[vl]d /var/lib/clamav/bytecode.c[vl]d >/dev/null

# clamd's socket: the stock scan.conf has LocalSocket commented out and the package never edits it
# (docs/testing.md, "The AlmaLinux 9 VM"). The preset does not enable clamd@scan, so enable it here;
# freshclam stays off (see the header).
RUN set -eu; \
    sed -i 's|^#LocalSocket /run/clamd.scan/clamd.sock|LocalSocket /run/clamd.scan/clamd.sock|' /etc/clamd.d/scan.conf; \
    grep -q '^LocalSocket /run/clamd.scan/clamd.sock$' /etc/clamd.d/scan.conf; \
    systemctl enable clamd@scan.service; \
    systemctl disable clamav-freshclam.service

# Offline from here on (see the header). Every [section] must end up with enabled=0: sed only
# rewrites a line that exists, so a section without one would stay enabled and fail the count.
RUN set -eu; \
    sed -i 's/^enabled=.*/enabled=0/' /etc/yum.repos.d/*.repo; \
    [ "$(cat /etc/yum.repos.d/*.repo | grep -c '^\[')" -eq "$(cat /etc/yum.repos.d/*.repo | grep -c '^enabled=0')" ]

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
