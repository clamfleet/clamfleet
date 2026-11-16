# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# The ClamAV container of the e2e suite in CI (docs/testing.md, "The e2e suite in Docker").
#
# What it is: Debian 13 with systemd as PID 1, the distribution's ClamAV (the same packages as the
# Incus snapshot `clean-clamav`) and a frozen copy of the signature databases. The suite needs a real
# systemd (systemctl, journalctl, systemd-run, the packages' units), which is why this is not the
# official ClamAV image: that one has no init system, and the agent asks systemd about clamd's unit.
#
# The signatures come from the official ClamAV image, pinned by digest below, and are never updated:
# freshclam is not run here and its unit is disabled (not masked: one scenario starts it with a
# drop-in). Frozen signatures keep the suite deterministic and keep CI off the ClamAV CDN, which
# rate-limits shared GitHub addresses. Dependabot moves both digests monthly (.github/dependabot.yml).
#
# The image is a CI fixture, built in the job and never pushed (M6 decision 13: no container image
# is a product of v1).
#
# TODO(S1 spike, open decision): the Incus snapshot `clean-clamav` has one real freshclam run behind
# it (an entry in clamav-freshclam's journal and a freshclam.log), and three e2e tests take that as
# their premise: TestHealthyHost, TestFreshclamFailingThenStopped and
# TestFreshclamLogUnreadableAfterRotation. This image has no such history (freshclam is never run
# here), so on it those three fail and the other 27 pass. Until the maintainer decides how they are
# served in CI, do not add an `e2e` job that runs this image.

# Only the databases are taken from this stage. Its tags carry no date and are rebuilt daily, so the
# pin is the digest; the tag is there for the reader and for Dependabot.
FROM clamav/clamav-debian:1.5.4@sha256:6982509b9e1415bf23cb49d0c55872fdd57fd2b92be33fa26d487da42d322076 AS signatures

FROM debian:trixie@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6

ENV DEBIAN_FRONTEND=noninteractive \
    container=docker

# policy-rc.d (exit 101 = "do not start services") is present only while packages install, so that
# no postinst tries to start clamd or freshclam in a build without systemd.
# The tools are the ones the suite calls inside the container: ss and ps for the listener and
# process assertions, curl for /healthz, runuser and mount from util-linux. ca-certificates is not
# needed: there is no network and the tests bring their own CA.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
 && chmod 0755 /usr/sbin/policy-rc.d \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus \
        clamav clamav-daemon clamdscan clamav-freshclam \
        curl iproute2 procps util-linux \
 && rm -f /usr/sbin/policy-rc.d \
 && rm -rf /var/lib/apt/lists/*

# Never `freshclam` here (see the header). Only the three database files are copied, with the
# owner the package gives its own, from a bind mount so no layer carries the rest of the image.
RUN --mount=type=bind,from=signatures,source=/var/lib/clamav,target=/sig \
    set -eu; \
    for f in /sig/*.cvd /sig/*.cld; do [ -e "$f" ] || continue; install -o clamav -g clamav -m 0644 "$f" /var/lib/clamav/; done; \
    ls /var/lib/clamav/main.c[vl]d /var/lib/clamav/daily.c[vl]d /var/lib/clamav/bytecode.c[vl]d >/dev/null \
 && systemctl disable clamav-freshclam.service

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
