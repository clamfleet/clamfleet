<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Recorded freshclam history

`freshclam.log` and `freshclam-journal.txt` are one real freshclam run of the Incus test container
(Debian 13, ClamAV 1.4.3), scrubbed of private names. They cannot carry a licence header (recorded
text): **this note is their licence statement, AGPL-3.0-only, copyright The ClamFleet Authors**.

The CI image has no network and never runs freshclam, but three e2e tests take the Incus snapshot's
one freshclam run as their premise. The Dockerfile installs `freshclam.log` as a file (`clamav:clamav`
640) and `replay-freshclam-history.sh` writes the journal lines at boot as entries of the
`clamav-freshclam` unit.

Re-record with `make record-freshclam-history` (needs the Incus suite's settings). Never hand-edit.
