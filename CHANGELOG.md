<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Changelog

All notable changes are listed here. The format follows Keep a Changelog; versions follow SemVer.

## Unreleased

### Added
- Milestone 1: shared payload structs (`internal/proto`), agent collectors (clamd socket, CVD/CLD
  headers, freshclam, systemd units, host, last scan) and `clamfleet-agent collect --dry-run`.
- `freshclam.source` in the report (`journal`, `log`, `journal+log`, `mtime`, or null). Additive, schema stays 1.

### Changed
- Agent environment variables use the prefix `CLAMFLEET_AGENT_` (config file: `CLAMFLEET_AGENT_CONFIG`),
  leaving `CLAMFLEET_SERVER_` for the server. This differs from HANDOVER section 12.
