<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Alert payload golden files

`*.golden.json` are the exact bytes of the alert payload, schema 1 (`internal/alert/payload.go`,
`docs/alerts.md`). They cannot carry a licence header (JSON): **this note is their licence
statement, AGPL-3.0-only, copyright The ClamFleet Authors**.

They are written by hand, not recorded: a change to one is a change to a public interface and
needs a schema decision (CLAUDE.md). Do not regenerate them to make a test pass.
