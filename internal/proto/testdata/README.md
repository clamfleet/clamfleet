<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Payload samples

`report_7_3.json` and `event_7_4.json` are samples of the agent's report and event payloads
(`internal/proto`), read by `proto_test.go`. They cannot carry a licence header (JSON): **this
note is their licence statement, AGPL-3.0-only, copyright The ClamFleet Authors**.

The payload structs are a public interface (CLAUDE.md): a change that makes these samples fail to
round-trip needs a schema bump, not an edit of the samples.
