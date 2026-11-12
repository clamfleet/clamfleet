// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package migrations embeds the goose SQL migrations.
//
// It is a package of its own, at the repository root, because go:embed can only
// reach files below the directory of the Go file that declares it, and the same
// .sql files are also the schema input of sqlc (sqlc.yaml). One directory per
// SQL dialect (today only sqlite) so a Postgres dialect can be added beside it
// without moving anything (spec 8.1).
package migrations

import "embed"

// SQLite holds the SQLite dialect migrations, under the "sqlite" directory.
//
//go:embed sqlite/*.sql
var SQLite embed.FS
