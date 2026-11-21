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

import (
	"embed"
	"io/fs"
)

// SQLite holds the SQLite dialect migrations, under the "sqlite" directory.
//
//go:embed sqlite/*.sql
var SQLite embed.FS

// overlay lets a build with the e2e_migration tag (migrations/e2e_overlay.go) add a test-only
// migration on top of the embedded set. It is nil in every production build.
var overlay func(base fs.FS) fs.FS

// FS is the migration set the store runs: SQLite, plus the test overlay in a build that has one.
// The upgrade e2e needs two builds of the same code that differ by one migration; the production
// set must not change for that, so the extra migration exists only under the build tag.
func FS() fs.FS {
	if overlay != nil {
		return overlay(SQLite)
	}
	return SQLite
}
