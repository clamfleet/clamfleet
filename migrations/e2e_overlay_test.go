//go:build e2e_migration

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package migrations

import (
	"io/fs"
	"testing"
)

// With the tag the set is the production one plus exactly one extra migration.
func TestOverlayAddsOneMigration(t *testing.T) {
	got, _ := fs.Glob(FS(), "sqlite/*.sql")
	if len(got) != 8 || got[7] != "sqlite/00008_e2e_overlay.sql" {
		t.Fatalf("%v", got)
	}
}
