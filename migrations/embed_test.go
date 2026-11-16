//go:build !e2e_migration

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package migrations

import (
	"io/fs"
	"testing"
)

// The production migration set has no overlay: FS() is exactly the embedded files, so a test-only
// migration can never ship (it needs -tags e2e_migration, which no release build uses).
func TestProductionSetHasNoOverlay(t *testing.T) {
	if overlay != nil {
		t.Fatal("an overlay is set in a build without the e2e_migration tag")
	}
	got, err := fs.Glob(FS(), "sqlite/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := fs.Glob(SQLite, "sqlite/*.sql")
	if len(got) != len(want) || len(got) != 6 {
		t.Fatalf("FS() lists %v, the embedded set %v: want the six production migrations", got, want)
	}
}
