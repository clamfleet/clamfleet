//go:build e2e_migration

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package migrations

import (
	"io/fs"
	"testing/fstest"

	"github.com/clamfleet/clamfleet/internal/version"
)

// TEST ONLY. Built only with -tags e2e_migration, by the package upgrade e2e (e2e/package_e2e_test.go,
// TestDebFailedUpgradeLeavesDataAlone), to give the "new" package a schema change the "old" one lacks.
// It adds one additive migration and nothing else; no release is built with this tag.
func init() {
	// The tagged binary says so wherever the version is shown, so it cannot pass for a release build.
	version.Version += "+e2e_migration"
	overlay = func(base fs.FS) fs.FS {
		m := fstest.MapFS{}
		_ = fs.WalkDir(base, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, rerr := fs.ReadFile(base, p)
			if rerr != nil {
				return rerr
			}
			m[p] = &fstest.MapFile{Data: b}
			return nil
		})
		m["sqlite/00007_e2e_overlay.sql"] = &fstest.MapFile{Data: []byte("-- +goose Up\nCREATE TABLE e2e_overlay_marker (id INTEGER PRIMARY KEY);\n-- +goose Down\nDROP TABLE e2e_overlay_marker;\n")}
		return m
	}
}
