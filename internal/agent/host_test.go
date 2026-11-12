// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/clamfleet/clamfleet/internal/proto"
)

func TestParseOSRelease(t *testing.T) {
	for file, want := range map[string]proto.OS{
		"debian13/os-release":            {ID: "debian", Version: "13"},
		"handmade/os-release.rhel9":      {ID: "rhel", Version: "9.4"},
		"handmade/os-release.debian-sid": {ID: "debian", Version: ""},
	} {
		if got := ParseOSRelease(fixture(t, file)); got != want {
			t.Errorf("%s: got %+v want %+v", file, got, want)
		}
	}
	if got := ParseOSRelease([]byte("ID='alma'\nVERSION_ID='9.3'\n")); got.ID != "alma" || got.Version != "9.3" {
		t.Errorf("single quotes: %+v", got)
	}
}

func TestReadOSReleaseFallsBackToSecondPath(t *testing.T) {
	dir := t.TempDir()
	second := filepath.Join(dir, "usr-lib-os-release")
	if err := os.WriteFile(second, []byte("ID=alpine\nVERSION_ID=3.20\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readOSRelease([]string{filepath.Join(dir, "missing"), second})
	if err != nil || got.ID != "alpine" {
		t.Fatalf("got %+v %v", got, err)
	}
	if _, err := readOSRelease([]string{filepath.Join(dir, "missing")}); err == nil {
		t.Fatal("no file must be an error")
	}
}
