// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadLastScan(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good.json", `{"started":"2026-11-12T02:00:00+01:00","finished":"2026-11-12T02:41:10Z","exit":1,"scanned":120345,"infected":2,"errors":3}`)
	s, p := readLastScan(good)
	if p != nil || s == nil || s.Scanned != 120345 || s.Infected != 2 || s.Exit != 1 {
		t.Fatalf("good: %+v %v", s, p)
	}
	if got := s.Started.Format("2006-01-02T15:04:05Z07:00"); got != "2026-11-12T01:00:00Z" {
		t.Fatalf("started not normalised to UTC: %s", got)
	}
	// Missing: no scan configured, so null and NO problem.
	if s, p := readLastScan(filepath.Join(dir, "absent.json")); s != nil || p != nil {
		t.Fatalf("missing: %+v %v", s, p)
	}
	for name, content := range map[string]string{"bad.json": "{not json", "empty.json": "{}"} {
		if s, p := readLastScan(write(name, content)); s != nil || p == nil {
			t.Errorf("%s: got %+v %v, want nil plus a problem", name, s, p)
		}
	}
}
