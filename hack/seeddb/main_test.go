// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/store/sqlite"
)

var t0 = "2031-03-04T12:00:00Z"

func counts(t *testing.T, path string) Expected {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var e Expected
	for q, dst := range map[string]*int{
		`SELECT count(*) FROM reports`: &e.Reports, `SELECT count(*) FROM events`: &e.Events,
		`SELECT count(*) FROM state_changes`: &e.StateChanges, `SELECT count(*) FROM audit_log`: &e.Audit,
		`SELECT count(*) FROM alert_log`: &e.AlertLog,
	} {
		if err := db.QueryRow(q).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// The manifest is TRUE: seeding and then pruning with the default cutoffs and with
// reports_days 14, by the real store, leaves exactly the rows the tool says. If the
// seeded ages and the guards drift apart, this fails before an e2e does.
func TestManifestMatchesTheRealPrunes(t *testing.T) {
	ctx := context.Background()
	now, _ := time.Parse(time.RFC3339, t0)
	for _, c := range []struct {
		name    string
		reports int // retention.reports_days
		field   func(Manifest) Expected
	}{
		{"defaults", 30, func(m Manifest) Expected { return m.AfterDefaults }},
		{"reports_days 14", 14, func(m Manifest) Expected { return m.AfterReports14 }},
	} {
		path := filepath.Join(t.TempDir(), "seed.db")
		var out bytes.Buffer
		if err := run([]string{"--db", path, "--now", t0}, &out); err != nil {
			t.Fatal(err)
		}
		var m Manifest
		if err := json.Unmarshal(out.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		if got := counts(t, path); got != m.Seeded {
			t.Fatalf("%s: seeded %+v, manifest says %+v", c.name, got, m.Seeded)
		}
		st, err := sqlite.Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		day := func(n int) time.Time { return now.Add(-time.Duration(n) * 24 * time.Hour) }
		for _, p := range []func() (int64, error){
			func() (int64, error) { return st.PruneEvents(ctx, day(365), 100) },
			func() (int64, error) { return st.PruneStateChanges(ctx, day(365), 100) },
			func() (int64, error) { return st.PruneReports(ctx, day(c.reports), 100) },
			func() (int64, error) { return st.PruneAlertHistory(ctx, day(90), 100) },
			func() (int64, error) { return st.PruneAudit(ctx, day(365), 100) },
		} {
			if _, err := p(); err != nil {
				t.Fatal(err)
			}
		}
		st.Close()
		if got, want := counts(t, path), c.field(m); got != want {
			t.Errorf("%s: after the prunes %+v, manifest says %+v", c.name, got, want)
		}
	}
}

func TestSeeddbRefusesWhatItShouldNotDo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	if err := run([]string{"--db", path}, &bytes.Buffer{}); err == nil {
		t.Fatal("--now is required: there is no wall-clock default")
	}
	if err := run([]string{"--db", path, "--now", "yesterday"}, &bytes.Buffer{}); err == nil {
		t.Fatal("a bad --now was accepted")
	}
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"--db", path, "--now", t0}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "never overwrites") {
		t.Fatalf("an existing database was not refused: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "precious" {
		t.Fatal("the existing file was changed")
	}
}
