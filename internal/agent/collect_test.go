// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

var update = flag.Bool("update", false, "rewrite testdata/report.golden.json (review the diff by hand)")

var fixedNow = time.Date(2026, 11, 12, 10, 30, 45, 123_000_000, time.UTC)

// fakeSystemctl answers "systemctl show" for the three default units from the
// recorded outputs, and "journalctl" from the recorded journal.
func fakeSystemctl(t *testing.T, states map[string]string) ExecFunc {
	t.Helper()
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "journalctl":
			return fixture(t, "freshclam/journal-rerun.txt"), nil
		case "systemctl":
			unit := args[len(args)-1]
			f, ok := states[unit]
			if !ok {
				return nil, fmt.Errorf("unexpected unit %s", unit)
			}
			return fixture(t, "services/"+f+".show"), nil
		}
		return nil, fmt.Errorf("unexpected command %s", name)
	}
}

// fullTree lays out a host: databases, clamd.conf pointing at the fake
// socket, and a scan summary. It returns the collector and the fake clamd.
func fullTree(t *testing.T, states map[string]string) (*Collector, *fakeClamd) {
	t.Helper()
	root := t.TempDir()
	db := filepath.Join(root, "db")
	if err := os.Mkdir(db, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"daily", "main", "bytecode"} {
		writeDB(t, db, n+".cvd", fixture(t, "cvd/initial/"+n+".cvd.hdr"))
	}
	f := startFakeClamd(t, recordedSession(t))
	conf := filepath.Join(root, "clamd.conf")
	if err := os.WriteFile(conf, []byte("# test\nLocalSocket "+f.Path+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scan := filepath.Join(root, "last_scan.json")
	if err := os.WriteFile(scan, []byte(`{"started":"2026-11-12T02:00:00Z","finished":"2026-11-12T02:41:10Z","exit":0,"scanned":120345,"infected":0,"errors":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Tags = []string{"web", "prod"}
	cfg.ClamdConf, cfg.DBDir = conf, db
	cfg.FreshclamLog = filepath.Join(root, "absent.log")
	cfg.Scan.Summary = scan
	return &Collector{
		Cfg: cfg, Version: "0.1.0", Now: func() time.Time { return fixedNow }, Loc: time.UTC,
		Exec:           fakeSystemctl(t, states),
		Hostname:       func() (string, error) { return "app01", nil },
		OSReleasePaths: []string{filepath.Join("testdata", "debian13", "os-release")},
		ClamdTimeout:   testTimeout,
	}, f
}

var healthyUnits = map[string]string{
	"clamav-daemon": "clamd-active", "clamav-freshclam": "freshclam-inactive", "clamav-clamonacc": "clamonacc-inactive",
}

func TestCollectGolden(t *testing.T) {
	c, _ := fullTree(t, healthyUnits)
	r, problems, err := c.Collect(context.Background())
	if err != nil || len(problems) != 0 {
		t.Fatalf("err=%v problems=%v", err, problems)
	}
	got, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := filepath.Join("testdata", "report.golden.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("report differs from golden file (rerun with -update and review):\n%s", got)
	}
}

// The server judges STALE per agent from this number, so it must follow the
// configured interval, not a constant.
func TestCollectReportsConfiguredInterval(t *testing.T) {
	c, _ := fullTree(t, healthyUnits)
	c.Cfg.Interval = 90 * time.Second
	r, _, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.IntervalSeconds == nil || *r.IntervalSeconds != 90 {
		t.Fatalf("interval_seconds = %v, want 90", r.IntervalSeconds)
	}
}

func TestCollectEverythingMissingStillProducesAReport(t *testing.T) {
	cfg := DefaultConfig()
	root := t.TempDir()
	cfg.ClamdConf = filepath.Join(root, "nope.conf")
	cfg.DBDir = filepath.Join(root, "nodb")
	cfg.FreshclamLog = filepath.Join(root, "nolog")
	cfg.Scan.Summary = filepath.Join(root, "noscan.json")
	c := &Collector{
		Cfg: cfg, Version: "x", Now: func() time.Time { return fixedNow }, Loc: time.UTC,
		Exec:           func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("no systemd") },
		Hostname:       func() (string, error) { return "h", nil },
		OSReleasePaths: []string{filepath.Join(root, "nope")},
	}
	r, problems, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Tags == nil || r.Clamd.Up || r.Clamd.Version != nil || r.Sigs.Daily != nil || r.LastScan != nil || r.Freshclam.LastOK != nil {
		t.Fatalf("not degraded to nulls: %+v", r)
	}
	if r.Services != (proto.Services{Clamd: "unknown", Freshclam: "unknown", Clamonacc: "unknown"}) {
		t.Fatalf("services: %+v", r.Services)
	}
	sources := map[string]bool{}
	for _, p := range problems {
		sources[p.Source] = true
	}
	for _, s := range []string{"os", "services", "freshclam"} {
		if !sources[s] {
			t.Errorf("no problem recorded for %s: %v", s, problems)
		}
	}
	// The result must still be valid JSON with every key.
	raw, _ := json.Marshal(r)
	var back proto.Report
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&back); err != nil {
		t.Fatal(err)
	}
}

func TestCollectHostnameFailureIsFatal(t *testing.T) {
	c, _ := fullTree(t, healthyUnits)
	c.Hostname = func() (string, error) { return "", errors.New("no hostname") }
	if _, _, err := c.Collect(context.Background()); err == nil {
		t.Fatal("hostname failure must be an error")
	}
}

// M1 Q4: the agent never starts clamd. On a socket-activated clamd, a
// connection to the socket of a stopped service would start it.
func TestClamdSocketIsNeverTouchedUnlessUnitIsUsable(t *testing.T) {
	cases := []struct {
		name     string
		clamd    string // services fixture for the clamd unit
		unitName string // units.clamd; "" means "not managed by systemd"
		wantConn bool
		wantErr  string // substring of clamd.error when not connecting
	}{
		{"active", "clamd-active", "clamav-daemon", true, ""},
		// Only an EMPTY units.clamd means "probe the socket"; a configured
		// unit that systemd does not know is most likely a typo or a wrong
		// distro default, and the socket may still be socket-activated.
		{"empty unit name: not managed by systemd", "not-found", "", true, ""},
		{"configured unit not found", "not-found", "clamav-daemon", false, `clamd unit clamav-daemon not found; set units.clamd to "" if clamd is not managed by systemd`},
		{"inactive", "clamd-inactive", "clamav-daemon", false, "not connecting"},
		{"failed", "freshclam-failed", "clamav-daemon", false, "not connecting"},
	}
	for _, tc := range cases {
		units := map[string]string{"clamav-daemon": tc.clamd, "clamav-freshclam": "freshclam-inactive", "clamav-clamonacc": "clamonacc-inactive"}
		c, f := fullTree(t, units)
		c.Cfg.Units.Clamd = tc.unitName
		r, _, err := c.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got := f.conns.Load() > 0; got != tc.wantConn {
			t.Errorf("%s: connected=%v, want %v", tc.name, got, tc.wantConn)
		}
		if r.Clamd.Up != tc.wantConn || (!tc.wantConn && (r.Clamd.Error == nil || !strings.Contains(*r.Clamd.Error, tc.wantErr))) {
			t.Errorf("%s: clamd = %+v", tc.name, r.Clamd)
		}
	}
	// systemctl itself failing: state unknown, so do not risk the connection.
	c, f := fullTree(t, healthyUnits)
	c.Exec = func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("systemctl: not found")
	}
	r, _, _ := c.Collect(context.Background())
	if f.conns.Load() != 0 || r.Clamd.Up || r.Services.Clamd != "unknown" {
		t.Errorf("unknown state: conns=%d clamd=%+v", f.conns.Load(), r.Clamd)
	}
}

func TestClamdNoLocalSocketInConf(t *testing.T) {
	c, _ := fullTree(t, healthyUnits)
	if err := os.WriteFile(c.Cfg.ClamdConf, fixture(t, "handmade/clamd.tcp-only.conf"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, problems, _ := c.Collect(context.Background())
	if r.Clamd.Up || r.Clamd.Error == nil || *r.Clamd.Error != "clamd.conf: no LocalSocket" || len(problems) != 1 {
		t.Fatalf("%+v %v", r.Clamd, problems)
	}
}

func TestReportTimestampComesFromInjectedClock(t *testing.T) {
	c, _ := fullTree(t, healthyUnits)
	r, _, _ := c.Collect(context.Background())
	if want := time.Date(2026, 11, 12, 10, 30, 45, 0, time.UTC); !r.TS.Equal(want) {
		t.Fatalf("ts = %v, want %v", r.TS, want)
	}
}
