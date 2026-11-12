// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

func utc(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestParseRecordedLogs(t *testing.T) {
	cases := []struct {
		file   string
		starts []string
		ok     []bool
	}{
		{"initial-download.log", []string{"2026-11-12T10:01:08Z"}, []bool{true}},
		{"after-rerun.log", []string{"2026-11-12T10:01:08Z", "2026-11-12T10:21:15Z"}, []bool{true, true}},
		{"logtime-no.log", []string{"2026-11-12T10:21:18Z"}, []bool{true}}, // LogTime no: the start line still carries the time
		{"journal-rerun.txt", []string{"2026-11-12T10:21:15Z"}, []bool{true}},
	}
	for _, c := range cases {
		runs := ParseFreshclamLog(fixture(t, "freshclam/"+c.file), time.UTC)
		if len(runs) != len(c.starts) {
			t.Errorf("%s: %d runs, want %d", c.file, len(runs), len(c.starts))
			continue
		}
		for i, r := range runs {
			if !r.Start.Equal(utc(c.starts[i])) || r.OK != c.ok[i] || r.Failed {
				t.Errorf("%s run %d: %+v", c.file, i, r)
			}
		}
	}
}

func TestParseRecordedFailures(t *testing.T) {
	for _, f := range []string{"failure.log", "journal-failure.txt"} {
		runs := ParseFreshclamLog(fixture(t, "freshclam/"+f), time.UTC)
		if len(runs) != 1 || !runs[0].Failed || runs[0].OK || !runs[0].Start.Equal(utc("2026-11-12T10:21:19Z")) {
			t.Fatalf("%s: %+v", f, runs)
		}
		msg := runs[0].ErrMsg
		if !strings.Contains(msg, "Download failed (7)") || strings.Contains(msg, "ERROR:") || strings.Contains(msg, "->") {
			t.Errorf("%s: message not cleaned: %q", f, msg)
		}
	}
}

func TestSummarizeInterleavedRuns(t *testing.T) {
	log := logRun("Mon Nov  9 10:00:00 2026", "daily.cvd database is up-to-date (version: 1)") +
		logRun("Mon Nov  9 11:00:00 2026", "ERROR: first failure") +
		logRun("Mon Nov  9 12:00:00 2026", "daily.cvd updated (version: 2)") +
		logRun("Mon Nov  9 13:00:00 2026", "ERROR: second failure", "ERROR: and more") +
		logRun("Mon Nov  9 14:00:00 2026", "something unrelated, no outcome yet")
	fc, ok := summarizeRuns(ParseFreshclamLog([]byte("junk before\n"+log), time.UTC))
	if !ok || fc.LastOK == nil || !fc.LastOK.Equal(utc("2026-11-09T12:00:00Z")) {
		t.Fatalf("last ok: %+v", fc)
	}
	if fc.LastError == nil || !fc.LastError.Equal(utc("2026-11-09T13:00:00Z")) || *fc.LastErrorMsg != "second failure" {
		t.Fatalf("last error: %+v", fc)
	}
}

func TestRunWithErrorAndUpdateCountsAsFailed(t *testing.T) {
	runs := ParseFreshclamLog([]byte(logRun("Mon Nov  9 10:00:00 2026", "daily.cvd updated (version: 2)", "ERROR: main failed")), time.UTC)
	if len(runs) != 1 || !runs[0].Failed || runs[0].OK {
		t.Fatalf("%+v", runs)
	}
}

func TestLogTimesAreReadInHostZone(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	// One run before and one after the 2026-10-25 change from CEST (+2) to CET (+1).
	log := []byte(logRun("Sat Oct 24 12:00:00 2026", "x is up-to-date") + logRun("Sun Oct 25 12:00:00 2026", "x is up-to-date"))
	runs := ParseFreshclamLog(log, berlin)
	if !runs[0].Start.Equal(utc("2026-10-24T10:00:00Z")) || !runs[1].Start.Equal(utc("2026-10-25T11:00:00Z")) {
		t.Fatalf("got %v and %v", runs[0].Start, runs[1].Start)
	}
	if utcRuns := ParseFreshclamLog(log, time.UTC); utcRuns[0].Start.Equal(runs[0].Start) {
		t.Fatal("zone is ignored")
	}
}

func TestSingleDigitDayWithTwoSpaces(t *testing.T) {
	runs := ParseFreshclamLog([]byte(logRun("Thu Nov  5 09:01:02 2026", "x is up-to-date")), time.UTC)
	if len(runs) != 1 || !runs[0].Start.Equal(utc("2026-11-05T09:01:02Z")) {
		t.Fatalf("%+v", runs)
	}
}

func TestErrorMessageHygiene(t *testing.T) {
	got := cleanErrorLine("Thu Nov 12 10:00:00 2026 -> ERROR: fetch failed via http://user:s3cret@proxy.example:3128/path and https://a:b@host")
	if strings.Contains(got, "s3cret") || strings.Contains(got, "a:b@") || !strings.Contains(got, "http://proxy.example:3128/path") {
		t.Fatalf("credentials not stripped: %q", got)
	}
	// A raw "@" inside the password: everything up to the LAST "@" of the authority is credentials.
	got = cleanErrorLine("ERROR: via http://user:p@ss@proxy:3128/ failed")
	if strings.Contains(got, "p@ss") || strings.Contains(got, "ss@") || strings.Contains(got, "user") || !strings.Contains(got, "http://proxy:3128/") {
		t.Fatalf("password with @ not fully stripped: %q", got)
	}
	long := cleanErrorLine("ERROR: " + strings.Repeat("é", 400))
	if len(long) > maxErrMsg || !strings.HasPrefix(long, "é") {
		t.Fatalf("not truncated on a rune boundary: %d bytes", len(long))
	}
}

func TestReadTailDropsPartialFirstLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(p, []byte("aaaaaaaa\nbbbb\ncccc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := readTail(p, 12) // starts in the middle of the first line
	if err != nil || string(b) != "bbbb\ncccc\n" {
		t.Fatalf("got %q %v", b, err)
	}
	b, _ = readTail(p, 1000)
	if string(b) != "aaaaaaaa\nbbbb\ncccc\n" {
		t.Fatalf("whole file expected, got %q", b)
	}
}

// collectorFor builds a Collector over a temp tree with a fake exec.
func collectorFor(t *testing.T, exec ExecFunc) (*Collector, string, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.DBDir = filepath.Join(dir, "db")
	cfg.FreshclamLog = filepath.Join(dir, "freshclam.log")
	if err := os.Mkdir(cfg.DBDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if exec == nil {
		exec = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	}
	return &Collector{Cfg: cfg, Loc: time.UTC, Exec: exec}, cfg.DBDir, cfg.FreshclamLog
}

func TestCollectFreshclamCutRunInBigLogIsDropped(t *testing.T) {
	c, _, logPath := collectorFor(t, nil)
	// 1.3 MiB of old junk, containing a failure whose start line is far out of the tail, then one good run.
	junk := strings.Repeat("ERROR: ancient failure, start line lost to the tail\n", 25000)
	body := junk + logRun("Mon Nov  9 12:00:00 2026", "x is up-to-date")
	if err := os.WriteFile(logPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	fc, p := c.collectFreshclam(context.Background())
	if len(p) != 0 || fc.LastOK == nil || !fc.LastOK.Equal(utc("2026-11-09T12:00:00Z")) || fc.LastError != nil {
		t.Fatalf("got %+v %v", fc, p)
	}
}

func TestCollectFreshclamUsesRotatedLogWhenCurrentIsEmpty(t *testing.T) {
	c, _, logPath := collectorFor(t, nil)
	_ = os.WriteFile(logPath, nil, 0o600)
	_ = os.WriteFile(logPath+".1", []byte(logRun("Mon Nov  9 12:00:00 2026", "ERROR: rotated failure")), 0o600)
	fc, p := c.collectFreshclam(context.Background())
	if len(p) != 0 || fc.LastError == nil || *fc.LastErrorMsg != "rotated failure" {
		t.Fatalf("got %+v %v", fc, p)
	}
}

// A source that has some run must not hide a newer run in the other one: an
// old OK in the journal plus a newer failure in the log file is a failing host.
func TestCollectFreshclamMergesJournalAndLog(t *testing.T) {
	c, _, logPath := collectorFor(t, func(context.Context, string, ...string) ([]byte, error) {
		return []byte(logRun("Mon Nov  9 12:00:00 2026", "x is up-to-date")), nil
	})
	_ = os.WriteFile(logPath, []byte(logRun("Tue Nov 10 12:00:00 2026", "ERROR: newer failure")), 0o600)
	fc, p := c.collectFreshclam(context.Background())
	if len(p) != 0 || fc.LastOK == nil || !fc.LastOK.Equal(utc("2026-11-09T12:00:00Z")) ||
		fc.LastError == nil || !fc.LastError.Equal(utc("2026-11-10T12:00:00Z")) || *fc.LastErrorMsg != "newer failure" {
		t.Fatalf("got %+v %v", fc, p)
	}
}

func TestCollectFreshclamJournalFirst(t *testing.T) {
	var calls []string
	c, _, logPath := collectorFor(t, func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return fixture(t, "freshclam/journal-failure.txt"), nil
	})
	// The file has an older "ok" run, the journal a newer failure: both
	// sources are merged, so the failure is visible and the old OK is kept.
	_ = os.WriteFile(logPath, fixture(t, "freshclam/initial-download.log"), 0o600)
	fc, p := c.collectFreshclam(context.Background())
	if len(p) != 0 || fc.LastError == nil || fc.LastOK == nil || !fc.LastOK.Equal(utc("2026-11-12T10:01:08Z")) {
		t.Fatalf("got %+v %v", fc, p)
	}
	if len(calls) != 1 || calls[0] != "journalctl -u clamav-freshclam -o cat --no-pager -q -n 1000" {
		t.Fatalf("calls = %v", calls)
	}
}

func TestCollectFreshclamFallsThroughJournalToFile(t *testing.T) {
	for name, exec := range map[string]ExecFunc{
		"journal empty (exit 0, e.g. agent not in systemd-journal)": func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
		"journalctl fails": func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("no journalctl") },
	} {
		c, _, logPath := collectorFor(t, exec)
		_ = os.WriteFile(logPath, fixture(t, "freshclam/initial-download.log"), 0o600)
		fc, p := c.collectFreshclam(context.Background())
		if len(p) != 0 || fc.LastOK == nil || !fc.LastOK.Equal(utc("2026-11-12T10:01:08Z")) {
			t.Errorf("%s: got %+v %v", name, fc, p)
		}
	}
}

func TestCollectFreshclamEmptyUnitSkipsJournal(t *testing.T) {
	c, _, logPath := collectorFor(t, func(context.Context, string, ...string) ([]byte, error) {
		t.Error("journalctl must not run without a freshclam unit")
		return nil, nil
	})
	c.Cfg.Units.Freshclam = ""
	_ = os.WriteFile(logPath, fixture(t, "freshclam/initial-download.log"), 0o600)
	if fc, _ := c.collectFreshclam(context.Background()); fc.LastOK == nil {
		t.Fatal("log file should have been used")
	}
}

func TestCollectFreshclamFallsBackToDatabaseMtime(t *testing.T) {
	c, db, _ := collectorFor(t, nil) // no journal output, no log file
	writeDB(t, db, "daily.cvd", fixture(t, "cvd/initial/daily.cvd.hdr"))
	mt := time.Date(2026, 11, 12, 6, 30, 0, 0, time.UTC)
	_ = os.Chtimes(filepath.Join(db, "daily.cvd"), mt, mt)
	fc, p := c.collectFreshclam(context.Background())
	if fc.LastOK == nil || !fc.LastOK.Equal(mt) || fc.LastError != nil || fc.LastErrorMsg != nil || len(p) != 1 {
		t.Fatalf("got %+v %v", fc, p)
	}
}

func TestCollectFreshclamUnreadableLogFallsBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: file permission bits do not apply to root")
	}
	c, db, logPath := collectorFor(t, nil)
	writeDB(t, db, "daily.cvd", fixture(t, "cvd/initial/daily.cvd.hdr"))
	_ = os.WriteFile(logPath, fixture(t, "freshclam/failure.log"), 0o000)
	fc, p := c.collectFreshclam(context.Background())
	if fc.LastOK == nil || fc.LastError != nil || len(p) != 1 || !strings.Contains(p[0].Err.Error(), "permission denied") {
		t.Fatalf("got %+v %v", fc, p)
	}
}

func TestCollectFreshclamNothingAvailable(t *testing.T) {
	c, _, _ := collectorFor(t, nil)
	fc, p := c.collectFreshclam(context.Background())
	if fc.LastOK != nil || fc.LastError != nil || fc.LastErrorMsg != nil || len(p) == 0 {
		t.Fatalf("got %+v %v", fc, p)
	}
}

// srcOf renders Freshclam.Source for comparison; "null" is the unknown case.
func srcOf(fc proto.Freshclam) string {
	if fc.Source == nil {
		return "null"
	}
	return *fc.Source
}

// freshclam.source says where the numbers came from; one case per value.
func TestCollectFreshclamSource(t *testing.T) {
	okRun := logRun("Mon Nov  9 12:00:00 2026", "x is up-to-date")
	failRun := logRun("Tue Nov 10 12:00:00 2026", "ERROR: newer failure")
	journal := func(out string) ExecFunc {
		return func(context.Context, string, ...string) ([]byte, error) { return []byte(out), nil }
	}
	for _, tc := range []struct {
		name    string
		journal string
		logFile string
		mtime   bool
		want    string
	}{
		{"journal only", okRun, "", false, "journal"},
		{"log only", "", okRun, false, "log"},
		{"both", okRun, failRun, false, "journal+log"},
		{"journal has no complete run, log has one", "junk without a run\n", okRun, false, "log"},
		{"mtime fallback", "", "", true, "mtime"},
		{"nothing known", "", "", false, "null"},
	} {
		c, db, logPath := collectorFor(t, journal(tc.journal))
		if tc.logFile != "" {
			_ = os.WriteFile(logPath, []byte(tc.logFile), 0o600)
		}
		if tc.mtime {
			writeDB(t, db, "daily.cvd", fixture(t, "cvd/initial/daily.cvd.hdr"))
		}
		fc, _ := c.collectFreshclam(context.Background())
		if got := srcOf(fc); got != tc.want {
			t.Errorf("%s: source = %s, want %s", tc.name, got, tc.want)
		}
	}
}
