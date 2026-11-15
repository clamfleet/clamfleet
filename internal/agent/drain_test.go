// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

type sentReq struct {
	Path string
	Body []byte
}

func (s sentReq) event(t *testing.T) proto.Event {
	t.Helper()
	var ev proto.Event
	if err := json.Unmarshal(s.Body, &ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

type drainFixture struct {
	*testSpool
	Q       *Queue
	D       *Drainer
	Logs    *syncBuf
	mu      sync.Mutex
	Sent    []sentReq
	Respond func(path string, body []byte) error
	Sleeps  []time.Duration
}

func newDrainFixture(t *testing.T) *drainFixture {
	t.Helper()
	ts := newTestSpool(t)
	f := &drainFixture{testSpool: ts, Logs: &syncBuf{}}
	ts.Opts.Log = slog.New(slog.NewJSONHandler(f.Logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.Q = ts.OpenRun(t)
	f.D = &Drainer{
		Q: f.Q, Now: ts.Clock.Now, Log: ts.Opts.Log, MaxEventAge: 365 * 24 * time.Hour,
		Send: func(_ context.Context, path string, body []byte) ([]byte, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.Sent = append(f.Sent, sentReq{path, body})
			if f.Respond != nil {
				if err := f.Respond(path, body); err != nil {
					return nil, err
				}
			}
			return []byte(`{"ok":true}`), nil
		},
		Sleep: func(_ context.Context, d time.Duration) { f.Sleeps = append(f.Sleeps, d) },
	}
	return f
}

func (f *drainFixture) sent() []sentReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentReq{}, f.Sent...)
}

// seedEvent writes a valid spooled event n (its id is n in hex), detected and
// spooled at offset from the injected now.
func (f *drainFixture) seedEvent(t *testing.T, n int, offset time.Duration, path string) string {
	t.Helper()
	id := fmt.Sprintf("%032x", n)
	ev := proto.Event{Schema: 1, ID: &id, Host: "app01", TS: f.Clock.Now().Add(offset).UTC().Truncate(time.Second), Path: path, Signature: "Win.Test.EICAR_HDB-1", Source: "clamd"}
	b, _ := json.Marshal(ev)
	name := itemFileName(f.Clock, id, offset)
	put(t, f.testSpool, dirEvents, name, b)
	return name
}

func (f *drainFixture) seedReport(t *testing.T, n int, offset time.Duration) string {
	t.Helper()
	r := proto.Report{Schema: 1, Host: "app01", Tags: []string{}, TS: f.Clock.Now().Add(offset).UTC().Truncate(time.Second)}
	b, _ := json.Marshal(r)
	name := itemFileName(f.Clock, fmt.Sprintf("%032x", n), offset)
	put(t, f.testSpool, dirReports, name, b)
	return name
}

func TestEventLaneOrderFreshFirstThenOldestFirst(t *testing.T) {
	f := newDrainFixture(t)
	f.seedEvent(t, 1, -3*time.Hour, "/old1")
	f.seedEvent(t, 2, -2*time.Hour, "/old2")
	f.seedEvent(t, 3, -10*time.Second, "/fresh")
	if n := f.D.EventPass(context.Background()); n != 3 {
		t.Fatalf("delivered %d", n)
	}
	var got []string
	for _, s := range f.sent() {
		if s.Path != "v1/event" {
			t.Fatalf("path %s", s.Path)
		}
		got = append(got, s.event(t).Path)
	}
	if strings.Join(got, ",") != "/fresh,/old1,/old2" {
		t.Fatalf("order %v, want the fresh event first, then oldest first", got)
	}
	if got := f.names(t, dirEvents); len(got) != 0 {
		t.Fatalf("delivered items left: %v", got)
	}
}

func TestReportLaneNewestFirstThenReplays(t *testing.T) {
	f := newDrainFixture(t)
	f.seedReport(t, 1, -3*time.Hour)
	f.seedReport(t, 2, -2*time.Hour)
	r3 := f.seedReport(t, 3, -time.Minute)
	disk, _ := os.ReadFile(filepath.Join(f.Dir, dirReports, r3))
	if n := f.D.ReportPass(context.Background()); n != 3 {
		t.Fatalf("delivered %d", n)
	}
	var tss []string
	var replay []bool
	for _, s := range f.sent() {
		var r proto.Report
		if err := json.Unmarshal(s.Body, &r); err != nil {
			t.Fatal(err)
		}
		tss = append(tss, r.TS.Format("15:04"))
		replay = append(replay, r.Replay)
	}
	want := []time.Time{f.Clock.Now().Add(-time.Minute), f.Clock.Now().Add(-3 * time.Hour), f.Clock.Now().Add(-2 * time.Hour)}
	for i, w := range want {
		if tss[i] != w.UTC().Format("15:04") {
			t.Fatalf("order %v, want newest, then oldest first", tss)
		}
	}
	if replay[0] || !replay[1] || !replay[2] {
		t.Fatalf("replay flags %v, want [false true true]", replay)
	}
	// The flag is set at send time and never stored.
	if !strings.Contains(string(disk), `"replay":false`) {
		t.Fatalf("on-disk report: %s", disk)
	}
	// Replays are paced: one pause between the two (not before the first).
	if len(f.Sleeps) != 1 || f.Sleeps[0] != 500*time.Millisecond {
		t.Fatalf("pacing %v, want one pause of 500ms (2 per second)", f.Sleeps)
	}
}

// After the newest was sent, a report that arrives later is the newest again
// (replay=false), and what is left of the older ones is still history.
func TestReportLaneNewArrivalAfterBacklog(t *testing.T) {
	f := newDrainFixture(t)
	f.seedReport(t, 1, -3*time.Hour)
	f.seedReport(t, 2, -time.Minute)
	f.D.ReportPass(context.Background())
	f.Sent = nil
	f.Clock.Advance(time.Minute)
	f.seedReport(t, 3, 0)
	f.seedReport(t, 4, -2*time.Hour) // an old one that turned up late
	f.D.ReportPass(context.Background())
	var flags []bool
	for _, s := range f.sent() {
		var r proto.Report
		json.Unmarshal(s.Body, &r)
		flags = append(flags, r.Replay)
	}
	if len(flags) != 2 || flags[0] || !flags[1] {
		t.Fatalf("flags %v, want [false true]", flags)
	}
}

// The report lane's request is held for a long time; a fresh detection is
// still delivered at once, because the lanes are independent.
func TestLanesAreIndependent(t *testing.T) {
	f := newDrainFixture(t)
	release := make(chan struct{})
	reportStarted := make(chan struct{}, 1)
	eventDone := make(chan struct{}, 1)
	f.D.Send = func(ctx context.Context, path string, body []byte) ([]byte, error) {
		if path == "v1/report" {
			reportStarted <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil, &SendError{Class: ClassNetwork}
		}
		eventDone <- struct{}{}
		return nil, nil
	}
	f.D.Poll = 5 * time.Millisecond
	f.seedReport(t, 1, -time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.D.Run(ctx); close(done) }()
	defer func() { cancel(); close(release); <-done }()
	select {
	case <-reportStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("the report was never sent")
	}
	f.seedEvent(t, 9, -time.Second, "/fresh")
	select {
	case <-eventDone:
	case <-time.After(2 * time.Second):
		t.Fatal("a fresh detection waited behind a stuck report request")
	}
}

func TestDeliveryClassification(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantKept    bool // stays in events/
		wantQuaran  bool
		wantBackoff bool
	}{
		{"503", &SendError{Class: ClassServer, Status: 503}, true, false, true},
		{"network", &SendError{Class: ClassNetwork}, true, false, true},
		{"401 kept: a rotated token is fixed by an operator", &SendError{Class: ClassUnauthorized, Status: 401}, true, false, true},
		{"403", &SendError{Class: ClassRejected, Status: 403}, true, false, true},
		{"404", &SendError{Class: ClassRejected, Status: 404}, true, false, true},
		{"408", &SendError{Class: ClassRejected, Status: 408}, true, false, true},
		{"429", &SendError{Class: ClassRejected, Status: 429}, true, false, true},
		{"3xx kept", &SendError{Class: ClassRejected, Status: 302}, true, false, true},
		{"400 poison", &SendError{Class: ClassRejected, Status: 400, Message: "event: path too long"}, false, true, false},
		{"413 poison", &SendError{Class: ClassRejected, Status: 413}, false, true, false},
		{"token file missing", &SendError{Class: ClassToken}, true, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newDrainFixture(t)
			f.Respond = func(string, []byte) error { return c.err }
			f.seedEvent(t, 1, -time.Hour, "/a")
			f.D.EventPass(context.Background())
			kept := len(f.names(t, dirEvents))
			quar := len(f.names(t, dirQuarantine))
			if (kept == 1) != c.wantKept || (quar == 1) != c.wantQuaran {
				t.Fatalf("kept=%d quarantined=%d", kept, quar)
			}
			if (f.D.ev.backoff > 0) != c.wantBackoff {
				t.Fatalf("backoff %v", f.D.ev.backoff)
			}
		})
	}
}

// A poison item does not block the one behind it.
func TestPoisonItemIsQuarantinedAndTheNextDelivered(t *testing.T) {
	f := newDrainFixture(t)
	f.seedEvent(t, 1, -2*time.Hour, "/poison")
	f.seedEvent(t, 2, -time.Hour, "/good")
	f.Respond = func(_ string, body []byte) error {
		if strings.Contains(string(body), "/poison") {
			return &SendError{Class: ClassRejected, Status: 400, Message: "bad"}
		}
		return nil
	}
	if n := f.D.EventPass(context.Background()); n != 1 {
		t.Fatalf("delivered %d", n)
	}
	if len(f.names(t, dirQuarantine)) != 1 || len(f.names(t, dirEvents)) != 0 {
		t.Fatalf("events %v quarantine %v", f.names(t, dirEvents), f.names(t, dirQuarantine))
	}
}

func TestBackoffDoublesToThirtySecondsAndRecovers(t *testing.T) {
	f := newDrainFixture(t)
	fail := true
	f.Respond = func(string, []byte) error {
		if fail {
			return &SendError{Class: ClassServer, Status: 503}
		}
		return nil
	}
	f.seedEvent(t, 1, -time.Hour, "/a")
	var seen []time.Duration
	for i := 0; i < 8; i++ {
		before := len(f.sent())
		f.D.EventPass(context.Background())
		if len(f.sent()) != before+1 {
			t.Fatalf("pass %d made %d sends", i, len(f.sent())-before)
		}
		seen = append(seen, f.D.ev.backoff)
		// Still inside the backoff: nothing is sent.
		f.D.EventPass(context.Background())
		if len(f.sent()) != before+1 {
			t.Fatalf("pass %d: sent during the backoff", i)
		}
		f.Clock.Advance(f.D.ev.backoff)
	}
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30, 30}
	for i, w := range want {
		if seen[i] != w*time.Second {
			t.Fatalf("backoff sequence %v", seen)
		}
	}
	fail = false
	if n := f.D.EventPass(context.Background()); n != 1 {
		t.Fatalf("delivered %d after recovery", n)
	}
	if f.D.ev.backoff != 0 || !strings.Contains(f.Logs.String(), "events are being sent again") {
		t.Fatalf("no recovery: backoff=%v logs=%s", f.D.ev.backoff, f.Logs.String())
	}
	// The streak is logged once, not once per attempt.
	if n := strings.Count(f.Logs.String(), `"msg":"event not sent"`); n != 1 {
		t.Fatalf("%d failure lines for one streak", n)
	}
}

func TestFreshEventResetsTheBackoff(t *testing.T) {
	f := newDrainFixture(t)
	down := true
	f.Respond = func(string, []byte) error {
		if down {
			return &SendError{Class: ClassServer, Status: 503}
		}
		return nil
	}
	f.seedEvent(t, 1, -time.Hour, "/old")
	for i := 0; i < 4; i++ {
		f.D.EventPass(context.Background())
		f.Clock.Advance(f.D.ev.backoff)
	}
	if f.D.ev.backoff < 8*time.Second {
		t.Fatalf("backoff %v", f.D.ev.backoff)
	}
	f.D.EventPass(context.Background()) // fails again, now backing off 16s
	down = false
	f.seedEvent(t, 2, 0, "/fresh")
	n := f.D.EventPass(context.Background())
	if n < 1 {
		t.Fatalf("the fresh event waited out the backoff (delivered %d)", n)
	}
}

func TestUnreadableItemIsSkippedNotQuarantined(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("needs a non-root user: mode 0000 must be unreadable")
	}
	f := newDrainFixture(t)
	name := f.seedEvent(t, 1, -time.Hour, "/a")
	os.Chmod(filepath.Join(f.Dir, dirEvents, name), 0)
	for i := 0; i < 3; i++ {
		f.D.EventPass(context.Background())
	}
	if len(f.names(t, dirEvents)) != 1 || len(f.names(t, dirQuarantine)) != 0 || len(f.sent()) != 0 {
		t.Fatal("an item the agent cannot read must stay where it is")
	}
	if n := strings.Count(f.Logs.String(), "permission denied"); n != 1 {
		t.Fatalf("logged %d times within a minute, want 1", n)
	}
	f.Clock.Advance(2 * time.Minute)
	f.D.EventPass(context.Background())
	if n := strings.Count(f.Logs.String(), "permission denied"); n != 2 {
		t.Fatalf("logged %d times after a minute, want 2", n)
	}
}

func TestExpiryOfOldSpooledEvents(t *testing.T) {
	f := newDrainFixture(t)
	f.seedEvent(t, 1, -366*24*time.Hour, "/MARKER-OLD")
	f.seedEvent(t, 2, -364*24*time.Hour, "/recent")
	n := f.D.EventPass(context.Background())
	if n != 1 || len(f.sent()) != 1 || f.sent()[0].event(t).Path != "/recent" {
		t.Fatalf("delivered %d, sent %d", n, len(f.sent()))
	}
	if len(f.names(t, dirEvents)) != 0 || len(f.names(t, dirQuarantine)) != 0 {
		t.Fatal("an expired event is deleted, not quarantined")
	}
	if !strings.Contains(f.Logs.String(), "expired") || !strings.Contains(f.Logs.String(), "EICAR") || strings.Contains(f.Logs.String(), "MARKER") {
		t.Fatalf("log: %s", f.Logs.String())
	}
}

func TestInvalidItemsAreQuarantined(t *testing.T) {
	f := newDrainFixture(t)
	id := fmt.Sprintf("%032x", 1)
	put(t, f.testSpool, dirEvents, itemFileName(f.Clock, id, -time.Hour), []byte(`{"schema":2}`))
	put(t, f.testSpool, dirEvents, "not-an-item-name", []byte(`{}`))
	f.D.EventPass(context.Background())
	if len(f.sent()) != 0 || len(f.names(t, dirEvents)) != 0 || len(f.names(t, dirQuarantine)) != 2 {
		t.Fatalf("sent %d events %v quarantine %v", len(f.sent()), f.names(t, dirEvents), f.names(t, dirQuarantine))
	}
}

// The request body is the validated, re-encoded struct: an unknown field in
// the file does not travel.
func TestSendsTheReencodedBodyNotTheFileBytes(t *testing.T) {
	f := newDrainFixture(t)
	id := fmt.Sprintf("%032x", 1)
	ts := f.Clock.Now().Add(-time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	raw := `{"schema":1,"id":"` + id + `","host":"h","ts":"` + ts + `","path":"/a","signature":"S","source":"clamd","admin":true}`
	put(t, f.testSpool, dirEvents, itemFileName(f.Clock, id, -time.Hour), []byte(raw))
	f.D.EventPass(context.Background())
	if len(f.sent()) != 1 || strings.Contains(string(f.sent()[0].Body), "admin") {
		t.Fatalf("sent: %v", f.sent())
	}
}

// A marker path never reaches the agent's logs, through every failure path.
func TestNoPathInAgentLogs(t *testing.T) {
	f := newDrainFixture(t)
	const marker = "/srv/MARKER-PATH"
	f.seedEvent(t, 1, -time.Hour, marker)
	f.seedEvent(t, 2, -2*time.Hour, marker+"-poison")
	f.seedEvent(t, 3, -400*24*time.Hour, marker+"-old")
	id := fmt.Sprintf("%032x", 4)
	put(t, f.testSpool, dirEvents, itemFileName(f.Clock, id, -3*time.Hour), []byte(`{"schema":1,"id":"`+id+`","path":"`+marker+`-bad"}`))
	f.Respond = func(_ string, body []byte) error {
		if strings.Contains(string(body), "poison") {
			return &SendError{Class: ClassRejected, Status: 400, Message: "invalid event"}
		}
		return &SendError{Class: ClassServer, Status: 503, Message: "down"}
	}
	f.D.EventPass(context.Background())
	f.Clock.Advance(time.Minute)
	f.D.EventPass(context.Background())
	if strings.Contains(f.Logs.String(), "MARKER") {
		t.Fatalf("a path is in the log:\n%s", f.Logs.String())
	}
	if f.Logs.String() == "" {
		t.Fatal("expected some log lines")
	}
}

// 20,000 spooled events are worked through in bounded chunks and all delivered.
func TestDrainsALargeBacklog(t *testing.T) {
	f := newDrainFixture(t)
	f.Q.o.MaxBytes = 1 << 30
	const n = 20000
	for i := 0; i < n; i++ {
		f.seedEvent(t, i+1, -time.Hour+time.Duration(i)*time.Millisecond, "/p")
	}
	f.FS.mu.Lock()
	f.FS.readDirs = 0
	f.FS.mu.Unlock()
	got := 0
	for pass := 0; pass < 200 && got < n; pass++ {
		got += f.D.EventPass(context.Background())
	}
	if got != n || len(f.names(t, dirEvents)) != 0 {
		t.Fatalf("delivered %d of %d", got, n)
	}
	if f.FS.readDirs < n/readDirChunk {
		t.Fatalf("the directory was read in only %d chunks", f.FS.readDirs)
	}
}

func TestSpoolReportsFullWarnsOncePerHour(t *testing.T) {
	f := newDrainFixture(t)
	f.Q.o.MaxBytes = blockEstimate
	e := f.OpenEvent(t)
	if _, err := e.AdmitEvent(300); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	r := &Runner{
		Collect: func(context.Context) (proto.Report, []Problem, error) {
			return proto.Report{Schema: 1, Host: "h", Tags: []string{}, TS: f.Clock.Now()}, nil, nil
		},
		Queue: f.Q, Drain: f.D, Now: f.Clock.Now, Log: slog.New(slog.NewJSONHandler(logs, nil)),
	}
	r.spoolReport(context.Background())
	r.spoolReport(context.Background())
	f.Clock.Advance(2 * time.Hour)
	r.spoolReport(context.Background())
	if n := strings.Count(logs.String(), "spool full"); n != 2 {
		t.Fatalf("warned %d times, want 2 (once per hour)", n)
	}
	_ = errors.New
}
