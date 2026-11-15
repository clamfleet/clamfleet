// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite/sqlcdb"
)

// t0 is the fixed "now" of these tests: the store never reads the wall clock.
var t0 = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

var cli = store.Audit{Kind: store.ActorCLI, Actor: "tester"}

func hash(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func addHost(t *testing.T, s *Store, name string) store.Host {
	t.Helper()
	h, err := s.CreateHost(context.Background(), name, hash("tok-"+name), t0, cli)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func rep(host string, ts time.Time, ver string, tags ...string) proto.Report {
	if tags == nil {
		tags = []string{}
	}
	return proto.Report{Schema: 1, Host: host, AgentVersion: ver, Tags: tags, TS: ts}
}

func record(t *testing.T, s *Store, id int64, r proto.Report, recv time.Time) store.ReportResult {
	t.Helper()
	res, err := s.RecordReport(context.Background(), store.ReportRecord{HostID: id, Report: r, ReceivedAt: recv})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func count(t *testing.T, s *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.r.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestCreateHost(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h, err := s.CreateHost(ctx, "Web01.Example", hash("a"), t0, cli)
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != "web01.example" {
		t.Fatalf("name %q not lowercased", h.Name)
	}
	if _, err := s.CreateHost(ctx, "WEB01.example", hash("b"), t0, cli); !errors.Is(err, store.ErrHostExists) {
		t.Fatalf("duplicate name: %v, want ErrHostExists", err)
	}
	if _, err := s.CreateHost(ctx, "other", hash("a"), t0, cli); err == nil {
		t.Fatal("duplicate token hash must fail")
	}
	for _, bad := range []string{"", "-x", "a b", "a/b", "x\n"} {
		if _, err := s.CreateHost(ctx, bad, hash("c"), t0, cli); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	// A failed create writes no audit row and leaves one host.
	if n := count(t, s, `SELECT count(*) FROM audit_log`); n != 1 {
		t.Fatalf("audit rows %d, want 1 (only the successful add)", n)
	}
	if n := count(t, s, `SELECT count(*) FROM hosts`); n != 1 {
		t.Fatalf("hosts %d, want 1", n)
	}
}

func TestHostByTokenHash(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	ref, err := s.HostByTokenHash(ctx, hash("tok-a"))
	if err != nil || ref.ID != h.ID || ref.Name != "a" {
		t.Fatalf("got %+v, %v", ref, err)
	}
	for _, in := range [][]byte{hash("nope"), nil, {}} {
		if _, err := s.HostByTokenHash(ctx, in); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("hash %x: %v, want ErrNotFound", in, err)
		}
	}
}

func TestRecordReportDuplicateStoredOnce(t *testing.T) {
	s := openTemp(t)
	h := addHost(t, s, "a")
	ts := t0.Add(-time.Minute)
	first := record(t, s, h.ID, rep("a", ts, "1", "x"), t0)
	if !first.Stored || !first.Newest {
		t.Fatalf("first: %+v", first)
	}
	later := t0.Add(5 * time.Minute)
	dup := record(t, s, h.ID, rep("a", ts, "1", "x"), later)
	if dup.Stored || dup.Newest {
		t.Fatalf("duplicate: %+v", dup)
	}
	if n := count(t, s, `SELECT count(*) FROM reports`); n != 1 {
		t.Fatalf("%d report rows, want 1", n)
	}
	d, err := s.HostByName(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	// The retry still proves the agent is alive: last_seen moves, first_seen does not.
	if !d.FirstSeen.Equal(t0) || !d.LastSeen.Equal(later) {
		t.Fatalf("first_seen %v last_seen %v", d.FirstSeen, d.LastSeen)
	}
}

func TestRecordReportOutOfOrderKeepsNewest(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	now := t0.Add(time.Hour)
	record(t, s, h.ID, rep("a", t0.Add(30*time.Minute), "2.0", "new"), now)
	// A late spooled report: older agent ts, arrives after.
	res := record(t, s, h.ID, rep("a", t0, "1.0", "old"), now.Add(time.Minute))
	if !res.Stored || res.Newest {
		t.Fatalf("late report: %+v (stored, but must not become last_report)", res)
	}
	d, err := s.HostByName(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if d.AgentVersion != "2.0" || !reflect.DeepEqual(d.Tags, []string{"new"}) {
		t.Fatalf("last_report overwritten: version %q tags %v", d.AgentVersion, d.Tags)
	}
	if d.ReportCount != 2 {
		t.Fatalf("history has %d reports, want 2", d.ReportCount)
	}
}

// A host whose clock runs ahead must not lock last_report against its later,
// correct reports.
func TestRecordReportFutureSkewDoesNotLock(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	record(t, s, h.ID, rep("a", t0.Add(48*time.Hour), "skewed"), t0)
	record(t, s, h.ID, rep("a", t0.Add(5*time.Minute), "normal"), t0.Add(5*time.Minute))
	d, err := s.HostByName(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if d.AgentVersion != "normal" {
		t.Fatalf("version %q: the skewed report locked last_report", d.AgentVersion)
	}
}

func TestRecordReportTagsReplacedNotMerged(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	record(t, s, h.ID, rep("a", t0, "1", "web", "prod"), t0)
	record(t, s, h.ID, rep("a", t0.Add(time.Minute), "1", "db", "db"), t0.Add(time.Minute)) // duplicate tag in one report
	d, _ := s.HostByName(ctx, "a")
	if !reflect.DeepEqual(d.Tags, []string{"db"}) {
		t.Fatalf("tags %v, want [db]", d.Tags)
	}
	record(t, s, h.ID, rep("a", t0.Add(2*time.Minute), "1"), t0.Add(2*time.Minute))
	d, _ = s.HostByName(ctx, "a")
	if len(d.Tags) != 0 {
		t.Fatalf("tags %v, want none", d.Tags)
	}
}

func TestRecordReportStoresCanonicalPayloadAndReportedName(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	r := rep("Reported-Name", time.Date(2026, 11, 12, 11, 0, 5, 999, time.FixedZone("CET", 3600)), "9")
	res := record(t, s, h.ID, r, t0)
	if res.PreviousReportedName != "" {
		t.Fatalf("previous %q", res.PreviousReportedName)
	}
	res = record(t, s, h.ID, rep("other", t0.Add(time.Hour), "9"), t0.Add(time.Hour))
	if res.PreviousReportedName != "Reported-Name" {
		t.Fatalf("previous %q", res.PreviousReportedName)
	}
	d, _ := s.HostByName(ctx, "a")
	if d.ReportedName != "other" || d.Name != "a" {
		t.Fatalf("identity mixed up: %+v", d.HostSummary)
	}
	var ts int64
	if err := s.r.QueryRow(`SELECT ts FROM reports ORDER BY ts LIMIT 1`).Scan(&ts); err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 11, 12, 10, 0, 5, 0, time.UTC).Unix(); ts != want {
		t.Fatalf("ts %d, want %d (UTC seconds)", ts, want)
	}
}

func TestRecordReportUnknownHost(t *testing.T) {
	s := openTemp(t)
	_, err := s.RecordReport(context.Background(), store.ReportRecord{HostID: 999, Report: rep("a", t0, "1"), ReceivedAt: t0})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestSetTokenRotateRevokeAndAudit(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	later := t0.Add(time.Hour)
	if err := s.SetToken(ctx, "A", hash("new"), later, store.Audit{Kind: store.ActorCLI, Actor: "root"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HostByTokenHash(ctx, hash("tok-a")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old token still works: %v", err)
	}
	if _, err := s.HostByTokenHash(ctx, hash("new")); err != nil {
		t.Fatalf("new token: %v", err)
	}
	if err := s.SetToken(ctx, "a", nil, later, cli); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HostByTokenHash(ctx, hash("new")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoked token still works: %v", err)
	}
	d, _ := s.HostByName(ctx, "a")
	if d.HasToken {
		t.Fatal("HasToken after revoke")
	}
	var actions []string
	for _, e := range d.Audit {
		actions = append(actions, e.Action)
	}
	want := []string{store.ActionTokenRevoke, store.ActionTokenRotate, store.ActionHostAdd}
	if !reflect.DeepEqual(actions, want) {
		t.Fatalf("audit actions %v, want %v (newest first)", actions, want)
	}
	if d.Audit[1].Actor != "root" {
		t.Fatalf("actor %q", d.Audit[1].Actor)
	}
	if err := s.SetToken(ctx, "ghost", hash("x"), later, cli); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown host: %v", err)
	}
}

// The audit row is part of the same transaction: a failure after the token
// update must leave neither the new token nor an audit row.
func TestSetTokenFailureRollsBackTokenAndAudit(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	s.afterTokenUpdate = func() error { return errors.New("injected") }
	if err := s.SetToken(ctx, "a", hash("new"), t0, cli); err == nil {
		t.Fatal("want the injected error")
	}
	s.afterTokenUpdate = nil
	if _, err := s.HostByTokenHash(ctx, hash("tok-a")); err != nil {
		t.Fatalf("old token lost after a rolled-back rotation: %v", err)
	}
	if _, err := s.HostByTokenHash(ctx, hash("new")); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("new token persisted despite the rollback")
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action <> 'host.add'`); n != 0 {
		t.Fatalf("%d audit rows persisted", n)
	}
}

func TestRecordEventDuplicate(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	e := store.EventRecord{HostID: h.ID, ReceivedAt: t0, Event: proto.Event{
		Schema: 1, Host: "a", TS: t0, Path: "/tmp/eicar", Signature: "Eicar", Source: "scan"}}
	for i, want := range []bool{true, false} {
		got, err := s.RecordEvent(ctx, e)
		if err != nil || got != want {
			t.Fatalf("call %d: stored=%v err=%v, want %v", i, got, err, want)
		}
	}
	e.Event.Path = "/tmp/other"
	if got, _ := s.RecordEvent(ctx, e); !got {
		t.Fatal("a different path is a different event")
	}
}

// Decision 2: deleting a host cascades to everything that belongs to it; the
// audit trail, which carries only a name snapshot, stays.
func TestDeleteHostCascades(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	record(t, s, h.ID, rep("a", t0, "1", "web"), t0)
	if _, err := s.RecordEvent(ctx, store.EventRecord{HostID: h.ID, ReceivedAt: t0,
		Event: proto.Event{TS: t0, Path: "/p", Signature: "s", Source: "scan"}}); err != nil {
		t.Fatal(err)
	}
	if n, err := sqlcdb.New(s.w).DeleteHost(ctx, h.ID); err != nil || n != 1 {
		t.Fatalf("delete: %d %v", n, err)
	}
	for _, tbl := range []string{"host_tags", "reports", "events"} {
		if n := count(t, s, "SELECT count(*) FROM "+tbl); n != 0 {
			t.Errorf("%s: %d rows left after host delete", tbl, n)
		}
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log`); n != 1 {
		t.Errorf("audit_log has %d rows, want 1 (must survive the host)", n)
	}
}

// Two Store instances on one file stand in for the server and the admin CLI
// (two processes): busy_timeout and BEGIN IMMEDIATE must serialise them with
// no SQLITE_BUSY and exact counts.
func TestConcurrentWritersTwoStores(t *testing.T) {
	ctx := context.Background()
	a := openTemp(t)
	b, err := Open(ctx, a.path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	h := addHost(t, a, "a")

	const workers, per = 4, 50
	var wg sync.WaitGroup
	errs := make(chan error, 2*workers*per)
	for si, s := range []*Store{a, b} {
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < per; i++ {
					ts := t0.Add(time.Duration(si*10000+w*100+i) * time.Second)
					if _, err := s.RecordReport(ctx, store.ReportRecord{HostID: h.ID, Report: rep("a", ts, "1"), ReceivedAt: ts}); err != nil {
						errs <- fmt.Errorf("store %d worker %d: %w", si, w, err)
					}
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := count(t, a, `SELECT count(*) FROM reports`); n != 2*workers*per {
		t.Fatalf("%d reports, want %d", n, 2*workers*per)
	}
}

func TestListHostsAndPing(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	b, a := addHost(t, s, "b"), addHost(t, s, "a")
	record(t, s, b.ID, rep("b", t0, "1", "x", "y"), t0)
	_ = a
	got, err := s.ListHosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "b" {
		t.Fatalf("order: %+v", got)
	}
	if !reflect.DeepEqual(got[1].Tags, []string{"x", "y"}) || got[0].Tags == nil || len(got[0].Tags) != 0 {
		t.Fatalf("tags: %v / %v", got[0].Tags, got[1].Tags)
	}
	if got[0].LastSeen != nil || got[1].LastSeen == nil {
		t.Fatal("last_seen")
	}
	if _, err := s.HostByName(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	s.Close()
	if err := s.Ping(ctx); err == nil {
		t.Fatal("Ping on a closed store must fail")
	}
}

// A replayed heartbeat is history only: the row is stored, nothing about the
// host moves. Each assertion pins one column a replay must not touch.
func TestRecordReportReplayIsHistoryOnly(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "web01")
	newest := rep("web01", t0.Add(time.Hour), "2.0", "prod")
	record(t, s, h.ID, newest, t0.Add(time.Hour+time.Second))
	before, err := s.HostByName(ctx, "web01")
	if err != nil {
		t.Fatal(err)
	}

	old := rep("web01", t0, "1.0", "stale-tag")
	old.Replay = true
	res := record(t, s, h.ID, old, t0.Add(2*time.Hour))
	if !res.Stored || res.Newest {
		t.Fatalf("a replay is stored and never newest: %+v", res)
	}
	after, err := s.HostByName(ctx, "web01")
	if err != nil {
		t.Fatal(err)
	}
	if !after.LastSeen.Equal(*before.LastSeen) {
		t.Fatalf("last_seen moved from %v to %v", before.LastSeen, after.LastSeen)
	}
	if string(after.LastReport) != string(before.LastReport) || after.AgentVersion != "2.0" || !reflect.DeepEqual(after.Tags, []string{"prod"}) {
		t.Fatalf("last_report, agent version or tags changed: %+v", after)
	}
	if n := count(t, s, `SELECT count(*) FROM reports WHERE host_id = ?`, h.ID); n != 2 {
		t.Fatalf("%d report rows, want 2 (the replay is kept as history)", n)
	}

	// A replay with a NEWER ts than last_report (the newest was quarantined on
	// the agent and only history got through) is still history only.
	later := rep("web01", t0.Add(3*time.Hour), "3.0", "x")
	later.Replay = true
	if res := record(t, s, h.ID, later, t0.Add(3*time.Hour+time.Second)); !res.Stored || res.Newest {
		t.Fatalf("%+v", res)
	}
	after2, _ := s.HostByName(ctx, "web01")
	if string(after2.LastReport) != string(before.LastReport) || !after2.LastSeen.Equal(*before.LastSeen) {
		t.Fatal("a newer-ts replay moved the host")
	}

	// A replayed duplicate of an existing ts changes nothing.
	dup := newest
	dup.Replay = true
	if res := record(t, s, h.ID, dup, t0.Add(4*time.Hour)); res.Stored {
		t.Fatalf("a duplicate was stored again: %+v", res)
	}
	if n := count(t, s, `SELECT count(*) FROM reports WHERE host_id = ?`, h.ID); n != 3 {
		t.Fatalf("%d report rows, want 3", n)
	}
}

// A host that has only ever sent replays has no first_seen: it never looked alive.
func TestRecordReportReplayDoesNotSetFirstSeen(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "web01")
	r := rep("web01", t0, "1.0")
	r.Replay = true
	record(t, s, h.ID, r, t0.Add(time.Minute))
	got, err := s.HostByName(ctx, "web01")
	if err != nil {
		t.Fatal(err)
	}
	if got.FirstSeen != nil || got.LastSeen != nil || len(got.LastReport) != 0 {
		t.Fatalf("%+v", got)
	}
}

// On an ord tie between two live reports the later arrival wins (the existing
// "<=" rule), so a retry of the same instant from a second path is not lost.
func TestRecordReportOrdTieLaterArrivalWins(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "web01")
	a := rep("web01", t0, "1.0")
	record(t, s, h.ID, a, t0)
	c := rep("web01", t0.Add(time.Second), "3.0")
	record(t, s, h.ID, c, t0) // ord = min(t0+1s, t0) = t0, the same as a
	got, _ := s.HostByName(ctx, "web01")
	if got.AgentVersion != "3.0" {
		t.Fatalf("on a tie the later arrival must win: %s", got.AgentVersion)
	}
}
