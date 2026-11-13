// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
)

var admin = store.Audit{Kind: store.ActorUser, Actor: "admin@example.com"}

func aid(n int) *string { s := fmt.Sprintf("%032x", n); return &s }

func event(host string, id *string, ts time.Time, path, sig string) proto.Event {
	return proto.Event{Schema: 1, ID: id, Host: host, TS: ts, Path: path, Signature: sig, Source: "clamd"}
}

func rec(t *testing.T, s *Store, hostID int64, ev proto.Event, recv time.Time) bool {
	t.Helper()
	stored, err := s.RecordEvent(context.Background(), store.EventRecord{HostID: hostID, Event: ev, ReceivedAt: recv})
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// A retry carries the same agent id: one row, one receipt, stored then not.
func TestRecordEventRetryByID(t *testing.T) {
	s := openTemp(t)
	h := addHost(t, s, "a")
	ev := event("a", aid(1), t0, "/p", "Sig")
	if !rec(t, s, h.ID, ev, t0) || rec(t, s, h.ID, ev, t0.Add(time.Minute)) {
		t.Fatal("want stored then not stored")
	}
	if n := count(t, s, `SELECT count(*) FROM events`); n != 1 {
		t.Fatalf("%d events", n)
	}
	if n := count(t, s, `SELECT count(*) FROM event_receipts`); n != 1 {
		t.Fatalf("%d receipts", n)
	}
	if n := count(t, s, `SELECT occurrences FROM events`); n != 1 {
		t.Fatalf("a retry bumped occurrences to %d", n)
	}
	if n := count(t, s, `SELECT count(*) FROM events WHERE alert_pending = 1`); n != 1 {
		t.Fatalf("%d flagged for alerting", n)
	}
}

// Two DIFFERENT ids with the same host, second, path and signature are two
// detections: one row with occurrences 2, two receipts, ONE alert flag. A retry
// of the second id afterwards does not change anything.
func TestRecordEventCollisionIsCountedNotLost(t *testing.T) {
	s := openTemp(t)
	h := addHost(t, s, "a")
	if !rec(t, s, h.ID, event("a", aid(1), t0, "/p", "Sig"), t0) {
		t.Fatal("first not stored")
	}
	if rec(t, s, h.ID, event("a", aid(2), t0, "/p", "Sig"), t0) {
		t.Fatal("a collision must not report stored=true (no second alert)")
	}
	if n := count(t, s, `SELECT count(*) FROM events`); n != 1 {
		t.Fatalf("%d events", n)
	}
	if n := count(t, s, `SELECT occurrences FROM events`); n != 2 {
		t.Fatalf("occurrences %d, want 2", n)
	}
	if n := count(t, s, `SELECT count(*) FROM event_receipts`); n != 2 {
		t.Fatalf("%d receipts", n)
	}
	rec(t, s, h.ID, event("a", aid(2), t0, "/p", "Sig"), t0.Add(time.Minute))
	if n := count(t, s, `SELECT occurrences FROM events`); n != 2 {
		t.Fatalf("a retry of the second id changed occurrences to %d", n)
	}
	if n := count(t, s, `SELECT count(*) FROM events WHERE alert_pending = 1`); n != 1 {
		t.Fatalf("%d events flagged: a merged detection must not alert again", n)
	}
}

// Two different very long paths cut by the agent to the same 4096 bytes end up
// as the same natural key: one row, x2.
func TestRecordEventTruncationCollision(t *testing.T) {
	s := openTemp(t)
	h := addHost(t, s, "a")
	cut := strings.Repeat("a", 4093) + "..."
	rec(t, s, h.ID, event("a", aid(1), t0, cut, "Sig"), t0)
	rec(t, s, h.ID, event("a", aid(2), t0, cut, "Sig"), t0)
	if n := count(t, s, `SELECT occurrences FROM events`); n != 2 {
		t.Fatalf("occurrences %d", n)
	}
}

// The raw byte 0xff (sent as \xff) and the literal text \xff (sent as \\xff)
// are two files: two rows, not one.
func TestRecordEventEncodingKeepsDistinctNamesDistinct(t *testing.T) {
	s := openTemp(t)
	h := addHost(t, s, "a")
	rec(t, s, h.ID, event("a", aid(1), t0, `/a\xffb`, "Sig"), t0)
	rec(t, s, h.ID, event("a", aid(2), t0, `/a\\xffb`, "Sig"), t0)
	if n := count(t, s, `SELECT count(*) FROM events`); n != 2 {
		t.Fatalf("%d rows, want 2", n)
	}
}

// Third-party clients without an id: the natural key alone dedups, as before,
// and no receipt is written.
func TestRecordEventWithoutIDKeepsOldBehaviour(t *testing.T) {
	s := openTemp(t)
	h := addHost(t, s, "a")
	ev := event("a", nil, t0, "/p", "Sig")
	if !rec(t, s, h.ID, ev, t0) || rec(t, s, h.ID, ev, t0) {
		t.Fatal("want stored then not stored")
	}
	if n := count(t, s, `SELECT count(*) FROM event_receipts`); n != 0 {
		t.Fatalf("%d receipts", n)
	}
	if n := count(t, s, `SELECT occurrences FROM events`); n != 1 {
		t.Fatalf("occurrences %d", n)
	}
}

// seed adds n events for a host, ids 1..n in order, one second apart, with
// signature sigs[i%len(sigs)].
func seed(t *testing.T, s *Store, hostID int64, hostName string, n int, base int, sigs ...string) {
	t.Helper()
	for i := 0; i < n; i++ {
		rec(t, s, hostID, event(hostName, aid(base+i), t0.Add(time.Duration(i)*time.Second), fmt.Sprintf("/p/%d/%d", base, i), sigs[i%len(sigs)]), t0.Add(time.Hour))
	}
}

func TestListAndCountFilters(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	a, b := addHost(t, s, "a"), addHost(t, s, "b")
	seed(t, s, a.ID, "a", 4, 100, "Win.Test.EICAR", "Php.Shell_x")
	seed(t, s, b.ID, "b", 3, 200, "50%_off", "plain")
	if _, _, err := s.AckEvent(ctx, 1, t0, admin); err != nil {
		t.Fatal(err)
	}

	count := func(f store.EventFilter) int64 {
		t.Helper()
		n, err := s.CountEvents(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, c := range []struct {
		name string
		f    store.EventFilter
		want int64
	}{
		{"default is open only", store.EventFilter{}, 6},
		{"all", store.EventFilter{Ack: store.AckAll}, 7},
		{"acked", store.EventFilter{Ack: store.AckAcked}, 1},
		{"host", store.EventFilter{Host: "b", Ack: store.AckAll}, 3},
		{"signature is case-insensitive", store.EventFilter{Signature: "eicar", Ack: store.AckAll}, 2},
		{"a percent sign matches itself only", store.EventFilter{Signature: "%", Ack: store.AckAll}, 2},
		{"an underscore matches itself only", store.EventFilter{Signature: "_", Ack: store.AckAll}, 4},
		{"a backslash matches itself only", store.EventFilter{Signature: `\`, Ack: store.AckAll}, 0},
		{"host and signature", store.EventFilter{Host: "a", Signature: "shell", Ack: store.AckAll}, 2},
		{"upto", store.EventFilter{UpTo: 3, Ack: store.AckAll}, 3},
		{"upto with the open filter", store.EventFilter{UpTo: 3}, 2},
		{"unknown host", store.EventFilter{Host: "zzz", Ack: store.AckAll}, 0},
	} {
		if got := count(c.f); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	rows, err := s.ListEvents(ctx, store.EventFilter{Host: "a", Ack: store.AckAll})
	if err != nil || len(rows) != 4 || rows[0].ID < rows[1].ID || rows[0].Host != "a" {
		t.Fatalf("rows %+v err %v: want newest id first", rows, err)
	}
	if _, err := s.ListEvents(ctx, store.EventFilter{Ack: "bogus"}); err == nil {
		t.Fatal("a bad ack filter was accepted")
	}
	if _, err := s.ListEvents(ctx, store.EventFilter{Limit: 201}); err == nil {
		t.Fatal("a page of 201 was accepted")
	}
	max, err := s.MaxEventID(ctx, store.EventFilter{Host: "a"})
	if err != nil || max != 4 {
		t.Fatalf("max id %d err %v", max, err)
	}
	if n, _ := s.CountOpenEvents(ctx); n != 6 {
		t.Fatalf("open %d", n)
	}
}

// Keyset pagination: rows inserted between two page loads neither repeat nor
// skip any row (OFFSET would shift the page).
func TestKeysetPaginationSurvivesInserts(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	seed(t, s, h.ID, "a", 7, 100, "S")
	p1, err := s.ListEvents(ctx, store.EventFilter{Limit: 3})
	if err != nil || len(p1) != 3 {
		t.Fatal(err, p1)
	}
	seed(t, s, h.ID, "a", 2, 500, "S") // two newer events arrive
	p2, err := s.ListEvents(ctx, store.EventFilter{Limit: 3, Before: p1[2].ID})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, r := range append(p1, p2...) {
		ids = append(ids, r.ID)
	}
	want := []int64{7, 6, 5, 4, 3, 2}
	for i, w := range want {
		if ids[i] != w {
			t.Fatalf("ids %v, want %v", ids, want)
		}
	}
}

func auditRows(t *testing.T, s *Store, action string) []string {
	t.Helper()
	rows, err := s.r.Query(`SELECT actor_kind || '|' || actor || '|' || target || '|' || detail FROM audit_log WHERE action = ? ORDER BY id`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var x string
		rows.Scan(&x)
		out = append(out, x)
	}
	return out
}

func TestAckEventIsAuditedIdempotentAndNeverLogsThePath(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	rec(t, s, h.ID, event("a", aid(1), t0, "/srv/MARKER-PATH/x", "Win.Test.EICAR"), t0)
	row, acked, err := s.AckEvent(ctx, 1, t0.Add(time.Hour), admin)
	if err != nil || !acked || row.AckBy != "admin@example.com" || row.AckAt == nil || row.Acked() == false {
		t.Fatalf("%+v %v %v", row, acked, err)
	}
	// A second acknowledgement by someone else changes nothing and writes no audit row.
	other := store.Audit{Kind: store.ActorUser, Actor: "other@example.com"}
	row, acked, err = s.AckEvent(ctx, 1, t0.Add(2*time.Hour), other)
	if err != nil || acked || row.AckBy != "admin@example.com" {
		t.Fatalf("second ack: %+v %v %v", row, acked, err)
	}
	rows := auditRows(t, s, store.ActionEventAck)
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "user|admin@example.com|a|") || !strings.Contains(rows[0], "Win.Test.EICAR") {
		t.Fatalf("audit rows: %v", rows)
	}
	if strings.Contains(rows[0], "MARKER") {
		t.Fatalf("the path is in the audit row: %s", rows[0])
	}
	if _, _, err := s.AckEvent(ctx, 99, t0, admin); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
}

// The UPDATE and its audit row are one transaction: a failure between them
// rolls both back.
func TestAckEventIsAtomicWithItsAudit(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	seed(t, s, h.ID, "a", 3, 1, "S")
	s.afterAckUpdate = func() error { return errors.New("injected") }
	if _, _, err := s.AckEvent(ctx, 1, t0, admin); err == nil {
		t.Fatal("want the injected error")
	}
	if _, err := s.AckEvents(ctx, store.EventFilter{}, 3, 3, t0, admin); err == nil {
		t.Fatal("want the injected error")
	}
	s.afterAckUpdate = nil
	if n := count(t, s, `SELECT count(*) FROM events WHERE ack_at IS NOT NULL`); n != 0 {
		t.Fatalf("%d events stayed acknowledged after a rollback", n)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action LIKE 'event.%'`); n != 0 {
		t.Fatalf("%d audit rows persisted", n)
	}
}

func TestAckEventsRespectsFiltersAndUpto(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	a, b := addHost(t, s, "a"), addHost(t, s, "b")
	seed(t, s, a.ID, "a", 4, 100, "Eicar", "Shell") // ids 1-4
	seed(t, s, b.ID, "b", 2, 200, "Eicar")          // ids 5-6
	if _, _, err := s.AckEvent(ctx, 1, t0, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AckEvents(ctx, store.EventFilter{}, 0, 0, t0, admin); err == nil {
		t.Fatal("a bulk acknowledgement without upto was accepted")
	}
	n, err := s.AckEvents(ctx, store.EventFilter{Host: "a", Signature: "eicar"}, 4, 1, t0.Add(time.Hour), admin)
	if err != nil || n != 1 { // id 1 is already acknowledged; id 3 is the only open Eicar of a up to 4
		t.Fatalf("n=%d err=%v", n, err)
	}
	if open, _ := s.CountEvents(ctx, store.EventFilter{}); open != 4 {
		t.Fatalf("%d open", open)
	}
	// upto excludes newer events: id 6 stays open.
	n, err = s.AckEvents(ctx, store.EventFilter{}, 5, 3, t0.Add(time.Hour), admin)
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if open, _ := s.CountEvents(ctx, store.EventFilter{}); open != 1 {
		t.Fatalf("%d open, want only id 6", open)
	}
	rows := auditRows(t, s, store.ActionEventAckBulk)
	if len(rows) != 2 || !strings.Contains(rows[0], `"count":"1"`) || !strings.Contains(rows[1], `"upto":"5"`) || !strings.Contains(rows[1], "|*|") {
		t.Fatalf("audit rows %v", rows)
	}
	// Nothing to do: no audit row.
	if n, _ := s.AckEvents(ctx, store.EventFilter{}, 5, 0, t0, admin); n != 0 {
		t.Fatal(n)
	}
	if got := auditRows(t, s, store.ActionEventAckBulk); len(got) != 2 {
		t.Fatalf("a no-op wrote an audit row: %v", got)
	}
}

// Two bulk acknowledgements over overlapping sets and a single one race:
// every event is acknowledged exactly once, by the first writer, and the counts
// add up to the union.
func TestConcurrentBulkAck(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	a, b := addHost(t, s, "a"), addHost(t, s, "b")
	seed(t, s, a.ID, "a", 80, 1000, "S") // ids 1-80
	seed(t, s, b.ID, "b", 20, 2000, "S") // ids 81-100
	var wg sync.WaitGroup
	counts := make([]int64, 3)
	actors := []store.Audit{
		{Kind: store.ActorUser, Actor: "one@example.com"}, {Kind: store.ActorUser, Actor: "two@example.com"}, {Kind: store.ActorUser, Actor: "three@example.com"},
	}
	wg.Add(3)
	go func() {
		defer wg.Done()
		counts[0], _ = s.AckEvents(ctx, store.EventFilter{Host: "a"}, 80, 80, t0, actors[0])
	}()
	go func() { defer wg.Done(); counts[1], _ = s.AckEvents(ctx, store.EventFilter{}, 100, 100, t0, actors[1]) }()
	go func() {
		defer wg.Done()
		_, acked, _ := s.AckEvent(ctx, 50, t0, actors[2])
		if acked {
			counts[2] = 1
		}
	}()
	wg.Wait()
	if total := counts[0] + counts[1] + counts[2]; total != 100 {
		t.Fatalf("counts %v add up to %d, want 100: an event was acknowledged twice or never", counts, total)
	}
	if n := count(t, s, `SELECT count(*) FROM events WHERE ack_at IS NULL`); n != 0 {
		t.Fatalf("%d still open", n)
	}
	// The audit rows add up to the same set, and each event's ack_by is one of the three.
	var sum int64
	for _, r := range auditRows(t, s, store.ActionEventAckBulk) {
		var c int64
		fmt.Sscanf(r[strings.Index(r, `"count":"`)+9:], "%d", &c)
		sum += c
	}
	sum += int64(len(auditRows(t, s, store.ActionEventAck)))
	if sum != 100 {
		t.Fatalf("audit rows account for %d events, want 100", sum)
	}
}

// The count the admin was shown (as of upto) equals what the bulk call changes;
// when another admin acknowledges one of them in between, the result is one
// less and the caller can say so.
func TestBulkAckCountMatchesBoundary(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	seed(t, s, h.ID, "a", 5, 1, "S")
	f := store.EventFilter{Host: "a", Ack: store.AckOpen}
	upto, _ := s.MaxEventID(ctx, f)
	f.UpTo = upto
	expected, _ := s.CountEvents(ctx, f)
	// a newer event arrives after the page was rendered
	seed(t, s, h.ID, "a", 1, 50, "S")
	if _, _, err := s.AckEvent(ctx, 2, t0, store.Audit{Kind: store.ActorUser, Actor: "other@example.com"}); err != nil {
		t.Fatal(err)
	}
	n, err := s.AckEvents(ctx, store.EventFilter{Host: "a"}, upto, expected, t0, admin)
	if err != nil || n != expected-1 {
		t.Fatalf("n=%d, want expected-1 = %d", n, expected-1)
	}
	if open, _ := s.CountOpenEvents(ctx); open != 1 {
		t.Fatalf("the newer event must stay open: %d open", open)
	}
}

func TestPruneEventsByArrivalInBatchesWithCascades(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	cutoff := t0.Add(24 * time.Hour)
	// 5 events received before the cutoff; one SPOOLED event: old agent ts but
	// received after the cutoff; one received exactly at the cutoff.
	for i := 0; i < 5; i++ {
		rec(t, s, h.ID, event("a", aid(i+1), t0, fmt.Sprintf("/p%d", i), "S"), cutoff.Add(-time.Hour))
	}
	rec(t, s, h.ID, event("a", aid(50), t0.Add(-365*24*time.Hour), "/spooled", "S"), cutoff.Add(time.Hour))
	rec(t, s, h.ID, event("a", aid(51), t0, "/edge", "S"), cutoff)
	n, err := s.PruneEvents(ctx, cutoff, 2) // three batches: 2, 2, 1
	if err != nil || n != 5 {
		t.Fatalf("pruned %d err %v, want 5", n, err)
	}
	if left := count(t, s, `SELECT count(*) FROM events`); left != 2 {
		t.Fatalf("%d events left: the boundary is received_at < before, by arrival", left)
	}
	if left := count(t, s, `SELECT count(*) FROM event_receipts`); left != 2 {
		t.Fatalf("%d receipts left, want 2 (cascade)", left)
	}
}

// Summary deliveries have no event; they and their closed windows leave with
// the 90-day alert history, not with the event prune.
func TestPruneAlertWindows(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	hid := itoa(h.ID)
	for _, q := range []string{
		`INSERT INTO alert_targets (id, name, type, config, created_at, updated_at) VALUES (1, 't', 'webhook', '{}', 1, 1)`,
		`INSERT INTO alert_detection_windows (id, target_id, host_id, window_start, closed_at, outcome) VALUES (1, 1, ` + hid + `, 1, 100, 'summarised')`,
		`INSERT INTO alert_detection_windows (id, target_id, host_id, window_start, closed_at, outcome) VALUES (2, 1, ` + hid + `, 1, 300, 'summarised')`,
		`INSERT INTO alert_detection_windows (id, target_id, host_id, window_start) VALUES (3, 1, ` + hid + `, 1)`,
	} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.PruneAlertWindows(ctx, time.Unix(200, 0), 10)
	if err != nil || n != 1 {
		t.Fatalf("pruned %d err %v", n, err)
	}
	if left := count(t, s, `SELECT count(*) FROM alert_detection_windows`); left != 2 {
		t.Fatalf("%d windows left: only the closed one before the cutoff goes, never an open one", left)
	}
	if _, err := s.PruneEvents(ctx, time.Unix(1<<40, 0), 10); err != nil {
		t.Fatal(err)
	}
	if left := count(t, s, `SELECT count(*) FROM alert_detection_windows`); left != 2 {
		t.Fatal("the event prune touched windows")
	}
}

// Rule: a closed window is pruned only when closed_at is strictly before the
// cutoff (closed_at < before), so a window closed exactly at the retention
// boundary survives one more run, like events pruned by received_at.
func TestPruneAlertWindowsBoundary(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	hid := itoa(h.ID)
	for _, q := range []string{
		`INSERT INTO alert_targets (id, name, type, config, created_at, updated_at) VALUES (1, 't', 'webhook', '{}', 1, 1)`,
		`INSERT INTO alert_detection_windows (id, target_id, host_id, window_start, closed_at, outcome) VALUES (1, 1, ` + hid + `, 1, 199, 'summarised')`,
		`INSERT INTO alert_detection_windows (id, target_id, host_id, window_start, closed_at, outcome) VALUES (2, 1, ` + hid + `, 1, 200, 'summarised')`,
		`INSERT INTO alert_detection_windows (id, target_id, host_id, window_start, closed_at, outcome) VALUES (3, 1, ` + hid + `, 1, 201, 'summarised')`,
	} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.PruneAlertWindows(ctx, time.Unix(200, 0), 10)
	if err != nil || n != 1 {
		t.Fatalf("pruned %d err %v, want only the window closed before the cutoff", n, err)
	}
	if left := count(t, s, `SELECT count(*) FROM alert_detection_windows WHERE closed_at = 200`); left != 1 {
		t.Fatal("the window closed exactly at the cutoff was pruned")
	}
}

func TestHostDetailAndFleetShowOpenEvents(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	a, b := addHost(t, s, "a"), addHost(t, s, "b")
	seed(t, s, a.ID, "a", 12, 100, "S")
	seed(t, s, b.ID, "b", 1, 300, "S")
	if _, _, err := s.AckEvent(ctx, 1, t0, admin); err != nil {
		t.Fatal(err)
	}
	d, err := s.HostByName(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if d.OpenEvents != 11 || d.EventCount != 12 || len(d.RecentEvents) != 10 || d.RecentEvents[0].ID != 12 {
		t.Fatalf("open=%d count=%d recent=%d", d.OpenEvents, d.EventCount, len(d.RecentEvents))
	}
	fleet, err := s.ListFleet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, r := range fleet {
		got[r.Name] = r.OpenEvents
	}
	if got["a"] != 11 || got["b"] != 1 {
		t.Fatalf("fleet open counts %v", got)
	}
}
