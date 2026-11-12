// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
)

func reasons(rules ...string) json.RawMessage {
	b, _ := json.Marshal(rules)
	return b
}

// fixed answers the same outcome for every host.
func fixed(state string, rs ...string) func(store.HealthInput) store.HealthOutcome {
	return func(store.HealthInput) store.HealthOutcome {
		return store.HealthOutcome{State: state, Reasons: reasons(rs...)}
	}
}

func repDaily(host string, ts time.Time, version int) proto.Report {
	r := rep(host, ts, "0.1.0")
	r.Sigs.Daily = &proto.SigDB{Version: version, Built: ts, Sigs: 1}
	r.Clamd.Version = ptrS("1.4.3")
	return r
}

func ptrS(s string) *string { return &s }

func stateOf(t *testing.T, s *Store, name string) store.HostDetail {
	t.Helper()
	d, err := s.HostByName(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestEvaluateHostsWritesTransitionsOnly(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "web01")

	// First evaluation: from_state is NULL (M3 decision 5).
	tr, err := s.EvaluateHosts(ctx, t0, nil, fixed("OK"))
	if err != nil || len(tr) != 1 || tr[0].From != nil || tr[0].To != "OK" || tr[0].Host != "web01" || !tr[0].TS.Equal(t0) {
		t.Fatalf("first evaluation: %+v %v", tr, err)
	}
	// Nothing changed: no row, state_since stays.
	if tr, err = s.EvaluateHosts(ctx, t0.Add(time.Minute), nil, fixed("OK")); err != nil || len(tr) != 0 {
		t.Fatalf("unchanged: %+v %v", tr, err)
	}
	// Same state, other reasons: the reasons are updated, no history row, state_since stays.
	if tr, err = s.EvaluateHosts(ctx, t0.Add(2*time.Minute), nil, fixed("OK", "x")); err != nil || len(tr) != 0 {
		t.Fatalf("reason-only change: %+v %v", tr, err)
	}
	d := stateOf(t, s, "web01")
	if d.State == nil || *d.State != "OK" || string(d.StateReason) != `["x"]` || !d.StateSince.Equal(t0) {
		t.Fatalf("after reason-only change: state %v reason %s since %v", d.State, d.StateReason, d.StateSince)
	}
	if n := count(t, s, `SELECT count(*) FROM state_changes WHERE host_id=?`, h.ID); n != 1 {
		t.Fatalf("%d history rows, want 1", n)
	}
	// OK -> CRIT: exactly one more row, with the injected time.
	when := t0.Add(time.Hour)
	tr, err = s.EvaluateHosts(ctx, when, nil, fixed("CRIT", "clamd_down"))
	if err != nil || len(tr) != 1 || *tr[0].From != "OK" || tr[0].To != "CRIT" {
		t.Fatalf("OK->CRIT: %+v %v", tr, err)
	}
	d = stateOf(t, s, "web01")
	if *d.State != "CRIT" || !d.StateSince.Equal(when) || len(d.StateChanges) != 2 {
		t.Fatalf("%+v", d)
	}
	last := d.StateChanges[0] // newest first
	if last.From == nil || *last.From != "OK" || last.To != "CRIT" || !last.TS.Equal(when) || string(last.Reason) != `["clamd_down"]` {
		t.Fatalf("newest change: %+v", last)
	}
	if first := d.StateChanges[1]; first.From != nil || first.To != "OK" {
		t.Fatalf("oldest change: %+v", first)
	}
}

func TestEvaluateHostsPendingWritesNothing(t *testing.T) {
	s := openTemp(t)
	addHost(t, s, "new01")
	tr, err := s.EvaluateHosts(context.Background(), t0, nil, fixed(""))
	if err != nil || len(tr) != 0 {
		t.Fatalf("%+v %v", tr, err)
	}
	d := stateOf(t, s, "new01")
	n := count(t, s, `SELECT count(*) FROM state_changes`)
	if d.State != nil || d.StateReason != nil || d.StateSince != nil || n != 0 {
		t.Fatalf("a pending host must stay NULL: %+v (%d rows)", d, n)
	}
	raw, _ := json.Marshal(d)
	if !strings.Contains(string(raw), `"state":null`) {
		t.Fatalf("pending state must encode as null: %s", raw)
	}
}

// Revoked hosts are not evaluated (their state freezes) and do not set the
// fleet's yardstick; a host without a daily does not poison it either.
func TestEvaluateHostsSkipsRevokedAndComputesFleetNewest(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	a, b, c, rv := addHost(t, s, "a"), addHost(t, s, "b"), addHost(t, s, "c"), addHost(t, s, "revoked")
	record(t, s, a.ID, repDaily("a", t0, 100), t0)
	record(t, s, b.ID, rep("b", t0, "0.1.0"), t0) // no daily at all
	record(t, s, rv.ID, repDaily("revoked", t0, 999), t0)
	_ = c
	if err := s.SetToken(ctx, "revoked", nil, t0, cli); err != nil {
		t.Fatal(err)
	}

	seen := map[string]store.HealthInput{}
	_, err := s.EvaluateHosts(ctx, t0, nil, func(in store.HealthInput) store.HealthOutcome {
		seen[in.Name] = in
		return store.HealthOutcome{State: "OK"}
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := seen["revoked"]; ok || len(seen) != 3 {
		t.Fatalf("evaluated hosts: %v", seen)
	}
	for name, in := range seen {
		if in.FleetNewestDaily != 100 {
			t.Errorf("%s: fleet newest %d, want 100 (the revoked host's 999 must not count)", name, in.FleetNewestDaily)
		}
	}
	if in := seen["a"]; in.Report == nil || in.LastSeen == nil || !in.LastSeen.Equal(t0) || in.Report.Sigs.Daily.Version != 100 {
		t.Fatalf("input of a: %+v", in)
	}
	if in := seen["c"]; in.Report != nil || in.LastSeen != nil {
		t.Fatalf("input of a host without a report: %+v", in)
	}
	if d := stateOf(t, s, "revoked"); d.State != nil {
		t.Fatalf("a revoked host was evaluated: %v", *d.State)
	}
}

func TestEvaluateHostsSubsetAndUnknownIDs(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	a, _ := addHost(t, s, "a"), addHost(t, s, "b")
	tr, err := s.EvaluateHosts(ctx, t0, []int64{a.ID, 9999}, fixed("WARN", "w"))
	if err != nil || len(tr) != 1 || tr[0].Host != "a" {
		t.Fatalf("%+v %v", tr, err)
	}
	if d := stateOf(t, s, "b"); d.State != nil {
		t.Fatal("host b was not asked for")
	}
	if tr, err = s.EvaluateHosts(ctx, t0, []int64{}, fixed("WARN")); err != nil || len(tr) != 0 {
		t.Fatalf("empty id list means no hosts: %+v %v", tr, err)
	}
}

func TestRecordReportFillsFleetColumns(t *testing.T) {
	s := openTemp(t)
	h := addHost(t, s, "a")
	record(t, s, h.ID, repDaily("a", t0, 100), t0)
	type cols struct {
		v, built int64
		clamd    string
	}
	get := func() (c cols) {
		if err := s.r.QueryRow(`SELECT daily_version, daily_built, clamd_version FROM hosts WHERE id=?`, h.ID).Scan(&c.v, &c.built, &c.clamd); err != nil {
			t.Fatal(err)
		}
		return
	}
	if got := get(); !reflect.DeepEqual(got, cols{100, t0.Unix(), "1.4.3"}) {
		t.Fatalf("%+v", got)
	}
	// An older report (late arrival) must not roll the columns back.
	record(t, s, h.ID, repDaily("a", t0.Add(-time.Hour), 50), t0.Add(time.Minute))
	if got := get(); got.v != 100 {
		t.Fatalf("older report overwrote the fleet columns: %+v", got)
	}
	// A newer report without a daily clears them (the host lost its database).
	record(t, s, h.ID, rep("a", t0.Add(time.Hour), "0.1.0"), t0.Add(time.Hour))
	var v *int64
	if err := s.r.QueryRow(`SELECT daily_version FROM hosts WHERE id=?`, h.ID).Scan(&v); err != nil || v != nil {
		t.Fatalf("daily_version = %v, %v; want NULL", v, err)
	}
}

// The interleaving the plan (4.2) exists for: an evaluation reads a host as
// silent; while it holds its inputs a report arrives and is evaluated OK. The
// report must wait for the first evaluation to commit, so the history reads
// NULL->STALE, STALE->OK and the final state is OK. With the inputs read
// outside the write lock, the late STALE would overwrite the OK.
func TestEvaluateHostsReadsAndWritesUnderOneLock(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	record(t, s, h.ID, rep("a", t0, "0.1.0"), t0)

	// A rule just like the real one: silent for over an hour is STALE.
	now := t0.Add(2 * time.Hour)
	eval := func(in store.HealthInput) store.HealthOutcome {
		if now.Sub(*in.LastSeen) > time.Hour {
			return store.HealthOutcome{State: "STALE", Reasons: reasons("stale")}
		}
		return store.HealthOutcome{State: "OK", Reasons: reasons()}
	}
	done := make(chan error, 1)
	var once sync.Once // the competing evaluation passes through the hook too
	s.beforeHealthWrite = func() error {
		once.Do(func() {
			go func() {
				// The report that arrives mid-evaluation, followed by its own evaluation.
				if _, err := s.RecordReport(ctx, store.ReportRecord{HostID: h.ID, Report: rep("a", now, "0.1.0"), ReceivedAt: now}); err != nil {
					done <- err
					return
				}
				_, err := s.EvaluateHosts(ctx, now, []int64{h.ID}, eval)
				done <- err
			}()
			// Correct code: the goroutine is blocked on the write lock for the whole
			// window. A design that read outside the lock lets it finish inside it.
			select {
			case err := <-done:
				done <- err
			case <-time.After(300 * time.Millisecond):
			}
		})
		return nil
	}
	if _, err := s.EvaluateHosts(ctx, now, nil, eval); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	d := stateOf(t, s, "a")
	if d.State == nil || *d.State != "OK" {
		t.Fatalf("final state %v, want OK: the stale evaluation overwrote the newer one", d.State)
	}
	var got []string
	for i := len(d.StateChanges) - 1; i >= 0; i-- {
		c := d.StateChanges[i]
		from := "NULL"
		if c.From != nil {
			from = *c.From
		}
		got = append(got, from+">"+c.To)
	}
	if want := []string{"NULL>STALE", "STALE>OK"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("history %v, want %v", got, want)
	}
}

// DeleteHost removes everything of the host, including its state history, and
// the audit row (same transaction, host name as text) survives it.
func TestDeleteHostCascadesAndAudits(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "Gone01")
	other := addHost(t, s, "stays")
	record(t, s, h.ID, repDaily("gone01", t0, 100), t0)
	if _, err := s.EvaluateHosts(ctx, t0, nil, fixed("OK")); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteHost(ctx, "GONE01", t0.Add(time.Hour), cli); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HostByName(ctx, "gone01"); err != store.ErrNotFound {
		t.Fatalf("host still there: %v", err)
	}
	for _, tbl := range []string{"host_tags", "reports", "events"} {
		if n := count(t, s, "SELECT count(*) FROM "+tbl+" WHERE host_id=?", h.ID); n != 0 {
			t.Errorf("%s: %d rows left", tbl, n)
		}
	}
	if n := count(t, s, `SELECT count(*) FROM state_changes WHERE host_id=?`, h.ID); n != 0 {
		t.Errorf("state_changes: %d rows left", n)
	}
	if n := count(t, s, `SELECT count(*) FROM state_changes WHERE host_id=?`, other.ID); n != 1 {
		t.Errorf("the other host's history was touched: %d rows", n)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action=? AND target=? AND ts=?`, store.ActionHostDelete, "gone01", t0.Add(time.Hour).Unix()); n != 1 {
		t.Errorf("host.delete audit rows: %d, want 1", n)
	}
	if err := s.DeleteHost(ctx, "gone01", t0, cli); err != store.ErrNotFound {
		t.Fatalf("second delete: %v, want ErrNotFound", err)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action=?`, store.ActionHostDelete); n != 1 {
		t.Errorf("a failed delete wrote an audit row")
	}
}
