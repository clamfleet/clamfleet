// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/alert"
	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
)

const testCooldown = 15 * time.Minute

// planner returns the real pure planner with deterministic ids.
func planner() func(store.AlertPlanInput) store.AlertPlanOutput {
	n := 0
	return alert.Planner{PublicURL: "https://cf.example", NewID: func() string { n++; return fmt.Sprintf("alert%04d", n) }}.Plan
}

func newTarget(t *testing.T, s *Store, name, typ string, edit func(*store.NewAlertTarget)) store.AlertTarget {
	t.Helper()
	nt := store.NewAlertTarget{Name: name, Type: typ, Config: []byte(`{}`), MinSeverity: "WARN",
		SendStateChanges: true, SendDetections: true, Enabled: true}
	if typ == store.TargetTypeEmail {
		nt.Config = []byte(`{"to":["a@x.example"]}`)
	}
	if edit != nil {
		edit(&nt)
	}
	var seal func(int64) ([]byte, error)
	if typ == store.TargetTypeWebhook {
		seal = func(id int64) ([]byte, error) { return []byte(fmt.Sprintf("sealed-%d-%s", id, name)), nil }
	}
	tg, err := s.CreateAlertTarget(context.Background(), nt, seal, t0, cli)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

// transition makes the host go to state at `at` through the real EvaluateHosts.
func transition(t *testing.T, s *Store, at time.Time, state string) {
	t.Helper()
	if _, err := s.EvaluateHosts(context.Background(), at, nil, fixed(state, "r_"+state)); err != nil {
		t.Fatal(err)
	}
}

func plan(t *testing.T, s *Store, now time.Time) store.PlanResult {
	t.Helper()
	res, err := s.PlanAlerts(context.Background(), now, testCooldown, planner())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func statusCount(t *testing.T, s *Store, status string) int {
	t.Helper()
	return count(t, s, `SELECT count(*) FROM alert_deliveries WHERE status = ?`, status)
}

func TestAlertTargetCreateUpdateDeleteAndAudit(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	tg := newTarget(t, s, "ops", "webhook", nil)
	if string(tg.Sealed) != fmt.Sprintf("sealed-%d-ops", tg.ID) {
		t.Fatalf("seal must be called with the new id: %q", tg.Sealed)
	}
	if _, err := s.CreateAlertTarget(ctx, store.NewAlertTarget{Name: "OPS", Type: "webhook", MinSeverity: "WARN"}, nil, t0, cli); !errors.Is(err, store.ErrTargetExists) {
		t.Fatalf("a taken name (any case): %v", err)
	}
	for _, bad := range []string{"new", "", "-x", "a b", strings.Repeat("a", 65), "a/b"} {
		if _, err := s.CreateAlertTarget(ctx, store.NewAlertTarget{Name: bad, Type: "email", MinSeverity: "WARN"}, nil, t0, cli); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	if _, err := s.CreateAlertTarget(ctx, store.NewAlertTarget{Name: "x", Type: "syslog", MinSeverity: "WARN"}, nil, t0, cli); err == nil {
		t.Error("unknown type accepted")
	}
	if _, err := s.CreateAlertTarget(ctx, store.NewAlertTarget{Name: "x", Type: "email", MinSeverity: "OK"}, nil, t0, cli); err == nil {
		t.Error("min severity OK accepted")
	}

	got, err := s.AlertTarget(ctx, "ops")
	if err != nil || got.ID != tg.ID || !got.Enabled || got.MinSeverity != "WARN" || string(got.Sealed) != string(tg.Sealed) {
		t.Fatalf("%+v %v", got, err)
	}
	c, err := s.UpdateAlertTarget(ctx, "ops", store.AlertTargetUpdate{Config: []byte(`{}`), MinSeverity: "CRIT", TagFilter: []string{"prod"},
		SendStateChanges: true, SendDetections: true, Enabled: true}, nil, t0.Add(time.Minute), cli)
	if err != nil || c.Deliveries != 0 {
		t.Fatalf("%+v %v", c, err)
	}
	got, _ = s.AlertTarget(ctx, "ops")
	if got.MinSeverity != "CRIT" || len(got.TagFilter) != 1 || string(got.Sealed) != string(tg.Sealed) {
		t.Fatalf("update must keep the secret when seal is nil: %+v", got)
	}
	// An update that changes nothing writes no audit row.
	before := count(t, s, `SELECT count(*) FROM audit_log`)
	if _, err := s.UpdateAlertTarget(ctx, "ops", store.AlertTargetUpdate{Config: []byte(`{}`), MinSeverity: "CRIT", TagFilter: []string{"prod"},
		SendStateChanges: true, SendDetections: true, Enabled: true}, nil, t0, cli); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT count(*) FROM audit_log`) != before {
		t.Fatal("a no-op update was audited")
	}
	if _, err := s.UpdateAlertTarget(ctx, "nope", store.AlertTargetUpdate{MinSeverity: "WARN"}, nil, t0, cli); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if err := s.RotateAlertSecret(ctx, "ops", func(id int64) ([]byte, error) { return []byte("rotated"), nil }, t0, cli); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.AlertTarget(ctx, "ops"); string(got.Sealed) != "rotated" {
		t.Fatalf("%q", got.Sealed)
	}
	em := newTarget(t, s, "mail", "email", nil)
	if err := s.RotateAlertSecret(ctx, em.Name, func(int64) ([]byte, error) { return nil, nil }, t0, cli); err == nil {
		t.Fatal("an email target has no key to rotate")
	}
	if err := s.DeleteAlertTarget(ctx, "ops", t0, cli); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AlertTarget(ctx, "ops"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("%v", err)
	}
	var actions []string
	rows, _ := s.r.Query(`SELECT action || ':' || detail FROM audit_log WHERE target_kind = 'alert_target' ORDER BY id`)
	for rows.Next() {
		var a string
		rows.Scan(&a)
		actions = append(actions, a)
	}
	rows.Close()
	joined := strings.Join(actions, "\n")
	for _, want := range []string{`alert_target.add:{"type":"webhook"}`, `alert_target.update:{"fields":"min_severity,tag_filter"}`, "alert_target.secret.rotate:", `alert_target.delete:{"type":"webhook"}`} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit lacks %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "sealed") || strings.Contains(joined, "rotated") {
		t.Fatalf("a secret reached the audit log:\n%s", joined)
	}
}

// PlanAlerts right after an upgrade creates no delivery: old rows are 0.
func TestPlanAlertsAfterUpgradeCreatesNothing(t *testing.T) {
	s := openTemp(t)
	h := addHost(t, s, "web01")
	newTarget(t, s, "ops", "webhook", nil)
	// History written before the upgrade: flag 0, as the migration leaves it.
	if _, err := s.w.Exec(`INSERT INTO state_changes (host_id, ts, from_state, to_state, reason, alert_pending) VALUES (?, 1, NULL, 'CRIT', '[]', 0)`, h.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.w.Exec(`INSERT INTO events (host_id, ts, received_at, path, signature, source, alert_pending) VALUES (?, 1, 1, '/x', 'S', 'scan', 0)`, h.ID); err != nil {
		t.Fatal(err)
	}
	res := plan(t, s, t0)
	if len(res.Deliveries) != 0 || count(t, s, `SELECT count(*) FROM alert_deliveries`) != 0 {
		t.Fatalf("history produced deliveries: %+v", res)
	}
	ok, err := s.HasAlertWork(context.Background(), t0, testCooldown)
	if err != nil || ok {
		t.Fatalf("HasAlertWork on a quiet database: %v %v", ok, err)
	}
}

func TestPlanAlertsWritesDeliveriesAndClearsFlags(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "web01")
	newTarget(t, s, "ops", "webhook", nil)
	newTarget(t, s, "mail", "email", func(n *store.NewAlertTarget) { n.Config = []byte(`{"to":["a@x.example","b@x.example"]}`) })
	transition(t, s, t0, "CRIT")
	if ok, _ := s.HasAlertWork(ctx, t0, testCooldown); !ok {
		t.Fatal("a flagged state change is work")
	}
	res := plan(t, s, t0)
	if len(res.Deliveries) != 3 {
		t.Fatalf("1 webhook + 2 recipients = 3 deliveries, got %d", len(res.Deliveries))
	}
	if n := count(t, s, `SELECT count(*) FROM state_changes WHERE alert_pending = 1`); n != 0 {
		t.Fatalf("flags not cleared: %d", n)
	}
	if n := count(t, s, `SELECT count(DISTINCT alert_id) FROM alert_deliveries`); n != 1 {
		t.Fatalf("one alert id expected: %d", n)
	}
	var p alert.StateChangePayload
	var raw string
	if err := s.r.QueryRow(`SELECT payload FROM alert_deliveries WHERE recipient = ''`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(raw), &p); err != nil || p.Host != "web01" || p.To != "CRIT" || p.Target != "ops" || p.From != nil {
		t.Fatalf("%+v %v", p, err)
	}
	// Planning again does nothing: the work is done.
	if again := plan(t, s, t0); len(again.Deliveries) != 0 {
		t.Fatalf("replanned: %+v", again)
	}
	if n := count(t, s, `SELECT count(*) FROM alert_notify_state WHERE last_state = 'CRIT'`); n != 2 {
		t.Fatalf("notify rows: %d", n)
	}
}

// Mutation 3: clearing the flags outside the planning transaction would leave
// them cleared (alerts lost) when the writes fail.
func TestPlanAlertsIsAtomic(t *testing.T) {
	s := openTemp(t)
	addHost(t, s, "web01")
	newTarget(t, s, "ops", "webhook", nil)
	transition(t, s, t0, "CRIT")
	if _, err := s.RecordEvent(context.Background(), store.EventRecord{HostID: 1, ReceivedAt: t0,
		Event: proto.Event{TS: t0, Path: "/p", Signature: "s", Source: "scan"}}); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	s.beforeAlertPlanWrite = func() error { return boom }
	if _, err := s.PlanAlerts(context.Background(), t0, testCooldown, planner()); !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
	s.beforeAlertPlanWrite = nil
	for q, want := range map[string]int{
		`SELECT count(*) FROM alert_deliveries`:                      0,
		`SELECT count(*) FROM alert_notify_state`:                    0,
		`SELECT count(*) FROM alert_log`:                             0,
		`SELECT count(*) FROM state_changes WHERE alert_pending = 1`: 1,
		`SELECT count(*) FROM events WHERE alert_pending = 1`:        1,
	} {
		if got := count(t, s, q); got != want {
			t.Errorf("%s = %d, want %d", q, got, want)
		}
	}
	if res := plan(t, s, t0); len(res.Deliveries) != 2 { // state change + detection
		t.Fatalf("the retry after the failure must plan everything: %+v", res)
	}
}

func TestClaimDeliveriesCapacityOrderAndLease(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	for i := 0; i < 6; i++ {
		addHost(t, s, fmt.Sprintf("h%d", i))
	}
	newTarget(t, s, "ops", "webhook", nil)
	transition(t, s, t0, "CRIT")
	plan(t, s, t0)
	if n := statusCount(t, s, "pending"); n != 6 {
		t.Fatalf("%d pending", n)
	}
	lease := 40 * time.Second
	got, err := s.ClaimDeliveries(ctx, t0, lease, 4)
	if err != nil || len(got) != 4 {
		t.Fatalf("claimed %d: %v (never more than max)", len(got), err)
	}
	if n := count(t, s, `SELECT count(*) FROM alert_deliveries WHERE attempts = 1 AND claim_token IS NOT NULL`); n != 4 {
		t.Fatalf("%d claimed rows with attempt 1 and a token", n)
	}
	if n := count(t, s, `SELECT count(*) FROM alert_deliveries WHERE attempts = 0 AND claim_token IS NULL`); n != 2 {
		t.Fatalf("%d untouched rows", n)
	}
	if n := count(t, s, `SELECT count(*) FROM alert_log WHERE status = 'attempting'`); n != 4 {
		t.Fatalf("%d attempting rows", n)
	}
	for _, c := range got {
		if len(c.Token) != 16 || c.Attempt != 1 || c.Target.Name != "ops" || string(c.Target.Sealed) == "" || c.LogID == 0 {
			t.Fatalf("%+v", c)
		}
	}
	// Claimed rows are not claimed again until their lease ends; the other two are.
	more, _ := s.ClaimDeliveries(ctx, t0.Add(time.Second), lease, 10)
	if len(more) != 2 {
		t.Fatalf("second claim got %d, want the 2 unclaimed", len(more))
	}
	if again, _ := s.ClaimDeliveries(ctx, t0.Add(2*time.Second), lease, 10); len(again) != 0 {
		t.Fatalf("a claimed row was claimed again inside its lease: %d", len(again))
	}
	if none, _ := s.ClaimDeliveries(ctx, t0, lease, 0); len(none) != 0 {
		t.Fatal("max 0 must claim nothing")
	}
}

// Mutation 10: an older pending delivery for the same (target, host,
// recipient) blocks a newer one; another host or recipient is not blocked.
func TestClaimDeliveriesKeepsOrderPerTargetHostRecipient(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	addHost(t, s, "b")
	newTarget(t, s, "mail", "email", func(n *store.NewAlertTarget) { n.Config = []byte(`{"to":["r1@x.example","r2@x.example"]}`) })
	// Host a: CRIT planned now, OK planned 20 minutes later (outside the cooldown).
	if _, err := s.EvaluateHosts(ctx, t0, []int64{1}, fixed("CRIT")); err != nil {
		t.Fatal(err)
	}
	plan(t, s, t0)
	if _, err := s.EvaluateHosts(ctx, t0.Add(20*time.Minute), []int64{1}, fixed("OK")); err != nil {
		t.Fatal(err)
	}
	plan(t, s, t0.Add(20*time.Minute))
	// Host b: one CRIT.
	if _, err := s.EvaluateHosts(ctx, t0.Add(21*time.Minute), []int64{2}, fixed("CRIT")); err != nil {
		t.Fatal(err)
	}
	plan(t, s, t0.Add(21*time.Minute))
	if n := statusCount(t, s, "pending"); n != 6 { // 3 alerts x 2 recipients
		t.Fatalf("%d pending", n)
	}
	got, err := s.ClaimDeliveries(ctx, t0.Add(22*time.Minute), time.Minute, 100)
	if err != nil {
		t.Fatal(err)
	}
	var recov, crit int
	for _, c := range got {
		var p alert.StateChangePayload
		json.Unmarshal(c.Payload, &p)
		if p.Host == "a" && p.To == "OK" {
			recov++
		} else {
			crit++
		}
	}
	// a's recovery is blocked behind a's CRIT for both recipients; a's CRIT x2 and b's CRIT x2 go.
	if recov != 0 || crit != 4 {
		t.Fatalf("claimed %d recoveries and %d crit deliveries; want 0 and 4", recov, crit)
	}
	// Finish a's first CRIT delivery for r1 only: r1's recovery is now free, r2's is not.
	var first store.ClaimedDelivery
	for _, c := range got {
		if c.HostName == "a" && c.Recipient == "r1@x.example" {
			first = c
		}
	}
	if err := s.FinishAttempt(ctx, first, store.AttemptResult{Status: store.AlertLogSent, Code: "SMTP 250"}, t0.Add(23*time.Minute)); err != nil {
		t.Fatal(err)
	}
	next, _ := s.ClaimDeliveries(ctx, t0.Add(24*time.Minute), time.Minute, 100)
	if len(next) != 1 || next[0].Recipient != "r1@x.example" || next[0].HostName != "a" {
		t.Fatalf("only r1's recovery may be claimed now: %+v", next)
	}
	// A terminal 'failed' delivery no longer blocks.
	var r2 store.ClaimedDelivery
	for _, c := range got {
		if c.HostName == "a" && c.Recipient == "r2@x.example" {
			r2 = c
		}
	}
	if err := s.FinishAttempt(ctx, r2, store.AttemptResult{Status: store.AlertLogFailed, Code: "SMTP 550"}, t0.Add(25*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if last, _ := s.ClaimDeliveries(ctx, t0.Add(26*time.Minute), time.Minute, 100); len(last) != 1 || last[0].Recipient != "r2@x.example" {
		t.Fatalf("%+v", last)
	}
}

func TestClaimDeliveriesSkipsDisabledTargetAndSwitchedOffKind(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	h := addHost(t, s, "a")
	newTarget(t, s, "ops", "webhook", nil)
	transition(t, s, t0, "CRIT")
	plan(t, s, t0)
	// Flip the switches behind the store's back: the claim itself must check them.
	for _, q := range []string{`UPDATE alert_targets SET enabled = 0`, `UPDATE alert_targets SET enabled = 1, send_state_changes = 0`} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.ClaimDeliveries(ctx, t0, time.Minute, 10); len(got) != 0 {
			t.Fatalf("claimed after %q: %d", q, len(got))
		}
	}
	if _, err := s.w.Exec(`UPDATE alert_targets SET send_state_changes = 1`); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ClaimDeliveries(ctx, t0, time.Minute, 10); len(got) != 1 || got[0].HostID != h.ID {
		t.Fatalf("%+v", got)
	}
}

// Mutation 13: FinishAttempt without the claim_token condition.
func TestFinishAttemptTokenAndCancellation(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	newTarget(t, s, "ops", "webhook", nil)
	transition(t, s, t0, "CRIT")
	plan(t, s, t0)

	first, _ := s.ClaimDeliveries(ctx, t0, 40*time.Second, 1)
	if len(first) != 1 {
		t.Fatal("no claim")
	}
	// The lease expires and the row is claimed again (a new token, attempt 2).
	if _, _, err := s.ExpireLeases(ctx, t0.Add(time.Minute), false); err != nil {
		t.Fatal(err)
	}
	second, _ := s.ClaimDeliveries(ctx, t0.Add(time.Minute), 40*time.Second, 1)
	if len(second) != 1 || second[0].Attempt != 2 || string(second[0].Token) == string(first[0].Token) {
		t.Fatalf("%+v", second)
	}
	// The first (late) sender now reports a failure: it must change nothing.
	err := s.FinishAttempt(ctx, first[0], store.AttemptResult{Status: store.AlertLogFailed, Code: "HTTP 500"}, t0.Add(2*time.Minute))
	if !errors.Is(err, store.ErrLeaseLost) {
		t.Fatalf("a stale token: %v", err)
	}
	if st := statusCount(t, s, "pending"); st != 1 {
		t.Fatalf("the late result changed the delivery (pending=%d)", st)
	}
	var st string
	s.r.QueryRow(`SELECT status FROM alert_log WHERE id = ?`, second[0].LogID).Scan(&st)
	if st != "attempting" {
		t.Fatalf("the new claim's log row was touched: %s", st)
	}
	s.r.QueryRow(`SELECT status FROM alert_log WHERE id = ?`, first[0].LogID).Scan(&st)
	if st != "interrupted" {
		t.Fatalf("the old attempt's row was rewritten: %s", st)
	}
	// The current claim finishes normally.
	if err := s.FinishAttempt(ctx, second[0], store.AttemptResult{Status: store.AlertLogSent, Code: "HTTP 204", Duration: 5 * time.Millisecond}, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if statusCount(t, s, "sent") != 1 {
		t.Fatal("not sent")
	}

	// A cancelled delivery stays cancelled when its in-flight attempt reports.
	transition(t, s, t0.Add(30*time.Minute), "OK")
	plan(t, s, t0.Add(30*time.Minute))
	third, _ := s.ClaimDeliveries(ctx, t0.Add(30*time.Minute), time.Minute, 1)
	if len(third) != 1 {
		t.Fatal("no third claim")
	}
	if _, err := s.UpdateAlertTarget(ctx, "ops", store.AlertTargetUpdate{Config: []byte(`{}`), MinSeverity: "WARN", SendStateChanges: false, SendDetections: true, Enabled: true}, nil, t0.Add(31*time.Minute), cli); err != nil {
		t.Fatal(err)
	}
	err = s.FinishAttempt(ctx, third[0], store.AttemptResult{Status: store.AlertLogSent, Code: "HTTP 200"}, t0.Add(32*time.Minute))
	if !errors.Is(err, store.ErrLeaseLost) {
		t.Fatalf("a cancelled delivery: %v", err)
	}
	if n := statusCount(t, s, "cancelled"); n != 1 {
		t.Fatalf("the cancelled delivery changed: cancelled=%d sent=%d", n, statusCount(t, s, "sent"))
	}
	// The attempt's own row records whether the message went out.
	s.r.QueryRow(`SELECT status FROM alert_log WHERE id = ?`, third[0].LogID).Scan(&st)
	if st != "sent" {
		t.Fatalf("the in-flight attempt's outcome was lost: %s", st)
	}
}

func TestFinishAttemptRetryingSchedulesNextAttempt(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	newTarget(t, s, "ops", "webhook", nil)
	transition(t, s, t0, "CRIT")
	plan(t, s, t0)
	c, _ := s.ClaimDeliveries(ctx, t0, time.Minute, 1)
	retryAt := t0.Add(time.Minute)
	if err := s.FinishAttempt(ctx, c[0], store.AttemptResult{Status: store.AlertLogRetrying, Code: "HTTP 503", Error: "x", RetryAt: retryAt}, t0); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ClaimDeliveries(ctx, retryAt.Add(-time.Second), time.Minute, 1); len(got) != 0 {
		t.Fatal("claimed before the retry time")
	}
	got, _ := s.ClaimDeliveries(ctx, retryAt, time.Minute, 1)
	if len(got) != 1 || got[0].Attempt != 2 {
		t.Fatalf("%+v", got)
	}
	if err := s.FinishAttempt(ctx, got[0], store.AttemptResult{Status: "bogus"}, t0); err == nil {
		t.Fatal("an invalid status was accepted")
	}
}

// Mutation 14: at MaxAlertAttempts an expired lease ends the delivery, with its
// log row, in one transaction.
func TestExpireLeases(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	newTarget(t, s, "ops", "webhook", nil)
	transition(t, s, t0, "CRIT")
	plan(t, s, t0)

	setAttempts := func(n int) {
		if _, err := s.w.Exec(`UPDATE alert_deliveries SET attempts = ?`, n); err != nil {
			t.Fatal(err)
		}
	}
	// Attempts 3 (claim makes it 4? no: set 2 so the claim is attempt 3).
	setAttempts(2)
	c, _ := s.ClaimDeliveries(ctx, t0, 40*time.Second, 1)
	if c[0].Attempt != 3 {
		t.Fatalf("attempt %d", c[0].Attempt)
	}
	if e, x, err := s.ExpireLeases(ctx, t0.Add(10*time.Second), false); err != nil || e != 0 || x != 0 {
		t.Fatalf("a lease that has not ended was expired: %d %d %v", e, x, err)
	}
	if e, x, err := s.ExpireLeases(ctx, t0.Add(41*time.Second), false); err != nil || e != 1 || x != 0 {
		t.Fatalf("%d %d %v", e, x, err)
	}
	var status string
	s.r.QueryRow(`SELECT status FROM alert_log WHERE id = ?`, c[0].LogID).Scan(&status)
	if status != "interrupted" || statusCount(t, s, "pending") != 1 {
		t.Fatalf("log %s", status)
	}
	if again, _ := s.ClaimDeliveries(ctx, t0.Add(41*time.Second), time.Minute, 1); len(again) != 1 || again[0].Attempt != 4 {
		t.Fatalf("an expired attempt-3 row must be due at once: %+v", again)
	}

	// Attempt 5 interrupted: failed, with finished_at and a failed log row.
	if _, err := s.w.Exec(`UPDATE alert_deliveries SET attempts = 4, claim_token = NULL, next_attempt_at = 0`); err != nil {
		t.Fatal(err)
	}
	s.w.Exec(`UPDATE alert_log SET status = 'interrupted' WHERE status = 'attempting'`)
	c5, _ := s.ClaimDeliveries(ctx, t0.Add(time.Hour), 40*time.Second, 1)
	if len(c5) != 1 || c5[0].Attempt != 5 {
		t.Fatalf("%+v", c5)
	}
	// A hook failing between the two writes rolls both back.
	boom := errors.New("boom")
	s.betweenExpireWrites = func() error { return boom }
	if _, _, err := s.ExpireLeases(ctx, t0.Add(2*time.Hour), false); !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
	s.betweenExpireWrites = nil
	if statusCount(t, s, "failed") != 0 || count(t, s, `SELECT count(*) FROM alert_log WHERE status = 'failed'`) != 0 {
		t.Fatal("a half-done expiry was committed")
	}
	if e, x, err := s.ExpireLeases(ctx, t0.Add(2*time.Hour), false); err != nil || e != 0 || x != 1 {
		t.Fatalf("%d %d %v", e, x, err)
	}
	var fin int64
	s.r.QueryRow(`SELECT finished_at FROM alert_deliveries`).Scan(&fin)
	if statusCount(t, s, "failed") != 1 || fin != t0.Add(2*time.Hour).Unix() ||
		count(t, s, `SELECT count(*) FROM alert_log WHERE status = 'failed' AND error LIKE '%attempt 5 was interrupted%'`) != 1 {
		t.Fatal("the last attempt's expiry must end the delivery with a failed log row")
	}
	if more, _ := s.ClaimDeliveries(ctx, t0.Add(48*time.Hour), time.Minute, 5); len(more) != 0 {
		t.Fatal("a failed delivery was claimed again")
	}
}

// At start every claim belongs to a dead process (all=true), and an
// 'attempting' row of a delivery cancelled meanwhile is closed too.
func TestExpireLeasesAllAtStart(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	newTarget(t, s, "ops", "webhook", nil)
	transition(t, s, t0, "CRIT")
	plan(t, s, t0)
	c, _ := s.ClaimDeliveries(ctx, t0, time.Hour, 1)
	if e, _, _ := s.ExpireLeases(ctx, t0.Add(time.Second), false); e != 0 {
		t.Fatal("not expired yet")
	}
	// Cancel it while claimed, so no claim is left to expire but the log row is.
	if _, err := s.UpdateAlertTarget(ctx, "ops", store.AlertTargetUpdate{Config: []byte(`{}`), MinSeverity: "WARN", Enabled: false, SendStateChanges: true, SendDetections: true}, nil, t0, cli); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ExpireLeases(ctx, t0.Add(time.Second), true); err != nil {
		t.Fatal(err)
	}
	var st string
	s.r.QueryRow(`SELECT status FROM alert_log WHERE id = ?`, c[0].LogID).Scan(&st)
	if st != "interrupted" {
		t.Fatalf("%s", st)
	}
}

// The switch-off rules (4.3), mutation 20.
func TestUpdateAlertTargetSwitchesOff(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) *Store {
		s := openTemp(t)
		addHost(t, s, "a")
		newTarget(t, s, "mail", "email", func(n *store.NewAlertTarget) { n.Config = []byte(`{"to":["a@x.example","b@x.example"]}`) })
		// A state delivery for a and b, a hold, and a pending detection delivery.
		transition(t, s, t0, "CRIT")
		plan(t, s, t0)
		transition(t, s, t0.Add(time.Minute), "OK") // held
		if _, err := s.RecordEvent(ctx, store.EventRecord{HostID: 1, ReceivedAt: t0, Event: proto.Event{TS: t0, Path: "/p", Signature: "s", Source: "scan"}}); err != nil {
			t.Fatal(err)
		}
		plan(t, s, t0.Add(time.Minute))
		if n := count(t, s, `SELECT held_count FROM alert_notify_state`); n != 1 {
			t.Fatalf("no hold: %d", n)
		}
		if n := statusCount(t, s, "pending"); n != 4 {
			t.Fatalf("%d pending (2 recipients x state + detection)", n)
		}
		return s
	}
	upd := func(t *testing.T, s *Store, edit func(*store.AlertTargetUpdate)) store.Cancelled {
		u := store.AlertTargetUpdate{Config: []byte(`{"to":["a@x.example","b@x.example"]}`), MinSeverity: "WARN", SendStateChanges: true, SendDetections: true, Enabled: true}
		edit(&u)
		c, err := s.UpdateAlertTarget(ctx, "mail", u, nil, t0.Add(2*time.Minute), cli)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	t.Run("state changes off", func(t *testing.T) {
		s := setup(t)
		c := upd(t, s, func(u *store.AlertTargetUpdate) { u.SendStateChanges = false })
		if c.Deliveries != 2 || statusCount(t, s, "cancelled") != 2 || statusCount(t, s, "pending") != 2 {
			t.Fatalf("%+v cancelled=%d", c, statusCount(t, s, "cancelled"))
		}
		if count(t, s, `SELECT count(*) FROM alert_notify_state`) != 0 {
			t.Fatal("the notify state and hold must go")
		}
		if count(t, s, `SELECT count(*) FROM alert_log WHERE status = 'cancelled' AND error = 'state changes switched off'`) != 2 {
			t.Fatal("cancelled log rows missing")
		}
		if count(t, s, `SELECT count(*) FROM alert_deliveries WHERE status = 'pending' AND kind = 'detection'`) != 2 {
			t.Fatal("the detection deliveries must stay pending")
		}
		if count(t, s, `SELECT count(*) FROM audit_log WHERE action = 'alert_target.update' AND detail LIKE '%"cancelled":"2"%'`) != 1 {
			t.Fatal("the audit row must say how many were cancelled")
		}
		// Back on: fresh start, nothing is sent for the host's current state.
		upd(t, s, func(u *store.AlertTargetUpdate) {})
		res := plan(t, s, t0.Add(time.Hour))
		if len(res.Deliveries) != 0 {
			t.Fatalf("turning state changes back on alerted: %+v", res.Deliveries)
		}
	})
	t.Run("detections off", func(t *testing.T) {
		s := setup(t)
		c := upd(t, s, func(u *store.AlertTargetUpdate) { u.SendDetections = false })
		if c.Deliveries != 2 || count(t, s, `SELECT count(*) FROM alert_deliveries WHERE status = 'cancelled' AND kind = 'detection'`) != 2 {
			t.Fatalf("%+v", c)
		}
		if count(t, s, `SELECT held_count FROM alert_notify_state`) != 1 {
			t.Fatal("the hold must be untouched")
		}
	})
	t.Run("disabled", func(t *testing.T) {
		s := setup(t)
		c := upd(t, s, func(u *store.AlertTargetUpdate) { u.Enabled = false })
		if c.Deliveries != 4 || statusCount(t, s, "pending") != 0 || count(t, s, `SELECT count(*) FROM alert_notify_state`) != 0 {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("recipient removed", func(t *testing.T) {
		s := setup(t)
		c := upd(t, s, func(u *store.AlertTargetUpdate) { u.Config = []byte(`{"to":["a@x.example"]}`) })
		if c.Deliveries != 2 || count(t, s, `SELECT count(*) FROM alert_deliveries WHERE status = 'cancelled' AND recipient = 'b@x.example'`) != 2 ||
			count(t, s, `SELECT count(*) FROM alert_deliveries WHERE status = 'pending' AND recipient = 'a@x.example'`) != 2 {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("min severity and tags keep what is planned", func(t *testing.T) {
		s := setup(t)
		c := upd(t, s, func(u *store.AlertTargetUpdate) { u.MinSeverity = "CRIT"; u.TagFilter = []string{"x"} })
		if c.Deliveries != 0 || statusCount(t, s, "pending") != 4 || count(t, s, `SELECT held_count FROM alert_notify_state`) != 1 {
			t.Fatalf("%+v", c)
		}
	})
}

func TestCascadesOfHostAndTargetDelete(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	newTarget(t, s, "ops", "webhook", nil)
	transition(t, s, t0, "CRIT")
	plan(t, s, t0)
	if err := s.RecordTestSend(ctx, "ops", []store.TestSendRecord{{Result: store.AttemptResult{Status: store.AlertLogSent, Code: "HTTP 204"}}}, t0, cli); err != nil {
		t.Fatal(err)
	}
	c, _ := s.ClaimDeliveries(ctx, t0, time.Minute, 1)
	s.FinishAttempt(ctx, c[0], store.AttemptResult{Status: store.AlertLogSent, Code: "HTTP 204"}, t0)

	// Target delete: deliveries and notify state go, log rows stay with the name.
	if err := s.DeleteAlertTarget(ctx, "ops", t0, cli); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT count(*) FROM alert_deliveries`)+count(t, s, `SELECT count(*) FROM alert_notify_state`) != 0 {
		t.Fatal("target delete left queue rows")
	}
	if n := count(t, s, `SELECT count(*) FROM alert_log WHERE target_id IS NULL AND target_name = 'ops'`); n != 2 {
		t.Fatalf("log rows after target delete: %d", n)
	}
	// Host delete: the log rows tied to its history go; the test-send row has no host and stays.
	if err := s.DeleteHost(ctx, "a", t0, cli); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM alert_log`); n != 1 {
		t.Fatalf("log rows after host delete: %d", n)
	}
}

// Mutation 38: UnroutedDetections counts routed ones.
func TestUnroutedDetections(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	newTarget(t, s, "ops", "webhook", func(n *store.NewAlertTarget) { n.TagFilter = []string{"prod"} })
	n := 0
	rec := func(path string, tags ...string) {
		n++ // a new report timestamp each time, or the duplicate would not replace the tags
		at := t0.Add(time.Duration(n) * time.Second)
		if _, err := s.RecordReport(ctx, store.ReportRecord{HostID: 1, Report: rep("a", at, "1", tags...), ReceivedAt: at}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RecordEvent(ctx, store.EventRecord{HostID: 1, ReceivedAt: t0, Event: proto.Event{TS: t0, Path: path, Signature: "s", Source: "scan"}}); err != nil {
			t.Fatal(err)
		}
	}
	rec("/dev", "dev")
	res := plan(t, s, t0)
	if len(res.Unrouted) != 1 || res.Unrouted[0].Host != "a" || len(res.Deliveries) != 0 {
		t.Fatalf("%+v", res)
	}
	if n, _ := s.UnroutedDetections(ctx, t0.Add(-time.Hour)); n != 1 {
		t.Fatalf("unrouted = %d", n)
	}
	if count(t, s, `SELECT count(*) FROM events`) != 1 {
		t.Fatal("the events row must stay")
	}
	rec("/prod", "prod")
	if n, _ := s.UnroutedDetections(ctx, t0.Add(-time.Hour)); n != 1 { // flagged, not planned yet: not counted
		t.Fatalf("a flagged event was counted: %d", n)
	}
	plan(t, s, t0)
	if n, _ := s.UnroutedDetections(ctx, t0.Add(-time.Hour)); n != 1 {
		t.Fatalf("a routed event was counted: %d", n)
	}
	if n, _ := s.UnroutedDetections(ctx, t0.Add(time.Hour)); n != 0 {
		t.Fatalf("since is a lower bound: %d", n)
	}
}

// Mutation 41: prune deletes pending deliveries, or uses >= at the boundary.
func TestPruneAlertHistory(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	newTarget(t, s, "ops", "webhook", nil)
	cut := t0.Add(90 * 24 * time.Hour)
	ins := func(status string, finished any, ts time.Time) {
		if _, err := s.w.Exec(`INSERT INTO alert_deliveries (alert_id, target_id, host_id, kind, payload, status, created_at, finished_at) VALUES ('x', 1, 1, 'state_change', '{}', ?, 1, ?)`, status, finished); err != nil {
			t.Fatal(err)
		}
		if _, err := s.w.Exec(`INSERT INTO alert_log (ts, target_id, target_name, status) VALUES (?, 1, 'ops', 'sent')`, ts.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	old := cut.Add(-time.Second).Unix()
	edge := cut.Unix()
	ins("sent", old, time.Unix(old, 0))        // goes
	ins("failed", old, time.Unix(old, 0))      // goes
	ins("pending", nil, time.Unix(old, 0))     // pending: stays although the log row goes
	ins("sent", edge, time.Unix(edge, 0))      // exactly at the boundary: stays
	n, err := s.PruneAlertHistory(ctx, cut, 1) // batch 1 forces the loop
	if err != nil || n != 5 {
		t.Fatalf("pruned %d (%v), want 2 deliveries + 3 log rows", n, err)
	}
	if got := count(t, s, `SELECT count(*) FROM alert_deliveries`); got != 2 {
		t.Fatalf("%d deliveries left, want the pending one and the boundary one", got)
	}
	if got := statusCount(t, s, "pending"); got != 1 {
		t.Fatal("a pending delivery was pruned")
	}
	if got := count(t, s, `SELECT count(*) FROM alert_log`); got != 1 {
		t.Fatalf("%d log rows left, want the boundary one", got)
	}
}

func TestResealAlertSecretsCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	a := newTarget(t, s, "a", "webhook", nil)
	b := newTarget(t, s, "b", "webhook", nil)
	newTarget(t, s, "mail", "email", nil)
	secrets, err := s.SealedAlertSecrets(ctx)
	if err != nil || len(secrets) != 2 {
		t.Fatalf("%+v %v", secrets, err)
	}
	// b changes between the read and the write (an admin rotated the key).
	if _, err := s.w.Exec(`UPDATE alert_targets SET secret = x'ff' WHERE id = ?`, b.ID); err != nil {
		t.Fatal(err)
	}
	applied, conflicts, err := s.ResealAlertSecrets(ctx, []store.AlertReseal{
		{TargetID: a.ID, Old: a.Sealed, New: []byte("new-a")},
		{TargetID: b.ID, Old: b.Sealed, New: []byte("new-b")},
	}, t0, cli)
	if err != nil || applied != 1 || len(conflicts) != 1 || conflicts[0] != b.ID {
		t.Fatalf("%d %v %v", applied, conflicts, err)
	}
	if got, _ := s.AlertTarget(ctx, "a"); string(got.Sealed) != "new-a" {
		t.Fatalf("%q", got.Sealed)
	}
	if got, _ := s.AlertTarget(ctx, "b"); string(got.Sealed) != "\xff" {
		t.Fatalf("the changed row must be left alone: %q", got.Sealed)
	}
}

func TestAlertLogAndTargetSummary(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	newTarget(t, s, "ops", "webhook", nil)
	newTarget(t, s, "other", "email", nil)
	transition(t, s, t0, "CRIT")
	plan(t, s, t0)
	c, _ := s.ClaimDeliveries(ctx, t0, time.Minute, 5)
	for _, d := range c {
		s.FinishAttempt(ctx, d, store.AttemptResult{Status: store.AlertLogRetrying, Code: "HTTP 503", Error: "the receiver answered HTTP 503", RetryAt: t0.Add(time.Minute), Duration: 3 * time.Millisecond}, t0.Add(time.Second))
	}
	log, err := s.AlertLog(ctx, store.AlertLogFilter{TargetName: "ops", Limit: 10})
	if err != nil || len(log) != 1 || log[0].Status != "retrying" || log[0].Code != "HTTP 503" || log[0].Host != "a" || log[0].Attempt != 1 {
		t.Fatalf("%+v %v", log, err)
	}
	if all, _ := s.AlertLog(ctx, store.AlertLogFilter{}); len(all) != 2 || all[0].ID < all[1].ID {
		t.Fatalf("newest first, every target: %+v", all)
	}
	sums, err := s.ListAlertTargets(ctx)
	if err != nil || len(sums) != 2 || sums[0].Name != "ops" || sums[0].LastStatus != "retrying" || sums[0].LastCode != "HTTP 503" || sums[0].LastAt == nil {
		t.Fatalf("%+v %v", sums, err)
	}
	if err := s.RecordTestSend(ctx, "ops", []store.TestSendRecord{{Result: store.AttemptResult{Status: store.AlertLogFailed, Code: "blocked", Error: "loopback"}}}, t0.Add(time.Hour), cli); err != nil {
		t.Fatal(err)
	}
	sums, _ = s.ListAlertTargets(ctx)
	if sums[0].LastStatus != "test_failed" {
		t.Fatalf("%+v", sums[0])
	}
	if count(t, s, `SELECT count(*) FROM audit_log WHERE action = 'alert_target.test' AND detail = '{"code":"blocked","result":"failed"}'`) != 1 {
		t.Fatal("test audit row")
	}
	if err := s.RecordTestSend(ctx, "nope", nil, t0, cli); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if n, err := s.CountPendingAlerts(ctx, "ops"); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestHasAlertWorkSeesEachKindOfWork(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	addHost(t, s, "a")
	newTarget(t, s, "ops", "webhook", nil)
	work := func(now time.Time) bool {
		ok, err := s.HasAlertWork(ctx, now, testCooldown)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if work(t0) {
		t.Fatal("quiet database")
	}
	transition(t, s, t0, "CRIT")
	if !work(t0) {
		t.Fatal("flag")
	}
	plan(t, s, t0)
	if !work(t0) { // a due delivery
		t.Fatal("due delivery")
	}
	c, _ := s.ClaimDeliveries(ctx, t0, 40*time.Second, 1)
	if work(t0.Add(time.Second)) {
		t.Fatal("a claimed delivery inside its lease is not work")
	}
	if !work(t0.Add(41 * time.Second)) {
		t.Fatal("expired lease")
	}
	s.FinishAttempt(ctx, c[0], store.AttemptResult{Status: store.AlertLogSent, Code: "HTTP 200"}, t0)
	if work(t0.Add(time.Minute)) {
		t.Fatal("nothing left")
	}
	transition(t, s, t0.Add(time.Minute), "OK")
	plan(t, s, t0.Add(time.Minute)) // held
	if work(t0.Add(time.Minute)) {
		t.Fatal("a hold that is not due is not work")
	}
	if !work(t0.Add(testCooldown)) {
		t.Fatal("a due hold is work")
	}
}

// Review finding 11: key rotation re-seals TOTP and alert-target secrets in ONE
// transaction. A failure midway rolls everything back; a conflict leaves the
// changed row alone and commits the rest.
func TestResealSecretsIsOneTransaction(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := enrolled(t, s, "a@example.com")
	a := newTarget(t, s, "a", "webhook", nil)
	b := newTarget(t, s, "b", "webhook", nil)
	totp := []store.Reseal{{UserID: u.ID, Old: []byte("sealed-1"), New: []byte("new-totp")}}
	alerts := []store.AlertReseal{
		{TargetID: a.ID, Old: a.Sealed, New: []byte("new-a")},
		{TargetID: b.ID, Old: b.Sealed, New: []byte("new-b")},
	}
	// A failure after the second row: nothing at all is re-sealed.
	boom := errors.New("boom")
	calls := 0
	s.betweenResealRows = func() error {
		calls++
		if calls == 2 {
			return boom
		}
		return nil
	}
	if _, err := s.ResealSecrets(ctx, totp, alerts, t0, cli); !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
	s.betweenResealRows = nil
	if st, _ := s.UserTOTP(ctx, u.ID); string(st.Sealed) != "sealed-1" {
		t.Fatalf("the TOTP secret was re-sealed in a rolled-back run: %q", st.Sealed)
	}
	for _, n := range []string{"a", "b"} {
		if got, _ := s.AlertTarget(ctx, n); !strings.HasPrefix(string(got.Sealed), "sealed-") {
			t.Fatalf("target %s re-sealed in a rolled-back run: %q", n, got.Sealed)
		}
	}
	if count(t, s, `SELECT count(*) FROM audit_log WHERE action = 'secrets.reencrypt'`) != 0 {
		t.Fatal("a rolled-back run was audited")
	}
	// A conflict on b: the other rows commit and the conflict is reported.
	if _, err := s.w.Exec(`UPDATE alert_targets SET secret = x'ff' WHERE id = ?`, b.ID); err != nil {
		t.Fatal(err)
	}
	res, err := s.ResealSecrets(ctx, totp, alerts, t0, cli)
	if err != nil || res.TOTP != 1 || res.AlertTargets != 1 || len(res.AlertConflicts) != 1 || res.AlertConflicts[0] != b.ID || len(res.TOTPConflicts) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if count(t, s, `SELECT count(*) FROM audit_log WHERE action = 'secrets.reencrypt' AND detail LIKE '%"totp":"1"%' AND detail LIKE '%"alert_target":"1"%' AND detail LIKE '%"conflicts":"1"%'`) != 1 {
		t.Fatal("the audit row must carry the counts and the conflicts")
	}
}
