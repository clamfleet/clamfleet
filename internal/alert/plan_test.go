// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package alert

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

const cd = 15 * time.Minute

// harness runs the planner the way the store does, carrying the notify state
// from one pass to the next so scenarios can span several passes.
type harness struct {
	t       *testing.T
	targets []store.AlertTarget
	hosts   map[int64]store.PlanHost
	notify  map[[2]int64]store.NotifyState
	nextID  int
	scID    int64
	cool    time.Duration
}

func newHarness(t *testing.T, targets ...store.AlertTarget) *harness {
	h := &harness{t: t, targets: targets, hosts: map[int64]store.PlanHost{}, notify: map[[2]int64]store.NotifyState{}, cool: cd}
	h.hosts[1] = store.PlanHost{ID: 1, Name: "app01", Tags: []string{"web", "prod"}}
	return h
}

func target(id int64, name, min string) store.AlertTarget {
	return store.AlertTarget{ID: id, Name: name, Type: store.TargetTypeWebhook, MinSeverity: min,
		SendStateChanges: true, SendDetections: true, Enabled: true}
}

func emailTarget(id int64, name string, to ...string) store.AlertTarget {
	t := target(id, name, "WARN")
	t.Type = store.TargetTypeEmail
	t.Config, _ = json.Marshal(EmailConfig{To: to})
	return t
}

func ptr(s string) *string { return &s }

// change records a transition of host 1 (as EvaluateHosts would) and returns it.
func (h *harness) change(at time.Time, from *string, to string) store.PlanStateChange {
	h.scID++
	hh := h.hosts[1]
	hh.State, hh.LatestChangeID, hh.LatestChangeTS = ptr(to), h.scID, at
	hh.Reason = json.RawMessage(fmt.Sprintf(`[{"rule":"r_%s","severity":"%s","msg":"msg %s"}]`, to, to, to))
	h.hosts[1] = hh
	return store.PlanStateChange{ID: h.scID, HostID: 1, TS: at, From: from, To: to, Reason: hh.Reason}
}

// plan runs one pass at now over the given flagged changes and applies the output.
func (h *harness) plan(now time.Time, changes ...store.PlanStateChange) store.AlertPlanOutput {
	return h.run(now, changes, nil)
}

func (h *harness) run(now time.Time, changes []store.PlanStateChange, events []store.PlanEvent) store.AlertPlanOutput {
	var notify []store.NotifyState
	for _, n := range h.notify {
		notify = append(notify, n)
	}
	in := store.AlertPlanInput{Now: now, Cooldown: h.cool, Targets: h.targets, Changes: changes, Events: events, Hosts: h.hosts, Notify: notify}
	p := Planner{PublicURL: "https://cf.example", NewID: func() string { h.nextID++; return fmt.Sprintf("id%03d", h.nextID) }}
	out := p.Plan(in)
	for _, n := range out.Notify {
		h.notify[[2]int64{n.TargetID, n.HostID}] = n
	}
	return out
}

func decode(t *testing.T, d store.NewDelivery) StateChangePayload {
	t.Helper()
	var p StateChangePayload
	if err := json.Unmarshal(d.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func strOf(p *string) string {
	if p == nil {
		return "<null>"
	}
	return *p
}

// The severity view table (4.3): the first evaluation, and each target
// minimum against each kind of step, as sequences of changes sent apart by
// more than the cooldown.
func TestPlanSeverityView(t *testing.T) {
	type step struct {
		to       string
		wantSend bool
		from     string // expected payload from, "" = do not check
		resolved bool
	}
	cases := []struct {
		name  string
		min   string
		first *string // from of the first change
		steps []step
	}{
		{"first evaluation OK sends nothing", "WARN", nil, []step{{"OK", false, "", false}}},
		{"first evaluation CRIT sends", "WARN", nil, []step{{"CRIT", true, "<null>", false}}},
		{"first evaluation WARN to a CRIT target sends nothing", "CRIT", nil, []step{{"WARN", false, "", false}}},
		{"WARN target: OK to WARN then recovery", "WARN", ptr("OK"), []step{{"WARN", true, "OK", false}, {"OK", true, "WARN", true}}},
		{"CRIT target: OK to WARN sends nothing, WARN to CRIT sends", "CRIT", ptr("OK"),
			[]step{{"WARN", false, "", false}, {"CRIT", true, "WARN", false}}},
		{"CRIT target: CRIT to WARN is a resolved alert, WARN to OK sends nothing", "CRIT", ptr("OK"),
			[]step{{"CRIT", true, "OK", false}, {"WARN", true, "CRIT", true}, {"OK", false, "", false}}},
		{"STALE target: CRIT sends nothing", "STALE", ptr("OK"), []step{{"CRIT", false, "", false}, {"STALE", true, "CRIT", false}}},
		{"WARN to CRIT to a WARN target is a state alert", "WARN", ptr("OK"),
			[]step{{"WARN", true, "OK", false}, {"CRIT", true, "WARN", false}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, target(1, "t", c.min))
			now := t0
			from := c.first
			for i, s := range c.steps {
				now = now.Add(2 * cd) // always outside the cooldown
				out := h.plan(now, h.change(now, from, s.to))
				from = ptr(s.to)
				if got := len(out.Deliveries) == 1; got != s.wantSend || len(out.Deliveries) > 1 {
					t.Fatalf("step %d (to %s): %d deliveries, want send=%v", i, s.to, len(out.Deliveries), s.wantSend)
				}
				if !s.wantSend {
					continue
				}
				p := decode(t, out.Deliveries[0])
				if p.To != s.to || strOf(p.From) != s.from || p.Resolved != s.resolved || p.Changes != 1 {
					t.Fatalf("step %d: payload %+v, want to=%s from=%s resolved=%v", i, p, s.to, s.from, s.resolved)
				}
			}
		})
	}
}

func TestPlanTagFilterAndSwitches(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(*store.AlertTarget)
		tags   []string
		wantTo int
	}{
		{"empty filter matches every host", func(*store.AlertTarget) {}, []string{"web"}, 1},
		{"empty filter, host without tags", func(*store.AlertTarget) {}, nil, 1},
		{"any-of: one tag in common", func(a *store.AlertTarget) { a.TagFilter = []string{"db", "prod"} }, []string{"web", "prod"}, 1},
		{"no tag in common", func(a *store.AlertTarget) { a.TagFilter = []string{"db"} }, []string{"web", "prod"}, 0},
		{"filter set, host has no tags", func(a *store.AlertTarget) { a.TagFilter = []string{"db"} }, nil, 0},
		{"disabled", func(a *store.AlertTarget) { a.Enabled = false }, []string{"web"}, 0},
		{"state changes off", func(a *store.AlertTarget) { a.SendStateChanges = false }, []string{"web"}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tg := target(1, "t", "WARN")
			c.edit(&tg)
			h := newHarness(t, tg)
			hh := h.hosts[1]
			hh.Tags = c.tags
			h.hosts[1] = hh
			out := h.plan(t0, h.change(t0, ptr("OK"), "CRIT"))
			if len(out.Deliveries) != c.wantTo {
				t.Fatalf("%d deliveries, want %d", len(out.Deliveries), c.wantTo)
			}
		})
	}
}

// Flap: OK->CRIT sends; CRIT->OK, OK->CRIT, CRIT->OK inside the window are
// held; the due hold, with the host OK, sends ONE recovery with changes=3 and
// from=CRIT. A due hold back at CRIT is skipped.
func TestPlanFlapIsCoalesced(t *testing.T) {
	h := newHarness(t, target(1, "t", "WARN"))
	out := h.plan(t0, h.change(t0, ptr("OK"), "CRIT"))
	if len(out.Deliveries) != 1 {
		t.Fatalf("first: %d", len(out.Deliveries))
	}
	for i, to := range []string{"OK", "CRIT", "OK"} {
		at := t0.Add(time.Duration(i+1) * time.Minute)
		prev := []string{"CRIT", "OK", "CRIT"}[i]
		out = h.plan(at, h.change(at, ptr(prev), to))
		if len(out.Deliveries) != 0 {
			t.Fatalf("change %d inside the window was sent", i)
		}
		if len(out.Logs) != 1 || out.Logs[0].Status != store.AlertLogHeld {
			t.Fatalf("change %d: want one held log row, got %+v", i, out.Logs)
		}
	}
	if n := h.notify[[2]int64{1, 1}]; n.HeldCount != 3 || n.LastState != "CRIT" || !n.LastAt.Equal(t0) {
		t.Fatalf("notify after the flap: %+v", n)
	}
	// Not due at +14m59s: nothing.
	if out = h.plan(t0.Add(cd - time.Second)); len(out.Deliveries) != 0 || len(out.Logs) != 0 {
		t.Fatalf("hold fired early: %+v", out)
	}
	out = h.plan(t0.Add(cd))
	if len(out.Deliveries) != 1 {
		t.Fatalf("due hold: %d deliveries", len(out.Deliveries))
	}
	p := decode(t, out.Deliveries[0])
	if p.From == nil || *p.From != "CRIT" || p.To != "OK" || p.Changes != 3 || !p.Resolved {
		t.Fatalf("summary: %+v", p)
	}
	if n := h.notify[[2]int64{1, 1}]; n.HeldCount != 0 || n.LastState != "OK" || !n.LastAt.Equal(t0.Add(cd)) {
		t.Fatalf("notify after summary: %+v", n)
	}
}

func TestPlanDueHoldBackToToldStateIsSkipped(t *testing.T) {
	h := newHarness(t, target(1, "t", "WARN"))
	h.plan(t0, h.change(t0, ptr("OK"), "CRIT"))
	h.plan(t0.Add(time.Minute), h.change(t0.Add(time.Minute), ptr("CRIT"), "OK"))
	h.plan(t0.Add(2*time.Minute), h.change(t0.Add(2*time.Minute), ptr("OK"), "CRIT"))
	out := h.plan(t0.Add(cd))
	if len(out.Deliveries) != 0 {
		t.Fatalf("sent although the host is back at the state the target was told: %+v", out.Deliveries)
	}
	if len(out.Logs) != 1 || out.Logs[0].Status != store.AlertLogSkipped {
		t.Fatalf("want a skipped row: %+v", out.Logs)
	}
	if n := h.notify[[2]int64{1, 1}]; n.HeldCount != 0 {
		t.Fatalf("hold not cleared: %+v", n)
	}
}

// Recovery inside the window: CRIT sent, OK held, the due hold sends OK.
func TestPlanRecoveryInsideWindowIsNeverLost(t *testing.T) {
	h := newHarness(t, target(1, "t", "WARN"))
	h.plan(t0, h.change(t0, ptr("OK"), "CRIT"))
	if out := h.plan(t0.Add(time.Minute), h.change(t0.Add(time.Minute), ptr("CRIT"), "OK")); len(out.Deliveries) != 0 {
		t.Fatal("recovery inside the window must be held")
	}
	out := h.plan(t0.Add(cd + time.Minute))
	if len(out.Deliveries) != 1 {
		t.Fatalf("the recovery was lost: %+v", out)
	}
	if p := decode(t, out.Deliveries[0]); p.To != "OK" || p.Changes != 1 || !p.Resolved {
		t.Fatalf("%+v", p)
	}
}

// CRIT->WARN->OK held on a WARN target: the summary's from is CRIT (what the
// target was told), not WARN (the latest change's own from).
func TestPlanSummaryFromIsWhatTheTargetWasTold(t *testing.T) {
	h := newHarness(t, target(1, "t", "WARN"))
	h.plan(t0, h.change(t0, ptr("OK"), "CRIT"))
	h.plan(t0.Add(time.Minute), h.change(t0.Add(time.Minute), ptr("CRIT"), "WARN"))
	h.plan(t0.Add(2*time.Minute), h.change(t0.Add(2*time.Minute), ptr("WARN"), "OK"))
	out := h.plan(t0.Add(cd))
	if len(out.Deliveries) != 1 {
		t.Fatalf("%+v", out)
	}
	p := decode(t, out.Deliveries[0])
	if strOf(p.From) != "CRIT" || p.To != "OK" || p.Changes != 2 {
		t.Fatalf("want from CRIT to OK changes 2, got %+v", p)
	}
}

func TestPlanCooldownZeroNeverHolds(t *testing.T) {
	h := newHarness(t, target(1, "t", "WARN"))
	h.cool = 0
	for i, to := range []string{"CRIT", "OK", "CRIT", "OK"} {
		at := t0.Add(time.Duration(i) * time.Second)
		prev := []string{"OK", "CRIT", "OK", "CRIT"}[i]
		if out := h.plan(at, h.change(at, ptr(prev), to)); len(out.Deliveries) != 1 {
			t.Fatalf("change %d to %s: %d deliveries", i, to, len(out.Deliveries))
		}
	}
}

// A clock that went backwards (last_at in the future) must not hold forever.
func TestPlanBackwardsClockDoesNotHold(t *testing.T) {
	h := newHarness(t, target(1, "t", "WARN"))
	h.plan(t0.Add(time.Hour), h.change(t0.Add(time.Hour), ptr("OK"), "CRIT"))
	out := h.plan(t0, h.change(t0, ptr("CRIT"), "OK")) // now is before last_at
	if len(out.Deliveries) != 1 {
		t.Fatalf("a change with last_at in the future was held: %+v", out)
	}
}

func TestPlanBackwardsClockExpiresAHold(t *testing.T) {
	h := newHarness(t, target(1, "t", "WARN"))
	h.plan(t0, h.change(t0, ptr("OK"), "CRIT"))
	h.plan(t0.Add(time.Minute), h.change(t0.Add(time.Minute), ptr("CRIT"), "OK"))
	// The clock jumps back to before last_at: the hold is due at once.
	out := h.plan(t0.Add(-time.Hour))
	if len(out.Deliveries) != 1 {
		t.Fatalf("a hold with last_at in the future never expires: %+v", out)
	}
}

// Three pending changes of one host in one pass: the first sends, the others
// are held (last_at = now was just set), so a backlog never bursts.
func TestPlanBacklogGivesOneSendAndTwoHeld(t *testing.T) {
	h := newHarness(t, target(1, "t", "WARN"))
	c1 := h.change(t0, ptr("OK"), "CRIT")
	c2 := h.change(t0.Add(time.Second), ptr("CRIT"), "WARN")
	c3 := h.change(t0.Add(2*time.Second), ptr("WARN"), "OK")
	out := h.plan(t0.Add(time.Minute), c1, c2, c3)
	if len(out.Deliveries) != 1 {
		t.Fatalf("%d deliveries", len(out.Deliveries))
	}
	held := 0
	for _, l := range out.Logs {
		if l.Status == store.AlertLogHeld {
			held++
		}
	}
	if held != 2 {
		t.Fatalf("%d held rows, want 2", held)
	}
	if p := decode(t, out.Deliveries[0]); p.To != "CRIT" {
		t.Fatalf("the first change must be the one sent: %+v", p)
	}
}

// A stale hold of a target that is now off, or no longer matches, is cleared
// without a send (defence in depth, 4.3).
func TestPlanStaleHoldIsClearedWithoutSend(t *testing.T) {
	for name, edit := range map[string]func(*store.AlertTarget){
		"state changes off": func(a *store.AlertTarget) { a.SendStateChanges = false },
		"disabled":          func(a *store.AlertTarget) { a.Enabled = false },
		"tag filter":        func(a *store.AlertTarget) { a.TagFilter = []string{"db"} },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, target(1, "t", "WARN"))
			h.plan(t0, h.change(t0, ptr("OK"), "CRIT"))
			h.plan(t0.Add(time.Minute), h.change(t0.Add(time.Minute), ptr("CRIT"), "OK"))
			edit(&h.targets[0])
			out := h.plan(t0.Add(cd))
			if len(out.Deliveries) != 0 {
				t.Fatalf("a stale hold sent: %+v", out.Deliveries)
			}
			if n := h.notify[[2]int64{1, 1}]; n.HeldCount != 0 {
				t.Fatalf("hold not cleared: %+v", n)
			}
		})
	}
}

func TestPlanHoldDoesNotShareAcrossTargets(t *testing.T) {
	h := newHarness(t, target(1, "a", "WARN"), target(2, "b", "CRIT"))
	out := h.plan(t0, h.change(t0, ptr("OK"), "CRIT"))
	if len(out.Deliveries) != 2 {
		t.Fatalf("%d deliveries", len(out.Deliveries))
	}
	if out.Deliveries[0].AlertID != out.Deliveries[1].AlertID {
		t.Fatal("one alert id must be shared across targets")
	}
	if out.Deliveries[0].TargetID == out.Deliveries[1].TargetID {
		t.Fatal("two targets expected")
	}
}

func TestPlanEmailFansOutPerRecipient(t *testing.T) {
	h := newHarness(t, emailTarget(1, "mail", "a@x.example", "b@x.example", "c@x.example"))
	out := h.plan(t0, h.change(t0, ptr("OK"), "CRIT"))
	if len(out.Deliveries) != 3 {
		t.Fatalf("%d deliveries", len(out.Deliveries))
	}
	var got []string
	for _, d := range out.Deliveries {
		if d.AlertID != out.Deliveries[0].AlertID || string(d.Payload) != string(out.Deliveries[0].Payload) {
			t.Fatal("recipients of one alert must share the id and the payload")
		}
		got = append(got, d.Recipient)
	}
	if !reflect.DeepEqual(got, []string{"a@x.example", "b@x.example", "c@x.example"}) {
		t.Fatalf("%v", got)
	}
}

func TestPlanDetections(t *testing.T) {
	ev := store.PlanEvent{ID: 7, HostID: 1, TS: t0, ReceivedAt: t0.Add(time.Second), Path: "/p", Signature: "Eicar", Source: "scan"}
	t.Run("never held and ignore min severity", func(t *testing.T) {
		h := newHarness(t, target(1, "t", "STALE"))
		// A state alert just went out: inside the cooldown, detections still flow.
		h.notify[[2]int64{1, 1}] = store.NotifyState{TargetID: 1, HostID: 1, LastState: "STALE", LastAt: t0}
		out := h.run(t0.Add(time.Second), nil, []store.PlanEvent{ev, {ID: 8, HostID: 1, TS: t0, Path: "/q", Signature: "Eicar", Source: "scan"}})
		if len(out.Deliveries) != 2 || len(out.Unrouted) != 0 || len(out.Logs) != 0 {
			t.Fatalf("%+v", out)
		}
		var p DetectionPayload
		_ = json.Unmarshal(out.Deliveries[0].Payload, &p)
		if p.Kind != KindDetection || p.Path != "/p" || p.URL == nil || *p.URL != "https://cf.example/hosts/app01" {
			t.Fatalf("%+v", p)
		}
		if out.Deliveries[0].EventID == nil || *out.Deliveries[0].EventID != 7 || out.Deliveries[0].StateChangeID != nil {
			t.Fatalf("%+v", out.Deliveries[0])
		}
	})
	t.Run("respects tags and the switch; an unmatched one is unrouted", func(t *testing.T) {
		tg := target(1, "t", "WARN")
		tg.TagFilter = []string{"dev"}
		off := target(2, "off", "WARN")
		off.SendDetections = false
		h := newHarness(t, tg, off)
		out := h.run(t0, nil, []store.PlanEvent{ev})
		if len(out.Deliveries) != 0 || !reflect.DeepEqual(out.Unrouted, []int64{7}) {
			t.Fatalf("%+v", out)
		}
	})
	t.Run("no target at all", func(t *testing.T) {
		h := newHarness(t)
		out := h.run(t0, nil, []store.PlanEvent{ev})
		if !reflect.DeepEqual(out.Unrouted, []int64{7}) {
			t.Fatalf("%+v", out)
		}
	})
}

func TestPlanEmailWithoutRecipientsIsSkippedNotSilent(t *testing.T) {
	tg := emailTarget(1, "mail")
	tg.Config = []byte(`not json`)
	h := newHarness(t, tg)
	out := h.plan(t0, h.change(t0, ptr("OK"), "CRIT"))
	if len(out.Deliveries) != 0 || len(out.Logs) != 1 || out.Logs[0].Status != store.AlertLogSkipped {
		t.Fatalf("%+v", out)
	}
}

// Detections ignore min_severity for every minimum, not only STALE: a WARN or
// CRIT target still gets one while its host is OK (below the minimum).
func TestPlanDetectionsIgnoreMinSeverityForEveryMinimum(t *testing.T) {
	ev := store.PlanEvent{ID: 7, HostID: 1, TS: t0, ReceivedAt: t0, Path: "/p", Signature: "Eicar", Source: "scan"}
	for _, min := range []string{"WARN", "CRIT", "STALE"} {
		h := newHarness(t, target(1, "t", min))
		hh := h.hosts[1]
		hh.State = ptr("OK")
		h.hosts[1] = hh
		out := h.run(t0, nil, []store.PlanEvent{ev})
		if len(out.Deliveries) != 1 || len(out.Unrouted) != 0 {
			t.Errorf("min %s: %+v", min, out)
		}
	}
}
