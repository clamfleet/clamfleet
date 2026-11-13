// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package alert

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

// winHarness runs the planner for detections and carries the open windows from
// pass to pass the way the store does: the writes of a pass are applied in
// order, a window with an outcome leaves the open set.
type winHarness struct {
	t       *testing.T
	targets []store.AlertTarget
	hosts   map[int64]store.PlanHost
	notify  map[[2]int64]store.NotifyState
	wins    []store.PlanWindow
	events  map[int64]store.PlanEvent
	nextWin int64
	nextID  int
	closed  []string // outcomes in order
}

func newWinHarness(t *testing.T, targets ...store.AlertTarget) *winHarness {
	return &winHarness{t: t, targets: targets, hosts: map[int64]store.PlanHost{
		1: {ID: 1, Name: "app01", Tags: []string{"web"}},
	}, notify: map[[2]int64]store.NotifyState{}, events: map[int64]store.PlanEvent{}}
}

func burstTarget(id int64, name string, burst int) store.AlertTarget {
	t := target(id, name, "WARN")
	t.DetectionBurst = burst
	return t
}

// ev builds a detection received at recv (server clock) with agent time ts.
func (h *winHarness) ev(id int64, recv, ts time.Time, sig string) store.PlanEvent {
	e := store.PlanEvent{ID: id, HostID: 1, TS: ts, ReceivedAt: recv, Path: fmt.Sprintf("/p/%d", id), Signature: sig, Source: "clamd"}
	h.events[id] = e
	return e
}

func (h *winHarness) pass(now time.Time, events ...store.PlanEvent) store.AlertPlanOutput {
	var notify []store.NotifyState
	for _, n := range h.notify {
		notify = append(notify, n)
	}
	in := store.AlertPlanInput{Now: now, Cooldown: cd, Targets: h.targets, Events: events, Hosts: h.hosts, Notify: notify,
		Windows: append([]store.PlanWindow(nil), h.wins...)}
	p := Planner{PublicURL: "https://cf.example", NewID: func() string { h.nextID++; return fmt.Sprintf("id%03d", h.nextID) }}
	out := p.Plan(in)
	for _, n := range out.Notify {
		h.notify[[2]int64{n.TargetID, n.HostID}] = n
	}
	for _, w := range out.Windows {
		i := -1
		for j := range h.wins {
			if w.ID != 0 && h.wins[j].ID == w.ID {
				i = j
			}
		}
		if i < 0 {
			h.nextWin++
			h.wins = append(h.wins, store.PlanWindow{ID: 1000 + h.nextWin, TargetID: w.TargetID, HostID: w.HostID, Start: w.Start})
			i = len(h.wins) - 1
			// the window's identity is carried in the output order; remember it for later passes
		}
		h.wins[i].Sent = w.Sent
		for _, id := range w.AddMembers {
			e := h.events[id]
			h.wins[i].Members = append(h.wins[i].Members, store.PlanWindowMember{EventID: id, TS: e.TS, Signature: e.Signature})
		}
		if w.Outcome != "" {
			h.closed = append(h.closed, w.Outcome)
			h.wins = append(h.wins[:i], h.wins[i+1:]...)
		}
	}
	return out
}

func kindCount(out store.AlertPlanOutput, kind string) int {
	n := 0
	for _, d := range out.Deliveries {
		if d.Kind == kind {
			n++
		}
	}
	return n
}

func summaryOf(t *testing.T, out store.AlertPlanOutput) DetectionSummaryPayload {
	t.Helper()
	for _, d := range out.Deliveries {
		if d.Kind == store.DeliveryDetectionSummary {
			var p DetectionSummaryPayload
			if err := json.Unmarshal(d.Payload, &p); err != nil {
				t.Fatal(err)
			}
			return p
		}
	}
	t.Fatal("no summary delivery")
	return DetectionSummaryPayload{}
}

// 12 detections at one instant with B = 10: ids 1-10 go one by one, 11 and 12
// are held in id order, one "held" log row names the end of the window; at
// start+W the window closes into ONE summary of count 2.
func TestWindowBurstSendsTenThenSummarises(t *testing.T) {
	h := newWinHarness(t, burstTarget(1, "ops", 10))
	var evs []store.PlanEvent
	for i := int64(1); i <= 12; i++ {
		evs = append(evs, h.ev(i, t0, t0.Add(-time.Hour), "S"))
	}
	out := h.pass(t0.Add(time.Second), evs...)
	if n := kindCount(out, store.DeliveryDetection); n != 10 {
		t.Fatalf("%d individual detections, want 10", n)
	}
	for i, d := range out.Deliveries {
		if *d.EventID != int64(i+1) {
			t.Fatalf("delivery %d is for event %d: the first ten in id order go out", i, *d.EventID)
		}
	}
	if len(out.Windows) != 1 || out.Windows[0].Sent != 10 || len(out.Windows[0].AddMembers) != 2 || out.Windows[0].AddMembers[0] != 11 || out.Windows[0].AddMembers[1] != 12 {
		t.Fatalf("windows %+v", out.Windows)
	}
	held := 0
	for _, l := range out.Logs {
		if l.Status == store.AlertLogHeld {
			held++
			if *l.EventID != 11 {
				t.Fatalf("the held row is about the first held event, got %d", *l.EventID)
			}
		}
	}
	if held != 1 {
		t.Fatalf("%d held rows, want one per window", held)
	}
	// Before the window ends nothing more happens.
	if out := h.pass(t0.Add(9*time.Minute + 59*time.Second)); len(out.Deliveries) != 0 || len(out.Windows) != 0 {
		t.Fatalf("early close: %+v", out)
	}
	out = h.pass(t0.Add(10 * time.Minute))
	if n := kindCount(out, store.DeliveryDetectionSummary); n != 1 || len(out.Deliveries) != 1 {
		t.Fatalf("%+v", out.Deliveries)
	}
	sum := summaryOf(t, out)
	if sum.Count != 2 || sum.Host != "app01" || sum.WindowSeconds != 600 || sum.WindowStart != FormatTime(t0) || sum.WindowEnd != FormatTime(t0.Add(10*time.Minute)) {
		t.Fatalf("%+v", sum)
	}
	if out.Windows[0].Outcome != store.WindowSummarised || out.Deliveries[0].WindowRef != 1 {
		t.Fatalf("%+v ref %d", out.Windows, out.Deliveries[0].WindowRef)
	}
	if len(h.wins) != 0 {
		t.Fatalf("the window stayed open: %+v", h.wins)
	}
}

// The boundary is exclusive: an event at exactly start+W opens a new window,
// after the old one was closed (its summary is written first).
func TestWindowBoundaryIsExclusive(t *testing.T) {
	h := newWinHarness(t, burstTarget(1, "ops", 1))
	h.pass(t0, h.ev(1, t0, t0, "S"), h.ev(2, t0, t0, "S")) // 1 sent, 2 held
	out := h.pass(t0.Add(10*time.Minute), h.ev(3, t0.Add(10*time.Minute), t0, "S"))
	if len(out.Windows) != 2 || out.Windows[0].Outcome != store.WindowSummarised || out.Windows[1].ID != 0 || out.Windows[1].Sent != 1 {
		t.Fatalf("%+v", out.Windows)
	}
	if kindCount(out, store.DeliveryDetectionSummary) != 1 || kindCount(out, store.DeliveryDetection) != 1 {
		t.Fatalf("%+v", out.Deliveries)
	}
	// One second before the end: the event still belongs to the old window.
	h2 := newWinHarness(t, burstTarget(1, "ops", 1))
	h2.pass(t0, h2.ev(1, t0, t0, "S"))
	out = h2.pass(t0.Add(9*time.Minute+59*time.Second), h2.ev(2, t0.Add(9*time.Minute+59*time.Second), t0, "S"))
	if kindCount(out, store.DeliveryDetection) != 0 || len(out.Windows) != 1 || out.Windows[0].Outcome != "" {
		t.Fatalf("%+v", out)
	}
}

// A window is measured on received_at, never the agent's ts: spooled events
// with a ts two days old but a fresh arrival count together.
func TestWindowUsesServerClockNotAgentTS(t *testing.T) {
	h := newWinHarness(t, burstTarget(1, "ops", 2))
	old := t0.Add(-48 * time.Hour)
	out := h.pass(t0, h.ev(1, t0, old, "S"), h.ev(2, t0, old.Add(time.Hour), "S"), h.ev(3, t0, old.Add(2*time.Hour), "S"))
	if kindCount(out, store.DeliveryDetection) != 2 || len(out.Windows[0].AddMembers) != 1 {
		t.Fatalf("%+v", out)
	}
	sum := summaryOf(t, h.pass(t0.Add(10*time.Minute)))
	if sum.Count != 1 || sum.FirstTS != FormatTime(old.Add(2*time.Hour)) {
		t.Fatalf("first_ts/last_ts are the agent's times, informational: %+v", sum)
	}
}

// The server clock went backwards: an event before the window's start counts in
// the open window; and a window more than a minute in the future is closed now.
func TestWindowBackwardsClock(t *testing.T) {
	h := newWinHarness(t, burstTarget(1, "ops", 1))
	h.pass(t0, h.ev(1, t0, t0, "S"), h.ev(2, t0, t0, "S")) // 2 held
	out := h.pass(t0, h.ev(3, t0.Add(-5*time.Minute), t0, "S"))
	if kindCount(out, store.DeliveryDetection) != 0 || len(out.Windows[0].AddMembers) != 1 || out.Windows[0].ID == 0 {
		t.Fatalf("an event before the window start must join the open window: %+v", out.Windows)
	}
	// now is 2 minutes before the window start: the window is closed at once.
	out = h.pass(t0.Add(-2 * time.Minute))
	if kindCount(out, store.DeliveryDetectionSummary) != 1 || summaryOf(t, out).Count != 2 {
		t.Fatalf("a window from the future must close now: %+v", out.Deliveries)
	}
	// 30 seconds before the start: not yet (clock jitter).
	h2 := newWinHarness(t, burstTarget(1, "ops", 1))
	h2.pass(t0, h2.ev(1, t0, t0, "S"), h2.ev(2, t0, t0, "S"))
	if out := h2.pass(t0.Add(-30 * time.Second)); len(out.Deliveries) != 0 {
		t.Fatalf("closed on 30 s of clock jitter: %+v", out.Deliveries)
	}
}

func TestWindowBurstZeroNeverOpensAWindow(t *testing.T) {
	h := newWinHarness(t, burstTarget(1, "ops", 0))
	var evs []store.PlanEvent
	for i := int64(1); i <= 25; i++ {
		evs = append(evs, h.ev(i, t0, t0, "S"))
	}
	out := h.pass(t0, evs...)
	if kindCount(out, store.DeliveryDetection) != 25 || len(out.Windows) != 0 {
		t.Fatalf("%d detections, %d windows", kindCount(out, store.DeliveryDetection), len(out.Windows))
	}
}

func TestWindowTargetsAreIndependent(t *testing.T) {
	h := newWinHarness(t, burstTarget(1, "a", 2), burstTarget(2, "b", 5))
	var evs []store.PlanEvent
	for i := int64(1); i <= 6; i++ {
		evs = append(evs, h.ev(i, t0, t0, "S"))
	}
	out := h.pass(t0, evs...)
	per := map[int64]int{}
	for _, d := range out.Deliveries {
		per[d.TargetID]++
	}
	if per[1] != 2 || per[2] != 5 {
		t.Fatalf("individual detections per target %v, want 2 and 5", per)
	}
	if len(out.Windows) != 2 || len(out.Windows[0].AddMembers) != 4 || len(out.Windows[1].AddMembers) != 1 {
		t.Fatalf("%+v", out.Windows)
	}
}

// One summary per recipient, all sharing one alert id (receivers deduplicate on it).
func TestWindowEmailSummaryFansOutWithOneID(t *testing.T) {
	m := emailTarget(1, "mail", "a@x.example", "b@x.example", "c@x.example")
	m.DetectionBurst = 1
	h := newWinHarness(t, m)
	h.pass(t0, h.ev(1, t0, t0, "S"), h.ev(2, t0, t0, "S"))
	out := h.pass(t0.Add(10 * time.Minute))
	if len(out.Deliveries) != 3 {
		t.Fatalf("%d deliveries", len(out.Deliveries))
	}
	for _, d := range out.Deliveries {
		if d.AlertID != out.Deliveries[0].AlertID || d.Kind != store.DeliveryDetectionSummary || d.EventID != nil || d.WindowRef != 1 {
			t.Fatalf("%+v", d)
		}
	}
}

// Summaries are detections: the state-change cooldown does not hold them. A state
// alert went to the same target and host a minute ago, inside a 15 minute cooldown.
func TestWindowSummaryIsNotHeldByTheCooldown(t *testing.T) {
	h := newWinHarness(t, burstTarget(1, "ops", 1))
	h.notify[[2]int64{1, 1}] = store.NotifyState{TargetID: 1, HostID: 1, LastState: "CRIT", LastAt: t0.Add(9 * time.Minute)}
	h.pass(t0, h.ev(1, t0, t0, "S"), h.ev(2, t0, t0, "S"))
	out := h.pass(t0.Add(10 * time.Minute))
	if kindCount(out, store.DeliveryDetectionSummary) != 1 {
		t.Fatalf("the summary was held: %+v", out)
	}
	for _, l := range out.Logs {
		if l.Status == store.AlertLogHeld {
			t.Fatalf("a held row for a summary: %+v", l)
		}
	}
}

func TestWindowWithoutMembersClosesEmpty(t *testing.T) {
	h := newWinHarness(t, burstTarget(1, "ops", 3))
	h.pass(t0, h.ev(1, t0, t0, "S"))
	out := h.pass(t0.Add(11 * time.Minute))
	if len(out.Deliveries) != 0 || len(out.Windows) != 1 || out.Windows[0].Outcome != store.WindowEmpty {
		t.Fatalf("%+v", out)
	}
}

// Defence in depth: a window whose target stopped sending detections is
// discarded, not summarised.
func TestWindowOfASwitchedOffTargetIsDiscarded(t *testing.T) {
	h := newWinHarness(t, burstTarget(1, "ops", 1))
	h.pass(t0, h.ev(1, t0, t0, "S"), h.ev(2, t0, t0, "S"))
	h.targets[0].SendDetections = false
	out := h.pass(t0.Add(10 * time.Minute))
	if len(out.Deliveries) != 0 || out.Windows[0].Outcome != store.WindowDiscarded {
		t.Fatalf("%+v", out)
	}
}

// Top 10 signatures by count (ties by name), the rest counted in more_signatures.
func TestWindowSummaryListsTopTenSignatures(t *testing.T) {
	h := newWinHarness(t, burstTarget(1, "ops", 1))
	evs := []store.PlanEvent{h.ev(1, t0, t0, "first")}
	id := int64(2)
	for s := 0; s < 12; s++ {
		for n := 0; n <= s; n++ { // signature s has s+1 members
			evs = append(evs, h.ev(id, t0, t0, fmt.Sprintf("sig%02d", s)))
			id++
		}
	}
	h.pass(t0, evs...)
	sum := summaryOf(t, h.pass(t0.Add(10*time.Minute)))
	if len(sum.Signatures) != 10 || sum.MoreSignatures != 2 || sum.Signatures[0].Signature != "sig11" || sum.Signatures[0].Count != 12 || sum.Signatures[9].Signature != "sig02" {
		t.Fatalf("%+v", sum)
	}
	if sum.Count != 78 {
		t.Fatalf("count %d, want 78", sum.Count)
	}
}

// A new burst after the window closed starts fresh: the count of individual
// alerts is per window.
func TestWindowResetsAfterClose(t *testing.T) {
	h := newWinHarness(t, burstTarget(1, "ops", 2))
	h.pass(t0, h.ev(1, t0, t0, "S"), h.ev(2, t0, t0, "S"), h.ev(3, t0, t0, "S"))
	h.pass(t0.Add(10 * time.Minute))
	later := t0.Add(30 * time.Minute)
	out := h.pass(later, h.ev(4, later, later, "S"), h.ev(5, later, later, "S"), h.ev(6, later, later, "S"))
	if kindCount(out, store.DeliveryDetection) != 2 {
		t.Fatalf("%d individual detections in the new window, want 2", kindCount(out, store.DeliveryDetection))
	}
}
