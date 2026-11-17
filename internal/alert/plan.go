// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// plan.go: the pure alert planner.
//
// Planner.Plan turns flagged state changes and detections, the targets, and
// what each target was last told about each host into deliveries, notify-state
// upserts and log rows. It performs no I/O and reads no clock: "now", the
// cooldown and the id source are inputs, so every boundary is testable. The
// store runs it inside one write transaction (store.AlertStore.PlanAlerts).
//
// Model, in one paragraph. Each target sees the fleet through its own minimum
// severity: a state s is shown as s when sev(s) >= sev(min) and as "below"
// otherwise. A target is told about a host only when the view of the new state
// differs from the view of the state it was last told. Changes inside the
// cooldown are held; when the window ends one alert reports the host's CURRENT
// state if its view differs from what the target was last told, and its "from"
// is the state the target was last told, so receivers see a consistent chain.
// Detections ignore the minimum severity and the cooldown; what limits a mass
// detection is the burst window, below.
//
// Burst windows (milestone 5, decision 10b). Per (target, host) a window opens
// at the server-clock received_at of a detection. The first DetectionBurst
// detections whose received_at falls in [start, start+W) are sent one by one;
// the rest are held (membership rows) and sent as ONE summary when the window
// ends. Only the server clock is used (never the agent's ts, which a spooled
// event can have days old). A window is closed in the same transaction that
// writes its summary, so a crash can neither lose nor repeat a summary.
//
// Dependencies: internal/store (types only).
package alert

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

// Severity order, spec 9: OK < WARN < CRIT < STALE.
var severity = map[string]int{"OK": 0, "WARN": 1, "CRIT": 2, "STALE": 3}

// Sev returns the rank of a state; an unknown state ranks as OK.
func Sev(state string) int { return severity[state] }

// ValidMinSeverity reports whether s is a legal target minimum (OK would mean
// "alert about nothing in particular", so it is not offered).
func ValidMinSeverity(s string) bool { return s == "WARN" || s == "CRIT" || s == "STALE" }

// below is the view of every state under a target's minimum severity.
const below = "below"

// view is how a target with minimum min sees state s.
func view(s, min string) string {
	if Sev(s) >= Sev(min) {
		return s
	}
	return below
}

// EmailConfig is the non-secret config JSON of an email target.
type EmailConfig struct {
	To []string `json:"to"`
}

// Recipients returns the recipient addresses of an email target's config.
func Recipients(config []byte) ([]string, error) {
	var c EmailConfig
	if err := json.Unmarshal(config, &c); err != nil {
		return nil, fmt.Errorf("email target config: %w", err)
	}
	return c.To, nil
}

// Planner holds the inputs that are not data: where alert ids and the link base
// come from. Both are injected so tests are deterministic.
type Planner struct {
	// NewID returns a fresh public alert id (128 random bits as hex in production).
	NewID func() string
	// PublicURL is the configured public_url ("" = links are null).
	PublicURL string
}

type pairKey struct{ target, host int64 }

// matches reports whether target t selects host h by tag: empty filter = every
// host, otherwise any one tag in common.
func matches(t store.AlertTarget, tags []string) bool {
	if len(t.TagFilter) == 0 {
		return true
	}
	for _, want := range t.TagFilter {
		for _, have := range tags {
			if want == have {
				return true
			}
		}
	}
	return false
}

func i64p(v int64) *int64 { return &v }

// Plan decides what to write for in. It never mutates in.
func (p Planner) Plan(in store.AlertPlanInput) store.AlertPlanOutput {
	var out store.AlertPlanOutput
	targets := append([]store.AlertTarget(nil), in.Targets...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })

	// Working copy of the notify state: a later change in the same pass must see
	// what an earlier one just did (the first sends, the rest are held).
	notify := map[pairKey]store.NotifyState{}
	for _, n := range in.Notify {
		notify[pairKey{n.TargetID, n.HostID}] = n
	}
	touched := map[pairKey]bool{}
	set := func(n store.NotifyState) {
		k := pairKey{n.TargetID, n.HostID}
		notify[k] = n
		touched[k] = true
	}

	for _, sc := range in.Changes {
		host, ok := in.Hosts[sc.HostID]
		if !ok {
			continue // the host vanished; the cascade removes the row
		}
		id := p.NewID()
		for _, t := range targets {
			if !t.Enabled || !t.SendStateChanges || !matches(t, host.Tags) {
				continue
			}
			p.planChange(&out, in, t, host, sc, id, notify, set)
		}
	}

	// Due holds, after the new changes: a change arriving in the same pass was
	// counted into held_count above, so the summary covers it too.
	var keys []pairKey
	for k, n := range notify {
		if n.HeldCount > 0 {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].target != keys[j].target {
			return keys[i].target < keys[j].target
		}
		return keys[i].host < keys[j].host
	})
	byID := map[int64]store.AlertTarget{}
	for _, t := range targets {
		byID[t.ID] = t
	}
	for _, k := range keys {
		n := notify[k]
		t, ok := byID[k.target]
		host, hok := in.Hosts[k.host]
		if !ok || !hok {
			continue
		}
		if !holdDue(n, in.Now, in.Cooldown) {
			continue
		}
		p.resolveHold(&out, in, t, host, n, set)
	}

	ws := newWindowSet(in)
	for _, ev := range in.Events {
		host, ok := in.Hosts[ev.HostID]
		if !ok {
			continue
		}
		p.planDetection(&out, in, ws, targets, host, ev)
	}
	p.closeDueWindows(&out, in, ws, byID)

	keysOut := make([]pairKey, 0, len(touched))
	for k := range touched {
		keysOut = append(keysOut, k)
	}
	sort.Slice(keysOut, func(i, j int) bool {
		if keysOut[i].target != keysOut[j].target {
			return keysOut[i].target < keysOut[j].target
		}
		return keysOut[i].host < keysOut[j].host
	})
	for _, k := range keysOut {
		out.Notify = append(out.Notify, notify[k])
	}
	return out
}

// holdDue: the window has ended, or the clock went backwards (last_at in the
// future): a hold must never wait forever.
func holdDue(n store.NotifyState, now time.Time, cooldown time.Duration) bool {
	return n.LastAt.After(now) || !now.Before(n.LastAt.Add(cooldown))
}

func (p Planner) planChange(out *store.AlertPlanOutput, in store.AlertPlanInput, t store.AlertTarget, host store.PlanHost,
	sc store.PlanStateChange, alertID string, notify map[pairKey]store.NotifyState, set func(store.NotifyState)) {

	k := pairKey{t.ID, host.ID}
	n, have := notify[k]
	scID := i64p(sc.ID)

	// 1. A hold is already waiting: this change joins it, the re-check decides.
	if have && n.HeldCount > 0 {
		n.HeldCount++
		set(n)
		out.Logs = append(out.Logs, store.PlanLog{TargetID: t.ID, TargetName: t.Name, HostName: host.Name, StateChangeID: scID,
			Status: store.AlertLogHeld, Error: "cooldown until " + FormatTime(n.LastAt.Add(in.Cooldown))})
		return
	}

	last := "OK" // a pair with no row has been told nothing: it starts "below"
	if have {
		last = n.LastState
	}
	// 2. The target's view did not change: a filter result, not an event.
	if view(sc.To, t.MinSeverity) == view(last, t.MinSeverity) {
		return
	}

	// 3. Outside the cooldown (or no history, or a backwards clock): send.
	if !have || in.Cooldown == 0 || n.LastAt.After(in.Now) || !in.Now.Before(n.LastAt.Add(in.Cooldown)) {
		from := sc.From
		if have {
			l := n.LastState
			from = &l
		}
		reasons, codes := SplitReasons(sc.Reason)
		pl := store.NewDelivery{StateChangeID: scID, Kind: store.DeliveryStateChange}
		p.addStateDeliveries(out, t, host, alertID, pl, StateChangePayload{
			Schema: SchemaVersion, ID: alertID, Kind: KindStateChange, Target: t.Name, Host: host.Name,
			Tags: SortedTags(host.Tags), TS: FormatTime(sc.TS), URL: HostURL(p.PublicURL, host.Name),
			From: from, To: sc.To, Reason: reasons, ReasonCodes: codes,
			Resolved: Sev(sc.To) < Sev(t.MinSeverity), Changes: 1,
		})
		set(store.NotifyState{TargetID: t.ID, HostID: host.ID, LastState: sc.To, LastAt: in.Now})
		return
	}

	// 4. Inside the cooldown: hold.
	set(store.NotifyState{TargetID: t.ID, HostID: host.ID, LastState: n.LastState, LastAt: n.LastAt, HeldCount: 1})
	out.Logs = append(out.Logs, store.PlanLog{TargetID: t.ID, TargetName: t.Name, HostName: host.Name, StateChangeID: scID,
		Status: store.AlertLogHeld, Error: "cooldown until " + FormatTime(n.LastAt.Add(in.Cooldown))})
}

// resolveHold handles a hold whose window has ended.
func (p Planner) resolveHold(out *store.AlertPlanOutput, in store.AlertPlanInput, t store.AlertTarget, host store.PlanHost,
	n store.NotifyState, set func(store.NotifyState)) {

	var scID *int64
	if host.LatestChangeID != 0 {
		scID = i64p(host.LatestChangeID)
	}
	cleared := n
	cleared.HeldCount = 0

	// Defence in depth: UpdateAlertTarget removes the holds of a target whose
	// state changes were switched off in the same transaction, but a stale hold
	// must still never send.
	if !t.Enabled || !t.SendStateChanges || !matches(t, host.Tags) || host.State == nil {
		set(cleared)
		return
	}
	cur := *host.State
	if view(cur, t.MinSeverity) == view(n.LastState, t.MinSeverity) {
		set(cleared)
		out.Logs = append(out.Logs, store.PlanLog{TargetID: t.ID, TargetName: t.Name, HostName: host.Name, StateChangeID: scID,
			Status: store.AlertLogSkipped, Error: "back to " + cur + " within the cooldown; nothing to report"})
		return
	}
	id := p.NewID()
	from := n.LastState // what the target was told, NOT the latest change's own from
	reasons, codes := SplitReasons(host.Reason)
	changes := n.HeldCount
	pl := store.NewDelivery{StateChangeID: scID, Kind: store.DeliveryStateChange}
	p.addStateDeliveries(out, t, host, id, pl, StateChangePayload{
		Schema: SchemaVersion, ID: id, Kind: KindStateChange, Target: t.Name, Host: host.Name,
		Tags: SortedTags(host.Tags), TS: FormatTime(latestTS(host, in.Now)), URL: HostURL(p.PublicURL, host.Name),
		From: &from, To: cur, Reason: reasons, ReasonCodes: codes,
		Resolved: Sev(cur) < Sev(t.MinSeverity), Changes: changes,
	})
	set(store.NotifyState{TargetID: t.ID, HostID: host.ID, LastState: cur, LastAt: in.Now})
}

func latestTS(h store.PlanHost, now time.Time) time.Time {
	if h.LatestChangeID != 0 {
		return h.LatestChangeTS
	}
	return now
}

// addStateDeliveries writes one delivery per recipient (email) or one (webhook).
func (p Planner) addStateDeliveries(out *store.AlertPlanOutput, t store.AlertTarget, host store.PlanHost, alertID string,
	d store.NewDelivery, payload StateChangePayload) {
	body, err := Marshal(payload)
	if err != nil { // plain strings and ints: cannot happen
		panic(err)
	}
	p.fanOut(out, t, host, alertID, d, body)
}

func (p Planner) fanOut(out *store.AlertPlanOutput, t store.AlertTarget, host store.PlanHost, alertID string, d store.NewDelivery, body []byte) {
	d.AlertID, d.TargetID, d.HostID, d.Payload = alertID, t.ID, host.ID, body
	if t.Type != store.TargetTypeEmail {
		out.Deliveries = append(out.Deliveries, d)
		return
	}
	to, err := Recipients(t.Config)
	if err != nil || len(to) == 0 {
		out.Logs = append(out.Logs, store.PlanLog{TargetID: t.ID, TargetName: t.Name, HostName: host.Name, StateChangeID: d.StateChangeID,
			EventID: d.EventID, Status: store.AlertLogSkipped, Error: "email target has no readable recipients"})
		return
	}
	for _, r := range to {
		dr := d
		dr.Recipient = r
		out.Deliveries = append(out.Deliveries, dr)
	}
}

// winState is the planner's working copy of one open window.
type winState struct {
	idx        int // index in out.Windows, -1 until the window is touched
	id         int64
	target     int64
	host       int64
	start      time.Time
	sent       int
	members    []store.PlanWindowMember
	heldLogged bool
}

// windowSet holds the open windows by (target, host).
type windowSet struct {
	open map[pairKey]*winState
}

func newWindowSet(in store.AlertPlanInput) *windowSet {
	ws := &windowSet{open: map[pairKey]*winState{}}
	for _, w := range in.Windows {
		ws.open[pairKey{w.TargetID, w.HostID}] = &winState{
			idx: -1, id: w.ID, target: w.TargetID, host: w.HostID, start: w.Start, sent: w.Sent,
			members: append([]store.PlanWindowMember(nil), w.Members...), heldLogged: len(w.Members) > 0,
		}
	}
	return ws
}

// touch makes sure the window has an entry in out.Windows and returns it.
func (w *winState) touch(out *store.AlertPlanOutput) *store.WindowWrite {
	if w.idx < 0 {
		w.idx = len(out.Windows)
		out.Windows = append(out.Windows, store.WindowWrite{ID: w.id, TargetID: w.target, HostID: w.host, Start: w.start})
	}
	out.Windows[w.idx].Sent = w.sent
	return &out.Windows[w.idx]
}

func (p Planner) planDetection(out *store.AlertPlanOutput, in store.AlertPlanInput, ws *windowSet, targets []store.AlertTarget, host store.PlanHost, ev store.PlanEvent) {
	id := p.NewID()
	routed := false
	for _, t := range targets {
		if !t.Enabled || !t.SendDetections || !matches(t, host.Tags) {
			continue
		}
		routed = true
		if t.DetectionBurst > 0 && !p.admit(out, in, ws, t, host, ev) {
			continue // held in the window: the summary will report it
		}
		pl := DetectionPayload{
			Schema: SchemaVersion, ID: id, Kind: KindDetection, Target: t.Name, Host: host.Name,
			Tags: SortedTags(host.Tags), TS: FormatTime(ev.TS), URL: HostURL(p.PublicURL, host.Name),
			Path: ev.Path, Signature: ev.Signature, Source: ev.Source, ReceivedAt: FormatTime(ev.ReceivedAt),
		}
		raw, err := Marshal(pl)
		if err != nil {
			panic(err)
		}
		p.fanOut(out, t, host, id, store.NewDelivery{EventID: i64p(ev.ID), Kind: store.DeliveryDetection}, raw)
	}
	if !routed {
		out.Unrouted = append(out.Unrouted, ev.ID)
	}
}

// admit applies the burst rules to a detection for a target with burst B > 0 and
// says whether it is sent individually (true) or held in the window (false). The
// clock is ev.ReceivedAt, the server's.
func (p Planner) admit(out *store.AlertPlanOutput, in store.AlertPlanInput, ws *windowSet, t store.AlertTarget, host store.PlanHost, ev store.PlanEvent) bool {
	k := pairKey{t.ID, host.ID}
	w := ws.open[k]
	// 1. No open window, or the event is at or after the window's end (the boundary
	// is exclusive: received_at == start+W opens a new window): close the old one
	// first, which writes its summary, then open a new one.
	if w != nil && !ev.ReceivedAt.Before(w.start.Add(store.DetectionWindow)) {
		p.closeWindow(out, in, t, host, w)
		delete(ws.open, k)
		w = nil
	}
	if w == nil {
		w = &winState{idx: -1, target: t.ID, host: host.ID, start: ev.ReceivedAt}
		ws.open[k] = w
	}
	// 2. An event with received_at before the window's start (the server clock went
	// back) simply counts in the open window: a window is never stretched or
	// reopened backwards.
	if w.sent < t.DetectionBurst {
		w.sent++
		w.touch(out)
		return true
	}
	// 4. Beyond the burst: held.
	wr := w.touch(out)
	wr.AddMembers = append(wr.AddMembers, ev.ID)
	w.members = append(w.members, store.PlanWindowMember{EventID: ev.ID, TS: ev.TS, Signature: ev.Signature})
	if !w.heldLogged {
		w.heldLogged = true
		out.Logs = append(out.Logs, store.PlanLog{TargetID: t.ID, TargetName: t.Name, HostName: host.Name, EventID: i64p(ev.ID), Status: store.AlertLogHeld,
			Error: fmt.Sprintf("holding detections beyond %d until %s", t.DetectionBurst, FormatTime(w.start.Add(store.DetectionWindow)))})
	}
	return false
}

// closeWindow ends a window: with members it writes one summary delivery per
// recipient (not subject to the state-change cooldown: summaries are
// detections), without it the window just closes.
func (p Planner) closeWindow(out *store.AlertPlanOutput, in store.AlertPlanInput, t store.AlertTarget, host store.PlanHost, w *winState) {
	wr := w.touch(out)
	if len(w.members) == 0 {
		wr.Outcome = store.WindowEmpty
		return
	}
	wr.Outcome = store.WindowSummarised
	id := p.NewID()
	first, last := w.members[0].TS, w.members[0].TS
	counts := map[string]int{}
	for _, m := range w.members {
		if m.TS.Before(first) {
			first = m.TS
		}
		if m.TS.After(last) {
			last = m.TS
		}
		counts[m.Signature]++
	}
	sigs := make([]SignatureCount, 0, len(counts))
	for sig, n := range counts {
		sigs = append(sigs, SignatureCount{Signature: sig, Count: n})
	}
	sort.Slice(sigs, func(i, j int) bool {
		if sigs[i].Count != sigs[j].Count {
			return sigs[i].Count > sigs[j].Count
		}
		return sigs[i].Signature < sigs[j].Signature
	})
	more := 0
	if len(sigs) > maxSummarySignatures {
		more = len(sigs) - maxSummarySignatures
		sigs = sigs[:maxSummarySignatures]
	}
	raw, err := Marshal(DetectionSummaryPayload{
		Schema: SchemaVersion, ID: id, Kind: KindDetectionSummary, Target: t.Name, Host: host.Name,
		Tags: SortedTags(host.Tags), TS: FormatTime(in.Now), URL: EventsURL(p.PublicURL, host.Name),
		Count: len(w.members), FirstTS: FormatTime(first), LastTS: FormatTime(last),
		WindowStart: FormatTime(w.start), WindowEnd: FormatTime(w.start.Add(store.DetectionWindow)),
		WindowSeconds: int(store.DetectionWindow / time.Second), Signatures: sigs, MoreSignatures: more,
	})
	if err != nil {
		panic(err)
	}
	p.fanOut(out, t, host, id, store.NewDelivery{Kind: store.DeliveryDetectionSummary, WindowRef: w.idx + 1}, raw)
}

// maxSummarySignatures is how many signatures a summary lists.
const maxSummarySignatures = 10

// closeDueWindows closes every window whose time has come: now >= start+W, or
// now < start-1min (the clock went back by more than a minute: close now rather
// than hold indefinitely). A window of a target that stopped sending detections
// is discarded, never summarised (the store discards them at the switch; this
// is the defence in depth).
func (p Planner) closeDueWindows(out *store.AlertPlanOutput, in store.AlertPlanInput, ws *windowSet, byID map[int64]store.AlertTarget) {
	keys := make([]pairKey, 0, len(ws.open))
	for k := range ws.open {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].target != keys[j].target {
			return keys[i].target < keys[j].target
		}
		return keys[i].host < keys[j].host
	})
	for _, k := range keys {
		w := ws.open[k]
		due := !in.Now.Before(w.start.Add(store.DetectionWindow)) || in.Now.Before(w.start.Add(-time.Minute))
		if !due {
			continue
		}
		t, tok := byID[k.target]
		host, hok := in.Hosts[k.host]
		if !tok || !hok {
			continue // cascade removes them; nothing to send to
		}
		if !t.Enabled || !t.SendDetections {
			w.touch(out).Outcome = store.WindowDiscarded
		} else {
			p.closeWindow(out, in, t, host, w)
		}
		delete(ws.open, k)
	}
}
