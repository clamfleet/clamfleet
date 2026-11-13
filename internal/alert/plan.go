// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// plan.go: the pure alert planner (docs/plans/milestone-4.md 4.3).
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
// Detections are never held and ignore the minimum severity.
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

	for _, ev := range in.Events {
		host, ok := in.Hosts[ev.HostID]
		if !ok {
			continue
		}
		p.planDetection(&out, targets, host, ev)
	}

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

func (p Planner) planDetection(out *store.AlertPlanOutput, targets []store.AlertTarget, host store.PlanHost, ev store.PlanEvent) {
	id := p.NewID()
	routed := false
	for _, t := range targets {
		if !t.Enabled || !t.SendDetections || !matches(t, host.Tags) {
			continue
		}
		routed = true
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
