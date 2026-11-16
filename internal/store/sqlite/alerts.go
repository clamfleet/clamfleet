// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// alerts.go: store.AlertStore on SQLite (docs/plans/milestone-4.md 4.2).
//
// The alert queue is a transactional outbox: nothing alert-related lives only
// in memory. Every decision is a conditional statement inside the single
// immediate write transaction (s.inTx) and its row count is read, never "read,
// decide in Go, write" across transactions:
//   - planning reads the flagged rows and writes deliveries, notify state, log
//     rows and clears the flags in ONE transaction, so a crash either leaves
//     the flags set (the plan runs again) or commits everything;
//   - a claim carries a random lease token and FinishAttempt only writes while
//     the token still matches, so a late result cannot overwrite a newer claim
//     or a cancellation.
//
// The store handles only SEALED secrets and never imports internal/alert: the
// pure planner arrives as a callback over store-owned types.
package sqlite

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite/sqlcdb"
)

var _ store.AlertStore = (*Store)(nil)

// maxPlanRows bounds one planning pass; the rest stays flagged for the next.
const maxPlanRows = 500

func nullInt64(v *int64) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *v, Valid: true}
}

func ptrInt64(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	return &n.Int64
}

func nullText(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func tagsJSON(tags []string) string {
	if tags == nil {
		tags = []string{}
	}
	b, _ := json.Marshal(tags) // plain strings: cannot fail
	return string(b)
}

func parseTags(s string) []string {
	var t []string
	if json.Unmarshal([]byte(s), &t) != nil {
		return nil
	}
	return t
}

func toTarget(r sqlcdb.AlertTarget) store.AlertTarget {
	return store.AlertTarget{
		ID: r.ID, Name: r.Name, Type: r.Type, Config: []byte(r.Config), Sealed: r.Secret,
		MinSeverity: r.MinSeverity, TagFilter: parseTags(r.TagFilter),
		SendStateChanges: r.SendStateChanges == 1, SendDetections: r.SendDetections == 1, DetectionBurst: int(r.DetectionBurst), Enabled: r.Enabled == 1,
		CreatedAt: time.Unix(r.CreatedAt, 0).UTC(), UpdatedAt: time.Unix(r.UpdatedAt, 0).UTC(),
	}
}

func validTargetFields(typ, minSev string) error {
	if typ != store.TargetTypeEmail && typ != store.TargetTypeWebhook {
		return fmt.Errorf("unknown alert target type %q", typ)
	}
	if minSev != "WARN" && minSev != "CRIT" && minSev != "STALE" {
		return fmt.Errorf("invalid minimum severity %q", minSev)
	}
	return nil
}

// CreateAlertTarget implements store.AlertStore.
func (s *Store) CreateAlertTarget(ctx context.Context, t store.NewAlertTarget, seal func(id int64) ([]byte, error), now time.Time, a store.Audit) (store.AlertTarget, error) {
	name, err := store.NormalizeAlertTargetName(t.Name)
	if err != nil {
		return store.AlertTarget{}, err
	}
	if err := validTargetFields(t.Type, t.MinSeverity); err != nil {
		return store.AlertTarget{}, err
	}
	var id int64
	var sealed []byte
	err = s.inTx(ctx, func(q *sqlcdb.Queries) error {
		if _, err := q.AlertTargetIDByName(ctx, name); err == nil {
			return store.ErrTargetExists
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		id, err = q.InsertAlertTarget(ctx, sqlcdb.InsertAlertTargetParams{
			Name: name, Type: t.Type, Config: string(t.Config), MinSeverity: t.MinSeverity, TagFilter: tagsJSON(t.TagFilter),
			SendStateChanges: boolInt(t.SendStateChanges), SendDetections: boolInt(t.SendDetections), DetectionBurst: int64(max(t.DetectionBurst, 0)),
			Enabled: boolInt(t.Enabled), Now: unix(now),
		})
		if err != nil {
			return err
		}
		if seal != nil {
			// Sealed inside the transaction with the new id, which is the AAD: a
			// blob cannot be moved to another target's row and still open.
			if sealed, err = seal(id); err != nil {
				return fmt.Errorf("seal target secret: %w", err)
			}
			if err := q.SetAlertTargetSecret(ctx, sqlcdb.SetAlertTargetSecretParams{Secret: sealed, Now: unix(now), ID: id}); err != nil {
				return err
			}
		}
		return writeAuditKind(ctx, q, now, a, store.ActionAlertTargetAdd, store.TargetAlertTarget, name, map[string]string{"type": t.Type})
	})
	if err != nil {
		return store.AlertTarget{}, err
	}
	return store.AlertTarget{
		ID: id, Name: name, Type: t.Type, Config: t.Config, Sealed: sealed, MinSeverity: t.MinSeverity, TagFilter: t.TagFilter,
		SendStateChanges: t.SendStateChanges, SendDetections: t.SendDetections, DetectionBurst: max(t.DetectionBurst, 0), Enabled: t.Enabled,
		CreatedAt: time.Unix(unix(now), 0).UTC(), UpdatedAt: time.Unix(unix(now), 0).UTC(),
	}, nil
}

// recipientsOf reads the "to" list of an email target's config. The store knows
// this one key so it can cancel the deliveries of a removed recipient.
func recipientsOf(config []byte) []string {
	var c struct {
		To []string `json:"to"`
	}
	if json.Unmarshal(config, &c) != nil {
		return nil
	}
	return c.To
}

// cancelPending cancels the target's pending deliveries of kind ("" = all) for
// which keep returns false, writing one 'cancelled' log row each.
func cancelPending(ctx context.Context, q *sqlcdb.Queries, t sqlcdb.AlertTarget, kind, why string, now time.Time, hit func(recipient string) bool) (int, error) {
	rows, err := q.PendingDeliveriesOfTarget(ctx, sqlcdb.PendingDeliveriesOfTargetParams{TargetID: t.ID, Kind: kind})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rows {
		if !hit(r.Recipient) {
			continue
		}
		c, err := q.CancelDelivery(ctx, sqlcdb.CancelDeliveryParams{Now: nullInt(now), ID: r.ID})
		if err != nil {
			return 0, err
		}
		if c == 0 {
			continue
		}
		n++
		if _, err := q.InsertAlertLog(ctx, sqlcdb.InsertAlertLogParams{
			Ts: unix(now), TargetID: sql.NullInt64{Int64: t.ID, Valid: true}, TargetName: t.Name,
			DeliveryID: sql.NullInt64{Int64: r.ID, Valid: true}, Recipient: nullText(r.Recipient), HostName: nullStr(r.HostName),
			StateChangeID: r.StateChangeID, EventID: r.EventID, Attempt: sql.NullInt64{Int64: r.Attempts, Valid: r.Attempts > 0},
			Status: store.AlertLogCancelled, Error: nullStr(why),
		}); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// UpdateAlertTarget implements store.AlertStore.
func (s *Store) UpdateAlertTarget(ctx context.Context, name string, u store.AlertTargetUpdate, seal func(id int64) ([]byte, error), now time.Time, a store.Audit) (store.Cancelled, error) {
	name = lower(name)
	var res store.Cancelled
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		old, err := q.AlertTargetByName(ctx, name)
		if err != nil {
			return notFound(err)
		}
		if u.Expect != nil && !snapshotMatches(old, *u.Expect) {
			return store.ErrChangedMeanwhile
		}
		if err := validTargetFields(old.Type, u.MinSeverity); err != nil {
			return err
		}
		var changed []string
		if string(u.Config) != old.Config {
			changed = append(changed, "recipients_or_url")
		}
		if u.MinSeverity != old.MinSeverity {
			changed = append(changed, "min_severity")
		}
		if tagsJSON(u.TagFilter) != old.TagFilter {
			changed = append(changed, "tag_filter")
		}
		if boolInt(u.SendStateChanges) != old.SendStateChanges {
			changed = append(changed, "send_state_changes")
		}
		if boolInt(u.SendDetections) != old.SendDetections {
			changed = append(changed, "send_detections")
		}
		burst := old.DetectionBurst
		if u.DetectionBurst != nil {
			if *u.DetectionBurst < 0 {
				return fmt.Errorf("detection burst must not be negative")
			}
			burst = int64(*u.DetectionBurst)
		}
		if burst != old.DetectionBurst {
			changed = append(changed, "detection_burst")
		}
		if boolInt(u.Enabled) != old.Enabled {
			changed = append(changed, "enabled")
		}
		if seal != nil {
			changed = append(changed, "secret")
		}
		if len(changed) == 0 {
			return nil
		}
		if err := q.UpdateAlertTarget(ctx, sqlcdb.UpdateAlertTargetParams{
			Config: string(u.Config), MinSeverity: u.MinSeverity, TagFilter: tagsJSON(u.TagFilter),
			SendStateChanges: boolInt(u.SendStateChanges), SendDetections: boolInt(u.SendDetections), DetectionBurst: burst,
			Enabled: boolInt(u.Enabled), Now: unix(now), ID: old.ID,
		}); err != nil {
			return err
		}
		if seal != nil {
			blob, err := seal(old.ID)
			if err != nil {
				return fmt.Errorf("seal target secret: %w", err)
			}
			if err := q.SetAlertTargetSecret(ctx, sqlcdb.SetAlertTargetSecretParams{Secret: blob, Now: unix(now), ID: old.ID}); err != nil {
				return err
			}
		}

		// Switching off (plan 4.3): what is pending for a kind that is now off
		// must not go out later, and a hold or "last told" for state changes that
		// are off is dropped so turning them back on starts fresh.
		all := func(string) bool { return true }
		disabling := old.Enabled == 1 && !u.Enabled
		stateOff := old.SendStateChanges == 1 && !u.SendStateChanges
		detOff := old.SendDetections == 1 && !u.SendDetections
		switch {
		case disabling:
			res.Deliveries, err = cancelPending(ctx, q, old, "", "target disabled", now, all)
		case stateOff && detOff:
			res.Deliveries, err = cancelPending(ctx, q, old, "", "state changes and detections switched off", now, all)
		case stateOff:
			res.Deliveries, err = cancelPending(ctx, q, old, store.DeliveryStateChange, "state changes switched off", now, all)
		case detOff:
			res.Deliveries, err = cancelPending(ctx, q, old, store.DeliveryDetection, "detections switched off", now, all)
		}
		if err != nil {
			return err
		}
		if disabling || stateOff {
			if err := q.DeleteNotifyStateOfTarget(ctx, old.ID); err != nil {
				return err
			}
		}
		// Rule (M5 decision 15): detections switched off, or the target disabled, while
		// a burst window holds detections: discard them, never summarise. It does
		// what the switch says, and matches the cancelling of pending detection
		// deliveries above. The detections stay stored and on the events page.
		if disabling || detOff {
			if res.HeldDetections, err = discardWindows(ctx, q, old, now); err != nil {
				return err
			}
		}
		if old.Type == store.TargetTypeEmail && !disabling {
			keep := recipientsOf(u.Config)
			n, err := cancelPending(ctx, q, old, "", "recipient removed", now, func(r string) bool { return r != "" && !slices.Contains(keep, r) })
			if err != nil {
				return err
			}
			res.Deliveries += n
		}

		detail := map[string]string{"fields": strings.Join(changed, ",")}
		if res.Deliveries > 0 {
			detail["cancelled"] = strconv.Itoa(res.Deliveries)
		}
		return writeAuditKind(ctx, q, now, a, store.ActionAlertTargetUpdate, store.TargetAlertTarget, name, detail)
	})
	return res, err
}

// discardWindows closes the open detection windows of a target as 'discarded'
// and writes one 'cancelled' log row per window that held detections. It
// returns how many held detections were dropped.
func discardWindows(ctx context.Context, q *sqlcdb.Queries, t sqlcdb.AlertTarget, now time.Time) (int, error) {
	rows, err := q.OpenWindowsOfTarget(ctx, t.ID)
	if err != nil {
		return 0, err
	}
	dropped := 0
	for _, w := range rows {
		if err := q.CloseWindow(ctx, sqlcdb.CloseWindowParams{ClosedAt: nullInt(now), Outcome: nullStr(store.WindowDiscarded), ID: w.ID}); err != nil {
			return 0, err
		}
		if w.Members == 0 {
			continue
		}
		dropped += int(w.Members)
		if _, err := q.InsertAlertLog(ctx, sqlcdb.InsertAlertLogParams{
			Ts: unix(now), TargetID: sql.NullInt64{Int64: t.ID, Valid: true}, TargetName: t.Name, HostName: nullStr(w.HostName),
			Status: store.AlertLogCancelled,
			Error:  nullStr(fmt.Sprintf("%d held detections were not summarised: detections switched off for this target", w.Members)),
		}); err != nil {
			return 0, err
		}
	}
	return dropped, nil
}

// snapshotMatches is the compare of the compare-and-swap of updates and rotations.
func snapshotMatches(t sqlcdb.AlertTarget, e store.TargetSnapshot) bool {
	return t.Config == string(e.Config) && bytes.Equal(t.Secret, e.Sealed)
}

// RotateAlertSecret implements store.AlertStore.
func (s *Store) RotateAlertSecret(ctx context.Context, name string, expect store.TargetSnapshot, seal func(id int64) ([]byte, error), now time.Time, a store.Audit) error {
	name = lower(name)
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		t, err := q.AlertTargetByName(ctx, name)
		if err != nil {
			return notFound(err)
		}
		if t.Type != store.TargetTypeWebhook {
			return fmt.Errorf("target %q has no signing key", name)
		}
		if !snapshotMatches(t, expect) {
			return store.ErrChangedMeanwhile
		}
		blob, err := seal(t.ID)
		if err != nil {
			return fmt.Errorf("seal target secret: %w", err)
		}
		if err := q.SetAlertTargetSecret(ctx, sqlcdb.SetAlertTargetSecretParams{Secret: blob, Now: unix(now), ID: t.ID}); err != nil {
			return err
		}
		return writeAuditKind(ctx, q, now, a, store.ActionAlertTargetRotate, store.TargetAlertTarget, name, nil)
	})
}

// DeleteAlertTarget implements store.AlertStore.
func (s *Store) DeleteAlertTarget(ctx context.Context, name string, now time.Time, a store.Audit) error {
	name = lower(name)
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		t, err := q.AlertTargetByName(ctx, name)
		if err != nil {
			return notFound(err)
		}
		if _, err := q.DeleteAlertTarget(ctx, t.ID); err != nil {
			return err
		}
		return writeAuditKind(ctx, q, now, a, store.ActionAlertTargetDelete, store.TargetAlertTarget, name, map[string]string{"type": t.Type})
	})
}

// AlertTarget implements store.AlertStore.
func (s *Store) AlertTarget(ctx context.Context, name string) (store.AlertTarget, error) {
	r, err := sqlcdb.New(s.r).AlertTargetByName(ctx, lower(name))
	if err != nil {
		return store.AlertTarget{}, notFound(err)
	}
	return toTarget(r), nil
}

// ListAlertTargets implements store.AlertStore.
func (s *Store) ListAlertTargets(ctx context.Context) ([]store.AlertTargetSummary, error) {
	rows, err := sqlcdb.New(s.r).ListAlertTargets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]store.AlertTargetSummary, 0, len(rows))
	for _, r := range rows {
		sum := store.AlertTargetSummary{
			AlertTarget: toTarget(sqlcdb.AlertTarget{ID: r.ID, Name: r.Name, Type: r.Type, Config: r.Config, Secret: r.Secret,
				MinSeverity: r.MinSeverity, TagFilter: r.TagFilter, SendStateChanges: r.SendStateChanges, SendDetections: r.SendDetections,
				Enabled: r.Enabled, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, DetectionBurst: r.DetectionBurst}),
			LastStatus: r.LastStatus, LastCode: r.LastCode,
		}
		if r.LastStatus != "" {
			t := time.Unix(r.LastTs, 0).UTC()
			sum.LastAt = &t
		}
		out = append(out, sum)
	}
	return out, nil
}

// CountPendingAlerts implements store.AlertStore.
func (s *Store) CountPendingAlerts(ctx context.Context, name string) (int, error) {
	q := sqlcdb.New(s.r)
	id, err := q.AlertTargetIDByName(ctx, lower(name))
	if err != nil {
		return 0, notFound(err)
	}
	n, err := q.CountPendingDeliveriesOfTarget(ctx, id)
	return int(n), err
}

// HasAlertWork implements store.AlertStore.
func (s *Store) HasAlertWork(ctx context.Context, now time.Time, cooldown time.Duration) (bool, error) {
	q := sqlcdb.New(s.r)
	checks := []func() (bool, error){
		func() (bool, error) { return q.HasFlaggedStateChange(ctx) },
		func() (bool, error) { return q.HasFlaggedEvent(ctx) },
		func() (bool, error) {
			return q.HasDueWindow(ctx, sqlcdb.HasDueWindowParams{WindowSecs: int64(store.DetectionWindow / time.Second), Now: unix(now)})
		},
		func() (bool, error) {
			return q.HasDueHold(ctx, sqlcdb.HasDueHoldParams{CooldownSecs: int64(cooldown / time.Second), Now: unix(now)})
		},
		func() (bool, error) { return q.HasDueDelivery(ctx, nullInt(now)) },
		func() (bool, error) { return q.HasExpiredLease(ctx, nullInt(now)) },
	}
	for _, c := range checks {
		ok, err := c()
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

type notifyKey struct{ target, host int64 }

// PlanAlerts implements store.AlertStore.
func (s *Store) PlanAlerts(ctx context.Context, now time.Time, cooldown time.Duration, plan func(store.AlertPlanInput) store.AlertPlanOutput) (store.PlanResult, error) {
	var res store.PlanResult
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		res = store.PlanResult{}
		scRows, err := q.FlaggedStateChanges(ctx, maxPlanRows)
		if err != nil {
			return err
		}
		evRows, err := q.FlaggedEvents(ctx, maxPlanRows)
		if err != nil {
			return err
		}
		targetRows, err := q.ListAllAlertTargets(ctx)
		if err != nil {
			return err
		}
		held, err := q.HeldNotifyRows(ctx)
		if err != nil {
			return err
		}
		winRows, err := q.OpenWindows(ctx)
		if err != nil {
			return err
		}
		memRows, err := q.OpenWindowMembers(ctx)
		if err != nil {
			return err
		}

		in := store.AlertPlanInput{Now: now, Cooldown: cooldown, Hosts: map[int64]store.PlanHost{}}
		winIdx := map[int64]int{}
		for _, w := range winRows {
			winIdx[w.ID] = len(in.Windows)
			in.Windows = append(in.Windows, store.PlanWindow{ID: w.ID, TargetID: w.TargetID, HostID: w.HostID, Start: time.Unix(w.WindowStart, 0).UTC(), Sent: int(w.Sent)})
		}
		for _, m := range memRows {
			if i, ok := winIdx[m.WindowID]; ok {
				in.Windows[i].Members = append(in.Windows[i].Members, store.PlanWindowMember{EventID: m.EventID, TS: time.Unix(m.Ts, 0).UTC(), Signature: m.Signature})
			}
		}
		for _, t := range targetRows {
			in.Targets = append(in.Targets, toTarget(t))
		}
		hostIDs := map[int64]bool{}
		var maxSC, maxEV int64
		for _, r := range scRows {
			in.Changes = append(in.Changes, store.PlanStateChange{
				ID: r.ID, HostID: r.HostID, TS: time.Unix(r.Ts, 0).UTC(), From: nullString(r.FromState), To: r.ToState, Reason: json.RawMessage(r.Reason),
			})
			hostIDs[r.HostID] = true
			maxSC = max(maxSC, r.ID)
		}
		evHost := map[int64]int64{}
		for _, r := range evRows {
			in.Events = append(in.Events, store.PlanEvent{
				ID: r.ID, HostID: r.HostID, TS: time.Unix(r.Ts, 0).UTC(), ReceivedAt: time.Unix(r.ReceivedAt, 0).UTC(),
				Path: r.Path, Signature: r.Signature, Source: r.Source,
			})
			hostIDs[r.HostID] = true
			evHost[r.ID] = r.HostID
			maxEV = max(maxEV, r.ID)
		}
		for _, h := range held {
			hostIDs[h.HostID] = true
		}
		for _, w := range in.Windows {
			hostIDs[w.HostID] = true
		}

		ids := make([]int64, 0, len(hostIDs))
		for id := range hostIDs {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		seen := map[notifyKey]bool{}
		res.Hosts = map[int64]string{}
		for _, id := range ids {
			h, err := q.PlanHostByID(ctx, id)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			tags, err := q.ListHostTags(ctx, id)
			if err != nil {
				return err
			}
			ph := store.PlanHost{ID: h.ID, Name: h.Name, Tags: tags, State: nullString(h.State), Reason: rawJSON(h.StateReason), LatestChangeID: h.LatestChangeID}
			if h.LatestChangeID != 0 {
				ph.LatestChangeTS = time.Unix(h.LatestChangeTs, 0).UTC()
			}
			in.Hosts[id] = ph
			res.Hosts[id] = h.Name
			ns, err := q.NotifyRowsOfHost(ctx, id)
			if err != nil {
				return err
			}
			for _, n := range ns {
				k := notifyKey{n.TargetID, n.HostID}
				if !seen[k] {
					seen[k] = true
					in.Notify = append(in.Notify, store.NotifyState{TargetID: n.TargetID, HostID: n.HostID, LastState: n.LastState,
						LastAt: time.Unix(n.LastAt, 0).UTC(), HeldCount: int(n.HeldCount)})
				}
			}
		}

		out := plan(in)

		if s.beforeAlertPlanWrite != nil {
			if err := s.beforeAlertPlanWrite(); err != nil {
				return err
			}
		}

		// Windows first, in the planner's order (a window that closes comes before
		// the one that replaces it, so the one-open-window index is never violated),
		// then the deliveries that consume them, all in this one transaction: a window
		// is closed exactly when its summary is written, or neither is.
		windowIDs := make([]int64, len(out.Windows))
		for i, w := range out.Windows {
			id := w.ID
			if id == 0 {
				if id, err = q.InsertWindow(ctx, sqlcdb.InsertWindowParams{TargetID: w.TargetID, HostID: w.HostID, WindowStart: unix(w.Start), Sent: int64(w.Sent)}); err != nil {
					return err
				}
			} else if err := q.SetWindowSent(ctx, sqlcdb.SetWindowSentParams{Sent: int64(w.Sent), ID: id}); err != nil {
				return err
			}
			windowIDs[i] = id
			for _, ev := range w.AddMembers {
				if err := q.InsertWindowMember(ctx, sqlcdb.InsertWindowMemberParams{WindowID: id, EventID: ev}); err != nil {
					return err
				}
			}
			// Closed here, before the next window is inserted; still in this
			// transaction, so a failure of a delivery insert below rolls the close
			// back with everything else.
			if w.Outcome != "" {
				if err := q.CloseWindow(ctx, sqlcdb.CloseWindowParams{ClosedAt: nullInt(now), Outcome: nullStr(w.Outcome), ID: id}); err != nil {
					return err
				}
			}
		}
		for _, d := range out.Deliveries {
			var winID sql.NullInt64
			if d.WindowRef > 0 {
				winID = sql.NullInt64{Int64: windowIDs[d.WindowRef-1], Valid: true}
			}
			if err := q.InsertDelivery(ctx, sqlcdb.InsertDeliveryParams{
				AlertID: d.AlertID, TargetID: d.TargetID, HostID: d.HostID, Recipient: d.Recipient,
				StateChangeID: nullInt64(d.StateChangeID), EventID: nullInt64(d.EventID), WindowID: winID, Kind: d.Kind, Payload: string(d.Payload), Now: nullInt(now),
			}); err != nil {
				return err
			}
		}

		if s.afterAlertPlanDeliveries != nil {
			if err := s.afterAlertPlanDeliveries(); err != nil {
				return err
			}
		}
		for _, n := range out.Notify {
			if err := q.UpsertNotifyState(ctx, sqlcdb.UpsertNotifyStateParams{
				TargetID: n.TargetID, HostID: n.HostID, LastState: n.LastState, LastAt: unix(n.LastAt), HeldCount: int64(n.HeldCount),
			}); err != nil {
				return err
			}
		}
		for _, l := range out.Logs {
			if _, err := q.InsertAlertLog(ctx, sqlcdb.InsertAlertLogParams{
				Ts: unix(now), TargetID: sql.NullInt64{Int64: l.TargetID, Valid: true}, TargetName: l.TargetName,
				HostName: nullText(l.HostName), StateChangeID: nullInt64(l.StateChangeID), EventID: nullInt64(l.EventID),
				Status: l.Status, Error: nullText(l.Error),
			}); err != nil {
				return err
			}
			if l.Status == store.AlertLogHeld {
				res.Held++
			}
		}
		for _, id := range out.Unrouted {
			res.Unrouted = append(res.Unrouted, store.UnroutedEvent{EventID: id, Host: res.Hosts[evHost[id]]})
		}
		res.Deliveries = out.Deliveries

		// Flags last, in the same transaction: everything above committed or none of it.
		if maxSC > 0 {
			if err := q.ClearStateChangeFlags(ctx, maxSC); err != nil {
				return err
			}
		}
		if maxEV > 0 {
			if err := q.ClearEventFlags(ctx, maxEV); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return store.PlanResult{}, err
	}
	return res, nil
}

// ExpireLeases implements store.AlertStore.
func (s *Store) ExpireLeases(ctx context.Context, now time.Time, all bool) (expired, exhausted int, err error) {
	err = s.inTx(ctx, func(q *sqlcdb.Queries) error {
		expired, exhausted = 0, 0
		allClaims := int64(0)
		if all {
			allClaims = 1
		}
		rows, err := q.ExpiredLeases(ctx, sqlcdb.ExpiredLeasesParams{AllClaims: allClaims, Now: nullInt(now)})
		if err != nil {
			return err
		}
		for _, r := range rows {
			if err := q.InterruptAttemptLog(ctx, sqlcdb.InterruptAttemptLogParams{
				DeliveryID: sql.NullInt64{Int64: r.ID, Valid: true}, Attempt: sql.NullInt64{Int64: r.Attempts, Valid: true},
			}); err != nil {
				return err
			}
			if r.Attempts < store.MaxAlertAttempts {
				if err := q.ReleaseDelivery(ctx, sqlcdb.ReleaseDeliveryParams{Now: nullInt(now), ID: r.ID}); err != nil {
					return err
				}
				expired++
				continue
			}
			// The last attempt was interrupted: the delivery ends here, in the same
			// transaction as its log row. Re-queuing it would let a delivery that
			// crashes the process run forever.
			if err := q.FailDelivery(ctx, sqlcdb.FailDeliveryParams{Now: nullInt(now), ID: r.ID}); err != nil {
				return err
			}
			if s.betweenExpireWrites != nil {
				if err := s.betweenExpireWrites(); err != nil {
					return err
				}
			}
			if _, err := q.InsertAlertLog(ctx, sqlcdb.InsertAlertLogParams{
				Ts: unix(now), TargetID: sql.NullInt64{Int64: r.TargetID, Valid: true}, TargetName: r.TargetName,
				DeliveryID: sql.NullInt64{Int64: r.ID, Valid: true}, Recipient: nullText(r.Recipient), HostName: nullStr(r.HostName),
				StateChangeID: r.StateChangeID, EventID: r.EventID, Attempt: sql.NullInt64{Int64: r.Attempts, Valid: true},
				Status: store.AlertLogFailed, Code: nullStr("interrupted"),
				Error: nullStr(fmt.Sprintf("attempt %d was interrupted; giving up", r.Attempts)),
			}); err != nil {
				return err
			}
			exhausted++
		}
		if all {
			// A claim that no longer exists (its delivery was cancelled or
			// finished meanwhile) can still have an 'attempting' row from a dead process.
			return q.InterruptAllAttemptLogs(ctx)
		}
		return nil
	})
	return expired, exhausted, err
}

// dueRow is the common shape of the two due queries' rows.
type dueRow struct {
	ID            int64
	AlertID       string
	TargetID      int64
	HostID        int64
	Recipient     string
	StateChangeID sql.NullInt64
	EventID       sql.NullInt64
	Kind          string
	Payload       string
	Attempts      int64
	HostName      string
}

// ClaimDeliveries implements store.AlertStore.
func (s *Store) ClaimDeliveries(ctx context.Context, now time.Time, lease time.Duration, lim store.ClaimLimits) ([]store.ClaimedDelivery, error) {
	if lim.Total <= 0 {
		return nil, nil
	}
	var out []store.ClaimedDelivery
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		out = nil
		targets := map[int64]sqlcdb.AlertTarget{}
		claim := func(rows []dueRow) error {
			for _, r := range rows {
				token := make([]byte, 16)
				if _, err := rand.Read(token); err != nil {
					return err
				}
				n, err := q.ClaimDelivery(ctx, sqlcdb.ClaimDeliveryParams{Token: token, LeaseUntil: nullInt(now.Add(lease)), ID: r.ID})
				if err != nil {
					return err
				}
				if n == 0 {
					continue
				}
				t, ok := targets[r.TargetID]
				if !ok {
					if t, err = q.AlertTargetByID(ctx, r.TargetID); err != nil {
						return err
					}
					targets[r.TargetID] = t
				}
				attempt := int(r.Attempts) + 1
				logID, err := q.InsertAlertLog(ctx, sqlcdb.InsertAlertLogParams{
					Ts: unix(now), TargetID: sql.NullInt64{Int64: t.ID, Valid: true}, TargetName: t.Name,
					DeliveryID: sql.NullInt64{Int64: r.ID, Valid: true}, Recipient: nullText(r.Recipient), HostName: nullStr(r.HostName),
					StateChangeID: r.StateChangeID, EventID: r.EventID, Attempt: sql.NullInt64{Int64: int64(attempt), Valid: true},
					Status: store.AlertLogAttempting,
				})
				if err != nil {
					return err
				}
				out = append(out, store.ClaimedDelivery{
					ID: r.ID, AlertID: r.AlertID, Target: toTarget(t), HostID: r.HostID, HostName: r.HostName, Recipient: r.Recipient,
					StateChangeID: ptrInt64(r.StateChangeID), EventID: ptrInt64(r.EventID), Kind: r.Kind, Payload: []byte(r.Payload),
					Attempt: attempt, Token: token, LogID: logID, ClaimedAt: now,
				})
			}
			return nil
		}
		// State alerts first: a CRIT must never wait behind detections.
		states, err := q.DueStateDeliveries(ctx, sqlcdb.DueStateDeliveriesParams{Now: nullInt(now), MaxRows: int64(lim.Total)})
		if err != nil {
			return err
		}
		rows := make([]dueRow, 0, len(states))
		for _, r := range states {
			rows = append(rows, dueRow(r))
		}
		if err := claim(rows); err != nil {
			return err
		}
		// Then detections and summaries in what is left, within the reserve and
		// the per-target cap.
		detMax := min(lim.Total-len(out), lim.Detections)
		if detMax <= 0 {
			return nil
		}
		perTarget := int64(lim.PerTarget)
		if perTarget <= 0 {
			perTarget = 1 << 30
		}
		dets, err := q.DueDetectionDeliveries(ctx, sqlcdb.DueDetectionDeliveriesParams{Now: nullInt(now), PerTarget: perTarget, MaxRows: int64(detMax)})
		if err != nil {
			return err
		}
		rows = rows[:0]
		for _, r := range dets {
			rows = append(rows, dueRow(r))
		}
		return claim(rows)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FinishAttempt implements store.AlertStore.
func (s *Store) FinishAttempt(ctx context.Context, c store.ClaimedDelivery, r store.AttemptResult, now time.Time) error {
	lost := false
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		lost = false
		// The log row is updated while it is still 'attempting', whatever happens
		// to the delivery: when the attempt's delivery was cancelled meanwhile this
		// row is the only record of whether the message went out.
		if err := q.FinishAttemptLog(ctx, sqlcdb.FinishAttemptLogParams{
			Status: r.Status, Code: nullText(r.Code), Error: nullText(r.Error),
			DurationMs: sql.NullInt64{Int64: r.Duration.Milliseconds(), Valid: true}, ID: c.LogID,
		}); err != nil {
			return err
		}
		p := sqlcdb.FinishDeliveryParams{ID: c.ID, Token: c.Token}
		switch r.Status {
		case store.AlertLogSent:
			p.Status, p.FinishedAt = "sent", nullInt(now)
		case store.AlertLogFailed:
			p.Status, p.FinishedAt = "failed", nullInt(now)
		case store.AlertLogRetrying:
			p.Status, p.NextAttemptAt = "pending", nullInt(r.RetryAt)
		default:
			return fmt.Errorf("invalid attempt status %q", r.Status)
		}
		n, err := q.FinishDelivery(ctx, p)
		if err != nil {
			return err
		}
		lost = n == 0
		return nil
	})
	if err != nil {
		return err
	}
	if lost {
		return store.ErrLeaseLost
	}
	return nil
}

// RecordTestSend implements store.AlertStore.
func (s *Store) RecordTestSend(ctx context.Context, targetName string, rs []store.TestSendRecord, now time.Time, a store.Audit) error {
	targetName = lower(targetName)
	return s.inTx(ctx, func(q *sqlcdb.Queries) error {
		t, err := q.AlertTargetByName(ctx, targetName)
		if err != nil {
			return notFound(err)
		}
		result, code := "sent", ""
		for _, r := range rs {
			status := store.AlertLogTestSent
			if r.Result.Status != store.AlertLogSent && r.Result.Status != store.AlertLogTestSent {
				status = store.AlertLogTestFailed
				if result == "sent" {
					result, code = "failed", r.Result.Code
				}
			}
			if _, err := q.InsertAlertLog(ctx, sqlcdb.InsertAlertLogParams{
				Ts: unix(now), TargetID: sql.NullInt64{Int64: t.ID, Valid: true}, TargetName: t.Name, Recipient: nullText(r.Recipient),
				Status: status, Code: nullText(r.Result.Code), Error: nullText(r.Result.Error),
				DurationMs: sql.NullInt64{Int64: r.Result.Duration.Milliseconds(), Valid: true},
			}); err != nil {
				return err
			}
		}
		detail := map[string]string{"result": result}
		if code != "" {
			detail["code"] = code
		}
		return writeAuditKind(ctx, q, now, a, store.ActionAlertTargetTest, store.TargetAlertTarget, t.Name, detail)
	})
}

// AlertLog implements store.AlertStore.
func (s *Store) AlertLog(ctx context.Context, f store.AlertLogFilter) ([]store.AlertLogEntry, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, 1000)
	rows, err := sqlcdb.New(s.r).ListAlertLog(ctx, sqlcdb.ListAlertLogParams{TargetName: lower(f.TargetName), MaxRows: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]store.AlertLogEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, store.AlertLogEntry{
			ID: r.ID, TS: time.Unix(r.Ts, 0).UTC(), TargetName: r.TargetName, Recipient: r.Recipient.String, Host: r.HostName.String, Kind: r.Kind,
			Attempt: int(r.Attempt.Int64), Status: r.Status, Code: r.Code.String, Error: r.Error.String, DurationMS: r.DurationMs.Int64,
		})
	}
	return out, nil
}

// UnroutedDetections implements store.AlertStore.
func (s *Store) UnroutedDetections(ctx context.Context, since time.Time) (int64, error) {
	return sqlcdb.New(s.r).CountUnroutedDetections(ctx, unix(since))
}

// PruneAlertHistory implements store.AlertStore. Each batch is its own
// transaction, so the write lock is released between them (spec 8.3).
func (s *Store) PruneAlertHistory(ctx context.Context, before time.Time, batch int) (int64, error) {
	if batch <= 0 {
		batch = 5000
	}
	var total int64
	for {
		var logs, dels int64
		err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
			var err error
			if logs, err = q.PruneAlertLog(ctx, sqlcdb.PruneAlertLogParams{Before: unix(before), Batch: int64(batch)}); err != nil {
				return err
			}
			dels, err = q.PruneFinishedDeliveries(ctx, sqlcdb.PruneFinishedDeliveriesParams{Before: nullInt(before), Batch: int64(batch)})
			return err
		})
		if err != nil {
			return total, err
		}
		total += logs + dels
		if logs < int64(batch) && dels < int64(batch) {
			return total, nil
		}
	}
}

// SealedAlertSecrets implements store.AlertStore.
func (s *Store) SealedAlertSecrets(ctx context.Context) ([]store.SealedTargetSecret, error) {
	rows, err := sqlcdb.New(s.r).SealedAlertSecrets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]store.SealedTargetSecret, 0, len(rows))
	for _, r := range rows {
		out = append(out, store.SealedTargetSecret{ID: r.ID, Name: r.Name, Sealed: r.Secret})
	}
	return out, nil
}

// ResealAlertSecrets implements store.AlertStore.
func (s *Store) ResealAlertSecrets(ctx context.Context, rs []store.AlertReseal, now time.Time, a store.Audit) (int, []int64, error) {
	res, err := s.ResealSecrets(ctx, nil, rs, now, a)
	return res.AlertTargets, res.AlertConflicts, err
}

// ResealSecrets implements store.AlertStore. One transaction for both kinds of
// secret, so an interrupted key rotation (a crash, a database error) re-seals
// nothing and running it again does the whole job; a row that changed between
// the caller's read and this write (an admin rotated a webhook key, a user
// re-enrolled TOTP) is reported as a conflict instead of being overwritten, and
// the caller must say so (exit 1) rather than claim a complete rotation.
func (s *Store) ResealSecrets(ctx context.Context, totp []store.Reseal, alerts []store.AlertReseal, now time.Time, a store.Audit) (store.ResealResult, error) {
	var res store.ResealResult
	err := s.inTx(ctx, func(q *sqlcdb.Queries) error {
		res = store.ResealResult{}
		for _, r := range totp {
			n, err := q.ResealTOTPSecret(ctx, sqlcdb.ResealTOTPSecretParams{NewSecret: r.New, ID: r.UserID, OldSecret: r.Old})
			if err != nil {
				return err
			}
			if n == 1 {
				res.TOTP++
			} else {
				res.TOTPConflicts = append(res.TOTPConflicts, r.UserID)
			}
			if s.betweenResealRows != nil {
				if err := s.betweenResealRows(); err != nil {
					return err
				}
			}
		}
		for _, r := range alerts {
			n, err := q.ResealAlertSecret(ctx, sqlcdb.ResealAlertSecretParams{NewSecret: r.New, ID: r.TargetID, OldSecret: r.Old})
			if err != nil {
				return err
			}
			if n == 1 {
				res.AlertTargets++
			} else {
				res.AlertConflicts = append(res.AlertConflicts, r.TargetID)
			}
			if s.betweenResealRows != nil {
				if err := s.betweenResealRows(); err != nil {
					return err
				}
			}
		}
		applied := res.TOTP + res.AlertTargets
		if applied == 0 {
			return nil // idempotent: nothing to do, nothing to audit
		}
		return writeAuditKind(ctx, q, now, a, store.ActionSecretsReseal, store.TargetServer, store.TargetServer, map[string]string{
			"count": strconv.Itoa(applied), "totp": strconv.Itoa(res.TOTP), "alert_target": strconv.Itoa(res.AlertTargets),
			"conflicts": strconv.Itoa(len(res.TOTPConflicts) + len(res.AlertConflicts)),
		})
	})
	if err != nil {
		return store.ResealResult{}, err
	}
	return res, nil
}
