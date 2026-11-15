// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
)

// detectionsFor records one detection for each of n hosts (h0..), plans them
// all, and returns the host ids.
func detectionsFor(t *testing.T, s *Store, n int) []int64 {
	t.Helper()
	var ids []int64
	for i := 0; i < n; i++ {
		h := addHost(t, s, fmt.Sprintf("h%d", i))
		ids = append(ids, h.ID)
		if _, err := s.RecordEvent(context.Background(), store.EventRecord{HostID: h.ID, ReceivedAt: t0,
			Event: proto.Event{TS: t0, Path: "/p", Signature: "S", Source: "clamd"}}); err != nil {
			t.Fatal(err)
		}
	}
	plan(t, s, t0)
	return ids
}

func kinds(got []store.ClaimedDelivery) (state int, det map[string]int) {
	det = map[string]int{}
	for _, c := range got {
		if c.Kind == store.DeliveryStateChange {
			state++
		} else {
			det[c.Target.Name]++
		}
	}
	return
}

// With 10 due detection deliveries for target D and one due state delivery, a
// claim for 4 idle workers returns the state delivery first and at most 2
// detections for D: a dead receiver cannot occupy every worker, and the state
// alert is never left behind detections that have lower ids.
func TestClaimStateFirstAndPerTargetCap(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	newTarget(t, s, "d", "webhook", nil)
	ids := detectionsFor(t, s, 10)
	if _, err := s.EvaluateHosts(ctx, t0, []int64{ids[0]}, fixed("CRIT")); err != nil {
		t.Fatal(err)
	}
	plan(t, s, t0)
	got, err := s.ClaimDeliveries(ctx, t0, time.Minute, store.ClaimLimits{Total: 4, Detections: 3, PerTarget: 2})
	if err != nil {
		t.Fatal(err)
	}
	state, det := kinds(got)
	if state != 1 || det["d"] != 2 || len(got) != 3 {
		t.Fatalf("claimed %d (state %d, detections %v), want the state alert and 2 detections", len(got), state, det)
	}
	if got[0].Kind != store.DeliveryStateChange {
		t.Fatalf("the state alert must come first: %s", got[0].Kind)
	}
	// Two are in flight to d: the next claim gets no detection for d.
	more, _ := s.ClaimDeliveries(ctx, t0, time.Minute, store.ClaimLimits{Total: 4, Detections: 3, PerTarget: 2})
	if len(more) != 0 {
		t.Fatalf("%d claimed while the target already has 2 in flight", len(more))
	}
	// When one finishes, one more is allowed.
	for _, c := range got {
		if c.Kind != store.DeliveryStateChange {
			if err := s.FinishAttempt(ctx, c, store.AttemptResult{Status: store.AlertLogSent, Code: "HTTP 204"}, t0); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	more, _ = s.ClaimDeliveries(ctx, t0, time.Minute, store.ClaimLimits{Total: 4, Detections: 3, PerTarget: 2})
	if len(more) != 1 {
		t.Fatalf("%d claimed after one finished, want 1", len(more))
	}
}

// The cap is applied in SQL before the LIMIT: a backlog of 20 deliveries to one
// target does not hide the deliveries of another target behind it.
func TestClaimPerTargetCapDoesNotHideOtherTargets(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	newTarget(t, s, "dead", "webhook", func(n *store.NewAlertTarget) { n.SendStateChanges = false })
	for i := 0; i < 20; i++ {
		h := addHost(t, s, fmt.Sprintf("h%02d", i))
		s.RecordEvent(ctx, store.EventRecord{HostID: h.ID, ReceivedAt: t0, Event: proto.Event{TS: t0, Path: "/p", Signature: "S", Source: "clamd"}})
	}
	plan(t, s, t0) // 20 detections for "dead", ids 1-20
	newTarget(t, s, "healthy", "webhook", func(n *store.NewAlertTarget) { n.SendStateChanges = false })
	// The healthy target only sees events from now on.
	h := addHost(t, s, "late")
	s.RecordEvent(ctx, store.EventRecord{HostID: h.ID, ReceivedAt: t0, Event: proto.Event{TS: t0, Path: "/late", Signature: "S", Source: "clamd"}})
	plan(t, s, t0)
	got, err := s.ClaimDeliveries(ctx, t0, time.Minute, store.ClaimLimits{Total: 4, Detections: 3, PerTarget: 2})
	if err != nil {
		t.Fatal(err)
	}
	_, det := kinds(got)
	if det["dead"] != 2 || det["healthy"] != 1 {
		t.Fatalf("claimed %v: the healthy target's detection was hidden behind the dead target's backlog", det)
	}
}

// Order is per (target, host, recipient, KIND): a pending state delivery that is
// being retried does not hold back a newer detection for the same host, and
// the other way round. Within one kind order is still kept.
func TestClaimOrderIsPerKind(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	newTarget(t, s, "t", "webhook", nil)
	h := addHost(t, s, "a")
	if _, err := s.EvaluateHosts(ctx, t0, []int64{h.ID}, fixed("CRIT")); err != nil {
		t.Fatal(err)
	}
	plan(t, s, t0)
	// The state delivery is claimed and then retried in the future: still pending.
	c, _ := s.ClaimDeliveries(ctx, t0, time.Minute, store.Claim(1))
	if len(c) != 1 {
		t.Fatal(len(c))
	}
	if err := s.FinishAttempt(ctx, c[0], store.AttemptResult{Status: store.AlertLogRetrying, Code: "HTTP 503", RetryAt: t0.Add(time.Hour)}, t0); err != nil {
		t.Fatal(err)
	}
	// A detection for the same host arrives: it is not blocked by the retrying CRIT.
	s.RecordEvent(ctx, store.EventRecord{HostID: h.ID, ReceivedAt: t0, Event: proto.Event{TS: t0, Path: "/p", Signature: "S", Source: "clamd"}})
	plan(t, s, t0)
	got, _ := s.ClaimDeliveries(ctx, t0, time.Minute, store.Claim(4))
	if len(got) != 1 || got[0].Kind != store.DeliveryDetection {
		t.Fatalf("%+v: the detection must not wait for the retrying state alert", got)
	}
	// Two detections of one host keep their order: the second waits for the first.
	s.RecordEvent(ctx, store.EventRecord{HostID: h.ID, ReceivedAt: t0, Event: proto.Event{TS: t0, Path: "/p2", Signature: "S", Source: "clamd"}})
	s.RecordEvent(ctx, store.EventRecord{HostID: h.ID, ReceivedAt: t0, Event: proto.Event{TS: t0, Path: "/p3", Signature: "S", Source: "clamd"}})
	plan(t, s, t0)
	if err := s.FinishAttempt(ctx, got[0], store.AttemptResult{Status: store.AlertLogSent, Code: "HTTP 204"}, t0); err != nil {
		t.Fatal(err)
	}
	next, _ := s.ClaimDeliveries(ctx, t0, time.Minute, store.Claim(4))
	if len(next) != 1 {
		t.Fatalf("%d detections claimed at once for one host: the order within a kind must hold", len(next))
	}
	var p struct {
		Path string `json:"path"`
	}
	json.Unmarshal(next[0].Payload, &p)
	if p.Path != "/p2" {
		t.Fatalf("the older detection must go first, got %s", p.Path)
	}
}
