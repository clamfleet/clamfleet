// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package server

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
)

type retClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *retClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *retClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// The runner prunes at start and then once per 24 h of the injected clock, by
// ARRIVAL: an event with an old agent ts that arrived recently stays. Closed
// windows go at 90 days. No path reaches the log.
func TestRetentionRunner(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	clk := &retClock{t: fixedNow}
	h, err := st.CreateHost(ctx, "a", []byte("0123456789abcdef0123456789abcdef"), clk.Now(), store.Audit{Kind: store.ActorCLI, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	old := clk.Now().Add(-400 * 24 * time.Hour)
	for i, c := range []struct {
		path string
		ts   time.Time
		recv time.Time
	}{
		{"/srv/MARKER-OLD", old, old},                                  // arrived 400 days ago: pruned
		{"/srv/MARKER-SPOOLED", old, clk.Now().Add(-24 * time.Hour)},   // old ts, arrived yesterday: kept
		{"/srv/MARKER-RECENT", clk.Now(), clk.Now().Add(-time.Minute)}, // kept
	} {
		if _, err := st.RecordEvent(ctx, store.EventRecord{HostID: h.ID, ReceivedAt: c.recv,
			Event: proto.Event{TS: c.ts, Path: c.path, Signature: fmt.Sprintf("s%d", i), Source: "clamd"}}); err != nil {
			t.Fatal(err)
		}
	}
	logs := &strings.Builder{}
	var lmu sync.Mutex
	log := slog.New(slog.NewJSONHandler(writerFunc(func(p []byte) (int, error) { lmu.Lock(); defer lmu.Unlock(); return logs.Write(p) }), nil))
	tick := make(chan time.Time)
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { RunRetention(rctx, st, clk.Now, 365, log, tick); close(done) }()
	defer func() { cancel(); <-done }()

	count := func() int {
		rows, err := st.ListEvents(ctx, store.EventFilter{Ack: store.AckAll})
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	waitFor := func(want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for count() != want {
			if time.Now().After(deadline) {
				t.Fatalf("%d events, want %d", count(), want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor(2) // the first prune ran at start
	// A tick inside 24 h does nothing, even though an event is now past the limit... ...
	clk.Add(time.Hour)
	tick <- clk.Now()
	time.Sleep(50 * time.Millisecond)
	if count() != 2 {
		t.Fatal("pruned again inside 24 h")
	}
	// 366 days after the spooled event arrived: it goes too, at the next daily run.
	clk.Add(366 * 24 * time.Hour)
	tick <- clk.Now()
	waitFor(0)
	lmu.Lock()
	defer lmu.Unlock()
	if strings.Contains(logs.String(), "MARKER") || !strings.Contains(logs.String(), "old events pruned") {
		t.Fatalf("log: %s", logs.String())
	}
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestRetentionConfig(t *testing.T) {
	c := DefaultConfig()
	if c.Retention.EventsDays != 365 {
		t.Fatalf("default %d", c.Retention.EventsDays)
	}
	for _, days := range []int{7, 3650, 365} {
		c.Retention.EventsDays = days
		if err := c.Retention.Validate(); err != nil {
			t.Errorf("%d: %v", days, err)
		}
	}
	for _, days := range []int{0, 6, 3651, -1} {
		c.Retention.EventsDays = days
		if err := c.Retention.Validate(); err == nil {
			t.Errorf("%d accepted", days)
		}
	}
}
