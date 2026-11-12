// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package webauth

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

type cleanupStore struct {
	fakeSessions
	calls chan time.Time
}

func (c *cleanupStore) DeleteExpiredSessions(_ context.Context, now time.Time, idle time.Duration) (int64, error) {
	c.calls <- now
	return 0, nil
}

func TestRunCleanupRunsAtStartAndOnEachTickUntilCancelled(t *testing.T) {
	st := &cleanupStore{calls: make(chan time.Time, 10)}
	tick := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunCleanup(ctx, st, func() time.Time { return clk }, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)), tick)
		close(done)
	}()
	wait := func(what string) {
		select {
		case got := <-st.calls:
			if !got.Equal(clk) {
				t.Fatalf("%s: used %v, want the injected clock %v", what, got, clk)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no cleanup %s", what)
		}
	}
	wait("at start")
	tick <- clk
	wait("after a tick")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunCleanup did not stop on cancel")
	}
}
