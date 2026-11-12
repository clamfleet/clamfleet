// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func testRunner(t *testing.T, send func(ctx context.Context, path string, body []byte) ([]byte, error)) (*Runner, chan time.Time, *syncBuf) {
	t.Helper()
	logs := &syncBuf{}
	tick := make(chan time.Time)
	return &Runner{
		Collect: func(context.Context) (proto.Report, []Problem, error) {
			return proto.Report{Schema: 1, Host: "app01", Tags: []string{}}, []Problem{{Source: "freshclam", Err: errors.New("no log")}}, nil
		},
		Send: send,
		Tick: tick,
		Log:  slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}, tick, logs
}

func TestOnce(t *testing.T) {
	var gotPath string
	var gotBody []byte
	r, _, logs := testRunner(t, func(_ context.Context, path string, body []byte) ([]byte, error) {
		gotPath, gotBody = path, body
		return []byte("{}"), nil
	})
	if err := r.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	var rep proto.Report
	if gotPath != "v1/report" || json.Unmarshal(gotBody, &rep) != nil || rep.Host != "app01" {
		t.Fatalf("path %q body %s", gotPath, gotBody)
	}
	if !strings.Contains(logs.String(), "collection problem") {
		t.Fatalf("problems must be logged: %s", logs.String())
	}

	wantErr := &SendError{Class: ClassServer, Status: 503}
	r.Send = func(context.Context, string, []byte) ([]byte, error) { return nil, wantErr }
	if err := r.Once(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("Once = %v, want the send error (so `run --once` exits 1)", err)
	}
	r.Collect = func(context.Context) (proto.Report, []Problem, error) { return proto.Report{}, nil, errors.New("boom") }
	if err := r.Once(context.Background()); err == nil || !strings.Contains(err.Error(), "collect") {
		t.Fatalf("collect failure: %v", err)
	}
}

func TestLoopSendsImmediatelyThenPerTickAndSurvivesFailures(t *testing.T) {
	sent := make(chan error, 10)
	calls := 0
	r, tick, logs := testRunner(t, func(context.Context, string, []byte) ([]byte, error) {
		calls++
		var err error
		if calls == 2 {
			err = &SendError{Class: ClassUnauthorized, Status: 401}
		}
		sent <- err
		return nil, err
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Loop(ctx) }()

	expect := func(label string, wantErr bool) {
		t.Helper()
		select {
		case err := <-sent:
			if (err != nil) != wantErr {
				t.Fatalf("%s: err = %v", label, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: no send", label)
		}
	}
	expect("immediate send (no waiting for the first tick)", false)
	select {
	case <-sent:
		t.Fatal("sent twice without a tick")
	case <-time.After(50 * time.Millisecond):
	}
	tick <- time.Now()
	expect("tick 1 (fails)", true)
	tick <- time.Now()
	expect("tick 2 (the loop survived the failure)", false)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Loop returned %v on cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Loop did not stop on cancel")
	}
	if !strings.Contains(logs.String(), `"class":"unauthorized"`) || !strings.Contains(logs.String(), "report not sent") {
		t.Fatalf("failure not logged with its class:\n%s", logs.String())
	}
}

// Cancelling while a send is in flight must stop the loop, not log a bogus failure.
func TestLoopStopsWhenCancelledDuringSend(t *testing.T) {
	started := make(chan struct{})
	r, _, logs := testRunner(t, func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		close(started)
		<-ctx.Done()
		return nil, &SendError{Class: ClassNetwork, Err: ctx.Err()}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Loop(ctx) }()
	<-started
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Loop did not stop")
	}
	if strings.Contains(logs.String(), "report not sent") {
		t.Fatalf("a shutdown was logged as a failed send:\n%s", logs.String())
	}
}
