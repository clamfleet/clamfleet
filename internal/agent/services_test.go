// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParseSystemctlShowRecorded(t *testing.T) {
	for file, want := range map[string]string{
		"clamd-active":       "active",
		"freshclam-inactive": "inactive",
		"freshclam-failed":   "failed",
		"not-found":          "not-found",
	} {
		got, ok := ParseSystemctlShow(fixture(t, "services/"+file+".show"))
		if !ok || got != want {
			t.Errorf("%s: got %q %v, want %q", file, got, ok, want)
		}
	}
	for _, bad := range []string{"", "garbage", "LoadState=loaded\n"} {
		if _, ok := ParseSystemctlShow([]byte(bad)); ok {
			t.Errorf("%q must not parse", bad)
		}
	}
}

func TestUnitStateCallsSystemctlSafely(t *testing.T) {
	var gotName string
	var gotArgs []string
	c := &Collector{Exec: func(_ context.Context, name string, args ...string) ([]byte, error) {
		gotName, gotArgs = name, args
		return fixture(t, "services/clamd-active.show"), nil
	}}
	st, p := c.unitState(context.Background(), "clamav-daemon")
	if st != "active" || p != nil {
		t.Fatalf("got %q %v", st, p)
	}
	want := "show --property=LoadState,ActiveState -- clamav-daemon"
	if gotName != "systemctl" || strings.Join(gotArgs, " ") != want {
		t.Fatalf("called %s %v, want systemctl %s", gotName, gotArgs, want)
	}
}

func TestUnitStateDegradation(t *testing.T) {
	failing := &Collector{Exec: func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("boom") }}
	if st, p := failing.unitState(context.Background(), "x"); st != "unknown" || p == nil {
		t.Fatalf("exec error: got %q %v", st, p)
	}
	garbage := &Collector{Exec: func(context.Context, string, ...string) ([]byte, error) { return []byte("???"), nil }}
	if st, p := garbage.unitState(context.Background(), "x"); st != "unknown" || p == nil {
		t.Fatalf("garbage: got %q %v", st, p)
	}
	never := &Collector{Exec: func(context.Context, string, ...string) ([]byte, error) {
		t.Error("systemctl must not run for an empty unit name")
		return nil, nil
	}}
	if st, p := never.unitState(context.Background(), ""); st != "not-found" || p != nil {
		t.Fatalf("empty unit: got %q %v", st, p)
	}
}

func TestRealExecCapsOutput(t *testing.T) {
	// 2 MB of output against a 1 MiB cap: must be an error, not an unbounded buffer.
	_, err := RealExec(context.Background(), "head", "-c", "2000000", "/dev/zero")
	if err == nil || !strings.Contains(err.Error(), "output larger than") {
		t.Fatalf("err = %v, want an output-size error", err)
	}
	out, err := RealExec(context.Background(), "printf", "ok")
	if err != nil || string(out) != "ok" {
		t.Fatalf("small output: %q %v", out, err)
	}
}
