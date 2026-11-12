// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package alert

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

func noJitter() float64 { return 0.5 }

// The schedule: attempts 1-4 are followed by 1, 5, 15 and 60 minutes; after
// attempt 5 there is nothing. MaxAttempts is the store's constant.
func TestNextDelaySchedule(t *testing.T) {
	// MaxAttempts is declared as the store's constant, so the crash path and
	// this schedule cannot drift; the literal pins the value the docs promise.
	if got := store.MaxAlertAttempts; got != 5 || len(backoff) != got-1 {
		t.Fatalf("store constant %d, backoff entries %d", got, len(backoff))
	}
	want := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}
	for i, w := range want {
		d, ok := NextDelay(i+1, 0, noJitter)
		if !ok || d != w {
			t.Errorf("after attempt %d: %v %v, want %v", i+1, d, ok, w)
		}
	}
	for _, a := range []int{0, 5, 6} {
		if _, ok := NextDelay(a, 0, noJitter); ok {
			t.Errorf("attempt %d must end the schedule", a)
		}
	}
	var total time.Duration
	for _, w := range want {
		total += w
	}
	if total != 81*time.Minute {
		t.Fatalf("window %v, want the 81 minutes the docs promise", total)
	}
}

func TestNextDelayJitterBounds(t *testing.T) {
	lo, _ := NextDelay(2, 0, func() float64 { return 0 })
	hi, _ := NextDelay(2, 0, func() float64 { return 0.999999 })
	if lo != 4*time.Minute+30*time.Second {
		t.Errorf("low end %v, want 4m30s (-10%%)", lo)
	}
	if hi < 5*time.Minute+29*time.Second || hi > 5*time.Minute+30*time.Second {
		t.Errorf("high end %v, want just under 5m30s (+10%%)", hi)
	}
}

func TestNextDelayRetryAfterRaisesNeverLowers(t *testing.T) {
	if d, _ := NextDelay(1, 2*time.Minute, noJitter); d != 2*time.Minute {
		t.Errorf("Retry-After 2m over a 1m schedule: %v", d)
	}
	if d, _ := NextDelay(2, 30*time.Second, noJitter); d != 5*time.Minute {
		t.Errorf("a short Retry-After must not shorten the schedule: %v", d)
	}
	if d, _ := NextDelay(1, 5*time.Hour, noJitter); d != MaxRetryAfter {
		t.Errorf("Retry-After must be capped at 60m: %v", d)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"120", 2 * time.Minute},
		{" 7 ", 7 * time.Second},
		{"0", 0},
		{"-5", 0},
		{"99999999", MaxRetryAfter},
		{now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second},
		{now.Add(-time.Hour).Format(http.TimeFormat), 0},
		{now.Add(10 * time.Hour).Format(http.TimeFormat), MaxRetryAfter},
		{"soon", 0},
		{"", 0},
		{"1.5", 0},
	}
	for _, c := range cases {
		if got := ParseRetryAfter(c.in, now); got != c.want {
			t.Errorf("%q: %v, want %v", c.in, got, c.want)
		}
	}
}

// The classification table of 4.4 (HTTP part).
func TestClassifyHTTP(t *testing.T) {
	now := time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC)
	want := map[int]Outcome{
		200: OutcomeSent, 201: OutcomeSent, 204: OutcomeSent, 299: OutcomeSent,
		408: OutcomeRetry, 425: OutcomeRetry, 429: OutcomeRetry, 500: OutcomeRetry, 503: OutcomeRetry, 599: OutcomeRetry,
		301: OutcomePermanent, 302: OutcomePermanent, 307: OutcomePermanent, 308: OutcomePermanent,
		400: OutcomePermanent, 401: OutcomePermanent, 403: OutcomePermanent, 404: OutcomePermanent, 410: OutcomePermanent, 422: OutcomePermanent,
		100: OutcomePermanent,
	}
	for status, w := range want {
		if r := ClassifyHTTP(status, "", now); r.Outcome != w || r.Code != fmt.Sprintf("HTTP %d", status) {
			t.Errorf("HTTP %d: %+v, want outcome %v", status, r, w)
		}
	}
	if r := ClassifyHTTP(429, "120", now); r.RetryAfter != 2*time.Minute {
		t.Errorf("429 with Retry-After 120: %+v", r)
	}
	if r := ClassifyHTTP(302, "", now); r.Text == "" || r.Outcome != OutcomePermanent {
		t.Errorf("3xx must say redirects are not followed: %+v", r)
	}
	if (Result{}).Outcome == OutcomeSent {
		t.Fatal("the zero Result must not count as delivered")
	}
}

func TestClassifySMTPReply(t *testing.T) {
	for code, w := range map[int]Outcome{421: OutcomeRetry, 450: OutcomeRetry, 451: OutcomeRetry, 452: OutcomeRetry,
		500: OutcomePermanent, 535: OutcomePermanent, 550: OutcomePermanent, 554: OutcomePermanent} {
		if r := ClassifySMTPReply(code, "RCPT"); r.Outcome != w || r.Code != fmt.Sprintf("SMTP %d", code) {
			t.Errorf("SMTP %d: %+v", code, r)
		}
	}
}

func TestClassifyError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		out  Outcome
		code string
	}{
		{"refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, OutcomeRetry, "connection refused"},
		{"reset", fmt.Errorf("x: %w", syscall.ECONNRESET), OutcomeRetry, "connection reset"},
		{"dns", &net.DNSError{Err: "no such host", Name: "marker.example"}, OutcomeRetry, "dns"},
		{"tls unknown authority", x509.UnknownAuthorityError{}, OutcomeRetry, "tls"},
		{"deadline", fmt.Errorf("wrap: %w", context.DeadlineExceeded), OutcomeRetry, "timeout"},
		{"net timeout", &net.OpError{Op: "read", Err: timeoutErr{}}, OutcomeRetry, "timeout"},
		{"blocked", fmt.Errorf("dial: %w", &PermanentError{Code: "blocked", Msg: "address is loopback"}), OutcomePermanent, "blocked"},
		{"unknown", errors.New("something with https://hooks.example/SECRET-MARKER"), OutcomeRetry, "error"},
	}
	for _, c := range cases {
		r := ClassifyError(c.err)
		if r.Outcome != c.out || r.Code != c.code {
			t.Errorf("%s: %+v", c.name, r)
		}
		if r.Text == "" {
			t.Errorf("%s: no text", c.name)
		}
	}
	// Our text never copies the transport error (it can hold URLs and names).
	for _, e := range []error{errors.New("SECRET-MARKER"), &net.DNSError{Err: "e", Name: "SECRET-MARKER"}} {
		if r := ClassifyError(e); contains(r.Text, "SECRET-MARKER") || contains(r.Code, "SECRET-MARKER") {
			t.Errorf("error text leaked: %+v", r)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func contains(s, sub string) bool { return strings.Contains(s, sub) }
