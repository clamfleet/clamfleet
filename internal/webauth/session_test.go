// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package webauth

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/agentauth"
)

func TestTokenFormat(t *testing.T) {
	tok, hash, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "cfs_") || len(tok) != 47 || ParseToken(tok) != nil {
		t.Fatalf("token %q", tok)
	}
	if len(hash) != 32 || string(hash) != string(HashToken(tok)) || strings.Contains(string(hash), tok[4:]) {
		t.Fatal("hash is not SHA-256 of the token")
	}
	// An agent token is not a session token, and the other way round.
	agentTok, _, _ := agentauth.Generate()
	if ParseToken(agentTok) == nil {
		t.Fatal("an agent token (cfa_) was accepted as a session token")
	}
	if agentauth.Parse(tok) == nil {
		t.Fatal("a session token (cfs_) was accepted as an agent token")
	}
	for _, bad := range []string{"", "cfs_", tok + "x", tok[:46], "cfs_" + strings.Repeat("!", 43), "xxx_" + tok[4:]} {
		if ParseToken(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCookieFlags(t *testing.T) {
	c := NewCookie("cfs_x", true)
	if c.Name != "__Host-clamfleet_session" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode ||
		c.Path != "/" || c.Domain != "" || c.MaxAge != 0 || !c.Expires.IsZero() {
		t.Fatalf("%+v", c)
	}
	h := c.String()
	for _, want := range []string{"HttpOnly", "Secure", "SameSite=Lax", "Path=/"} {
		if !strings.Contains(h, want) {
			t.Errorf("Set-Cookie %q lacks %s", h, want)
		}
	}
	d := NewCookie("cfs_x", false)
	if d.Name != "clamfleet_session" || d.Secure || !d.HttpOnly || d.SameSite != http.SameSiteLaxMode {
		t.Fatalf("development cookie: %+v", d)
	}
	if cl := ClearCookie(true); cl.MaxAge >= 0 || cl.Value != "" {
		t.Fatalf("clear cookie: %+v", cl)
	}
}

func TestSanitizeNext(t *testing.T) {
	cases := map[string]string{
		"/hosts/web01":             "/hosts/web01",
		"/fleet/rows?tag=a&b=c":    "/fleet/rows?tag=a&b=c",
		"":                         "/",
		"//evil.example":           "/",
		"/\\evil.example":          "/",
		"https://evil.example":     "/",
		"javascript:alert(1)":      "/",
		"evil":                     "/",
		"/ok\r\nSet-Cookie: x":     "/",
		"/a\\b":                    "/",
		"/login":                   "/",
		"/login?next=/x":           "/",
		"/logout":                  "/",
		"/%2f%2fevil":              "/%2f%2fevil", // still a local path: the browser does not decode it into //
		strings.Repeat("/a", 2000): "/",
	}
	for in, want := range cases {
		if got := SanitizeNext(in); got != want {
			t.Errorf("SanitizeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCSRFTokenMaskingAndMatching(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	p := Principal{csrf: secret}
	a, b := p.CSRFToken(), p.CSRFToken()
	if a == b {
		t.Fatal("two renderings of the token are identical: no masking")
	}
	if !tokenMatches(secret, a) || !tokenMatches(secret, b) {
		t.Fatal("a freshly masked token does not match")
	}
	other := Principal{csrf: []byte("fedcba9876543210fedcba9876543210")}
	for name, tok := range map[string]string{
		"empty": "", "garbage": "!!!", "other session": other.CSRFToken(),
		"truncated": a[:len(a)-4], "too long": a + a, "raw secret": string(secret),
	} {
		if tokenMatches(secret, tok) {
			t.Errorf("%s accepted", name)
		}
	}
	if tokenMatches(nil, a) {
		t.Fatal("matched against an empty secret")
	}
}

func TestThrottle(t *testing.T) {
	now := time.Date(2031, 1, 1, 12, 0, 0, 0, time.UTC)
	th := NewThrottle(func() time.Time { return now })
	for i := 1; i <= 4; i++ {
		if d := th.Fail("Ann@Example.com"); d != 0 {
			t.Fatalf("failure %d already delays by %v", i, d)
		}
		if w := th.Wait("ann@example.com"); w != 0 {
			t.Fatalf("wait after %d failures: %v", i, w)
		}
	}
	if d := th.Fail("ann@example.com"); d != 30*time.Second {
		t.Fatalf("5th failure delay %v, want 30s", d)
	}
	if w := th.Wait("ANN@example.com"); w != 30*time.Second {
		t.Fatalf("wait %v", w)
	}
	// Other emails are unaffected; unknown emails are throttled like known ones.
	if w := th.Wait("bob@example.com"); w != 0 {
		t.Fatalf("another email is throttled: %v", w)
	}
	now = now.Add(31 * time.Second)
	if w := th.Wait("ann@example.com"); w != 0 {
		t.Fatalf("still waiting after the delay: %v", w)
	}
	// Doubling: 60 s, 120 s, ... capped at 15 min.
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	for i, w := range want {
		d := th.Fail("ann@example.com")
		if d != w {
			t.Fatalf("failure %d: delay %v, want %v", i+6, d, w)
		}
		now = now.Add(d)
	}
	// A success resets everything.
	th.Success("ann@example.com")
	if d := th.Fail("ann@example.com"); d != 0 {
		t.Fatalf("after success a single failure delays by %v", d)
	}
}

func TestThrottleWindowForgetsOldFailures(t *testing.T) {
	now := time.Date(2031, 1, 1, 12, 0, 0, 0, time.UTC)
	th := NewThrottle(func() time.Time { return now })
	for i := 0; i < 4; i++ {
		th.Fail("a@example.com")
	}
	now = now.Add(16 * time.Minute) // outside the 15 min window
	if d := th.Fail("a@example.com"); d != 0 {
		t.Fatalf("4 old failures + 1 new one delayed by %v; the window should have reset", d)
	}
}

func TestThrottleMemoryIsBounded(t *testing.T) {
	now := time.Date(2031, 1, 1, 12, 0, 0, 0, time.UTC)
	th := NewThrottle(func() time.Time { return now })
	for i := 0; i < throttleMaxEntries+500; i++ {
		th.Fail(strings.Repeat("x", 10) + string(rune('a'+i%26)) + time.Duration(i).String())
	}
	if len(th.m) > throttleMaxEntries {
		t.Fatalf("%d entries, cap %d", len(th.m), throttleMaxEntries)
	}
}

func TestThrottleBeginCountsBeforeTheVerdict(t *testing.T) {
	now := time.Date(2031, 1, 1, 12, 0, 0, 0, time.UTC)
	th := NewThrottle(func() time.Time { return now })
	var dones []func(Outcome)
	for i := 0; i < throttleFreeFailures; i++ {
		w, done := th.Begin("a@example.com")
		if w != 0 || done == nil {
			t.Fatalf("attempt %d refused (%v) although fewer than %d are in flight", i+1, w, throttleFreeFailures)
		}
		dones = append(dones, done)
	}
	// Nothing has finished yet, and the next one is already refused.
	if w, done := th.Begin("a@example.com"); w != 30*time.Second || done != nil {
		t.Fatalf("6th concurrent attempt: wait %v, done set: %v", w, done != nil)
	}
	// A success of one of them forgets everything.
	dones[0](Succeeded)
	if w, done := th.Begin("a@example.com"); w != 0 || done == nil {
		t.Fatalf("after a success: %v", w)
	}
	dones[1](Failed) // ignored: the entry was reset, and each done is a once-only call
}

func TestThrottleAbortTakesTheProvisionalFailureBack(t *testing.T) {
	now := time.Date(2031, 1, 1, 12, 0, 0, 0, time.UTC)
	th := NewThrottle(func() time.Time { return now })
	for i := 0; i < 20; i++ { // server faults, never a verdict: must not lock the account
		w, done := th.Begin("a@example.com")
		if w != 0 {
			t.Fatalf("attempt %d refused after only aborted attempts", i+1)
		}
		done(Aborted)
		done(Aborted) // once only: the second call must not subtract again
	}
	if e, ok := th.m["a@example.com"]; ok {
		t.Fatalf("aborted attempts left an entry: %+v", e)
	}
}

// A spray of distinct emails must not flush the backoff of the account it targets.
func TestThrottleSprayCannotFlushATargetsBackoff(t *testing.T) {
	now := time.Date(2031, 1, 1, 12, 0, 0, 0, time.UTC)
	th := NewThrottle(func() time.Time { return now })
	for i := 0; i < throttleFreeFailures; i++ {
		th.Fail("target@example.com")
	}
	if th.Wait("target@example.com") == 0 {
		t.Fatal("setup: target not throttled")
	}
	for i := 0; i < throttleMaxEntries*2; i++ {
		now = now.Add(time.Millisecond)
		_, done := th.Begin(strings.Repeat("s", 5) + time.Duration(i).String() + "@spray.example")
		done(Failed)
	}
	if len(th.m) > throttleMaxEntries {
		t.Fatalf("%d entries, cap %d", len(th.m), throttleMaxEntries)
	}
	if w := th.Wait("target@example.com"); w == 0 {
		t.Fatal("a spray of other emails flushed the target's backoff")
	}
}

// A target that has been guessed 4 times must survive a spray of one-failure entries.
func TestThrottleEvictionKeepsNearThresholdCountsAndExpiredDelays(t *testing.T) {
	now := time.Date(2031, 1, 1, 12, 0, 0, 0, time.UTC)
	th := NewThrottle(func() time.Time { return now })
	for i := 0; i < 4; i++ {
		th.Fail("near@example.com")
	}
	for i := 0; i < throttleFreeFailures; i++ {
		th.Fail("expired@example.com")
	}
	now = now.Add(31 * time.Second) // the delay of "expired" has just run out; its count must remain
	for i := 0; i < throttleMaxEntries*2; i++ {
		now = now.Add(time.Millisecond)
		_, done := th.Begin("spray" + time.Duration(i).String() + "@spray.example")
		done(Failed)
	}
	if f := th.m["near@example.com"]; f == nil || f.fails != 4 {
		t.Fatalf("the near-threshold target lost its count: %+v", f)
	}
	if f := th.m["expired@example.com"]; f == nil || f.fails != throttleFreeFailures {
		t.Fatalf("the target whose delay just expired lost its count: %+v", f)
	}
	// One more failure on "expired" goes straight to the doubled delay.
	if d := th.Fail("expired@example.com"); d != time.Minute {
		t.Fatalf("delay %v, want 1m (count kept)", d)
	}
}

// An aborted attempt leaves the backoff as it was: not longer, not shorter.
func TestThrottleAbortRestoresTheBackoff(t *testing.T) {
	now := time.Date(2031, 1, 1, 12, 0, 0, 0, time.UTC)
	th := NewThrottle(func() time.Time { return now })
	for i := 0; i < 4; i++ {
		th.Fail("a@example.com")
	}
	last := th.m["a@example.com"].last
	now = now.Add(5 * time.Second)
	_, done := th.Begin("a@example.com") // the 5th: sets a 30 s delay provisionally
	if th.Wait("a@example.com") == 0 {
		t.Fatal("setup: no provisional delay")
	}
	done(Aborted)
	e := th.m["a@example.com"]
	if e.fails != 4 || !e.until.IsZero() || !e.last.Equal(last) {
		t.Fatalf("after Aborted: fails=%d until=%v last=%v (want 4, zero, %v)", e.fails, e.until, e.last, last)
	}
	// An already throttled entry keeps its delay across an aborted attempt that was admitted after expiry.
	th.Fail("b@example.com")
	for i := 0; i < 4; i++ {
		th.Fail("b@example.com")
	}
	until := th.m["b@example.com"].until
	now = until.Add(time.Second)
	_, d2 := th.Begin("b@example.com") // 6th failure: provisional 60 s
	d2(Aborted)
	if got := th.m["b@example.com"]; got.fails != 5 || !got.until.Equal(until) {
		t.Fatalf("aborted attempt changed the delay: fails=%d until=%v want %v", got.fails, got.until, until)
	}
	// A brand new entry that is aborted leaves no entry behind.
	_, d3 := th.Begin("c@example.com")
	d3(Aborted)
	if _, ok := th.m["c@example.com"]; ok {
		t.Fatal("an aborted first attempt left an entry")
	}
}
