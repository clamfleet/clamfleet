// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// throttle.go: per-email login backoff.
//
// Rule: after 5 failed logins for one email within 15 minutes, only one
// attempt per 30 s is answered, doubling with every further failure up to
// 15 min; a success resets it. There is no hard lockout (it would let anyone
// lock an admin out) and no IP-based limit (the client IP is "logging only",
// M2 decision 12: it can be wrong behind a proxy, and IP rate limits belong in
// the reverse proxy). State is in memory: a restart forgets it, which is
// acceptable because it only slows guessing and argon2 already costs ~50 ms.
//
// The key is the email as typed (lowercased), whether or not an account
// exists, so the throttle itself is no account-existence oracle.
package webauth

import (
	"strings"
	"sync"
	"time"
)

const (
	throttleFreeFailures = 5
	throttleWindow       = 15 * time.Minute
	throttleBase         = 30 * time.Second
	throttleMax          = 15 * time.Minute
	// throttleMaxEntries bounds memory: the key is attacker-chosen text.
	throttleMaxEntries = 10000
)

type throttleEntry struct {
	fails int
	last  time.Time // time of the latest failure
	until time.Time // no attempt is answered before this
}

// Throttle tracks failed logins per email. The zero value is not usable: use NewThrottle.
type Throttle struct {
	now func() time.Time
	mu  sync.Mutex
	m   map[string]*throttleEntry
}

// NewThrottle returns a Throttle on the given (injected) clock.
func NewThrottle(now func() time.Time) *Throttle {
	return &Throttle{now: now, m: map[string]*throttleEntry{}}
}

func key(email string) string {
	k := strings.ToLower(strings.TrimSpace(email))
	if len(k) > 254 {
		k = k[:254]
	}
	return k
}

// Wait returns how long the caller must wait before an attempt for email is
// answered; 0 means go ahead. An attempt refused because of Wait is not a new
// failure (otherwise hammering would extend the lockout for the real user).
func (t *Throttle) Wait(email string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[key(email)]
	if e == nil {
		return 0
	}
	if w := e.until.Sub(t.now()); w > 0 {
		return w
	}
	return 0
}

// Fail records a failed attempt and returns the delay that now applies.
func (t *Throttle) Fail(email string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	k := key(email)
	e := t.m[k]
	if e == nil {
		if len(t.m) >= throttleMaxEntries {
			t.evict(now)
		}
		e = &throttleEntry{}
		t.m[k] = e
	}
	if now.Sub(e.last) > throttleWindow {
		e.fails = 0 // old failures no longer count
	}
	e.fails++
	e.last = now
	if e.fails < throttleFreeFailures {
		return 0
	}
	d := throttleBase
	for i := throttleFreeFailures; i < e.fails && d < throttleMax; i++ {
		d *= 2
	}
	d = min(d, throttleMax)
	e.until = now.Add(d)
	return d
}

// Success forgets the failures of email.
func (t *Throttle) Success(email string) {
	t.mu.Lock()
	delete(t.m, key(email))
	t.mu.Unlock()
}

// evict makes room: first drop entries that no longer matter, then, if the
// table is still full of live entries, one arbitrary entry. Caller holds mu.
func (t *Throttle) evict(now time.Time) {
	for k, e := range t.m {
		if now.Sub(e.last) > throttleWindow && !now.Before(e.until) {
			delete(t.m, k)
		}
	}
	if len(t.m) >= throttleMaxEntries {
		for k := range t.m {
			delete(t.m, k)
			break
		}
	}
}
