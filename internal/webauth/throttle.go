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

// Outcome says how an attempt that Begin admitted ended.
type Outcome int

const (
	// Failed: the credentials were wrong. The provisional failure stays.
	Failed Outcome = iota
	// Succeeded: the caller is in; every failure of this email is forgotten.
	Succeeded
	// Aborted: no verdict (a server fault). The provisional failure is taken back.
	Aborted
)

// Wait returns how long the caller must wait before an attempt for email would
// be admitted; 0 means go ahead. It only looks: use Begin to take part.
func (t *Throttle) Wait(email string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[key(email)]
	if e == nil {
		return 0
	}
	return max(e.until.Sub(t.now()), 0)
}

// Begin admits or refuses one attempt for email, atomically. A refused attempt
// returns the time to wait and a nil done; it is not a new failure (otherwise
// hammering would extend the lockout for the real user).
//
// An admitted attempt is counted as a FAILURE immediately, before the caller
// hashes anything, and done(outcome) corrects it afterwards. Counting only
// after the verdict would let N parallel requests all pass the check while
// none had failed yet, and every one of them would cost an argon2 hash: the
// backoff would not bound a burst. With the provisional failure, the attempt
// that reaches the threshold sets the delay at once and the next one is
// refused, so at most throttleFreeFailures attempts per window are ever in
// flight or verified. done may be called once; later calls are ignored.
func (t *Throttle) Begin(email string) (wait time.Duration, done func(Outcome)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	k := key(email)
	e := t.m[k]
	if e != nil {
		if w := e.until.Sub(now); w > 0 {
			return w, nil
		}
	} else {
		if len(t.m) >= throttleMaxEntries {
			t.evict(now)
		}
		e = &throttleEntry{}
		t.m[k] = e
	}
	prevFails, prevLast, prevUntil := e.fails, e.last, e.until
	t.fail(e, now)
	myLast, myUntil := e.last, e.until
	var once sync.Once
	return 0, func(o Outcome) {
		once.Do(func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			switch o {
			case Succeeded:
				delete(t.m, k)
			case Aborted:
				// Take the provisional failure back, as if the attempt never happened.
				// Only while the entry is still ours; and only restore the delay and the
				// last-failure time if no later attempt has moved them since, so an
				// aborted attempt can neither lengthen the backoff nor erase another
				// attempt's count.
				cur := t.m[k]
				if cur != e {
					return
				}
				if e.fails > 0 {
					e.fails--
				}
				if e.until.Equal(myUntil) {
					e.until = prevUntil
				}
				if e.last.Equal(myLast) {
					e.last = prevLast
				}
				if e.fails == 0 && prevFails == 0 {
					delete(t.m, k) // an entry nobody has a failure on is no entry
				}
			}
		})
	}
}

// fail records one failure on e and sets the delay that now applies. Caller holds mu.
func (t *Throttle) fail(e *throttleEntry, now time.Time) {
	if now.Sub(e.last) > throttleWindow {
		e.fails = 0 // old failures no longer count
	}
	e.fails++
	e.last = now
	if e.fails < throttleFreeFailures {
		return
	}
	d := throttleBase
	for i := throttleFreeFailures; i < e.fails && d < throttleMax; i++ {
		d *= 2
	}
	e.until = now.Add(min(d, throttleMax))
}

// Fail records a failed attempt without admission control and returns the
// delay that now applies. Begin is what the login path uses; Fail remains for
// callers that only report a verdict.
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
	t.fail(e, now)
	return max(e.until.Sub(now), 0)
}

// Success forgets the failures of email.
func (t *Throttle) Success(email string) {
	t.mu.Lock()
	delete(t.m, key(email))
	t.mu.Unlock()
}

// evict makes room for one new entry by removing the one that matters least.
// Order of preference for the victim:
//  1. an entry that is not throttled right now, before a throttled one;
//  2. among those, the one with the fewest failures still inside the window
//     (an account that is being guessed keeps its count, a one-shot typo or a
//     spray entry goes first), then the one with the oldest activity;
//  3. among throttled entries, the one whose delay ends first.
//
// A spray of distinct emails therefore evicts its own one-failure entries and
// never the backoff, or the near-threshold count, of the account it is guessing.
// Caller holds mu.
func (t *Throttle) evict(now time.Time) {
	type rank struct {
		throttled bool
		fails     int
		when      time.Time
	}
	less := func(a, b rank) bool { // a is a better victim than b
		switch {
		case a.throttled != b.throttled:
			return !a.throttled
		case !a.throttled && a.fails != b.fails:
			return a.fails < b.fails
		}
		return a.when.Before(b.when)
	}
	var victim string
	var best rank
	first := true
	for k, e := range t.m {
		r := rank{throttled: e.until.After(now), when: e.last}
		if r.throttled {
			r.when = e.until
		} else if now.Sub(e.last) <= throttleWindow {
			r.fails = e.fails
		}
		if first || less(r, best) {
			victim, best, first = k, r, false
		}
	}
	delete(t.m, victim)
}
