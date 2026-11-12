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
	t.fail(e, now)
	var once sync.Once
	return 0, func(o Outcome) {
		once.Do(func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			switch o {
			case Succeeded:
				delete(t.m, k)
			case Aborted:
				// Only if the entry is still ours: it may have been evicted or reset.
				if cur := t.m[k]; cur == e && e.fails > 0 {
					e.fails--
					if e.fails < throttleFreeFailures {
						e.until = time.Time{}
					}
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

// evict makes room for one new entry. It removes the entry that matters least:
// an entry that is not currently throttled goes before one that is, and among
// equals the one with the oldest activity (for throttled entries: the one whose
// delay ends first). A spray of distinct emails therefore evicts its own
// one-failure entries, not the backoff of the account it is trying to guess.
// Caller holds mu.
func (t *Throttle) evict(now time.Time) {
	var victim string
	var vThrottled bool
	var vWhen time.Time
	first := true
	for k, e := range t.m {
		throttled := e.until.After(now)
		when := e.last
		if throttled {
			when = e.until
		}
		switch {
		case first,
			vThrottled && !throttled,
			vThrottled == throttled && when.Before(vWhen):
			victim, vThrottled, vWhen, first = k, throttled, when, false
		}
	}
	delete(t.m, victim)
}
