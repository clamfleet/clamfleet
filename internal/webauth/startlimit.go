// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// startlimit.go: a per-client-IP bound on OIDC sign-ins in progress.
//
// Starting an OIDC sign-in needs no session, and each start stores a row (store.MaxOIDCStates caps
// the table). Without a per-source bound one host could fill that table and switch SSO off for
// everybody for ten minutes. So each client IP may have only a few sign-ins in progress; a person
// signing in needs one for under ten minutes, so the limit never meets a real user, even several
// behind one NAT.
//
// The IP is the one api.ClientIP reports (X-Forwarded-For only from trusted_proxies). That is
// "logging only" elsewhere (M2 decision 10), because it can be wrong; here a wrong value costs only
// this bound, and the table cap in the store remains the last line. State is in memory (a restart
// forgets it, as for Throttle), which is fine for a bound on a ten-minute row.
package webauth

import (
	"sync"
	"time"
)

// StartLimiter counts live starts per client IP.
type StartLimiter struct {
	now    func() time.Time
	perIP  int
	maxIPs int
	ttl    time.Duration
	mu     sync.Mutex
	m      map[string][]time.Time // ip -> expiry of each live start
}

// NewStartLimiter allows perIP live starts per address, each living ttl. now is the injected clock.
func NewStartLimiter(now func() time.Time, perIP int, ttl time.Duration) *StartLimiter {
	return &StartLimiter{now: now, perIP: perIP, ttl: ttl, maxIPs: 10000, m: map[string][]time.Time{}}
}

// Allow records one start for ip and returns true, or returns false (recording nothing) when ip
// already has perIP live starts.
func (l *StartLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	live := l.m[ip][:0:0]
	for _, exp := range l.m[ip] {
		if exp.After(now) {
			live = append(live, exp)
		}
	}
	if len(live) >= l.perIP {
		l.m[ip] = live
		return false
	}
	if _, known := l.m[ip]; !known && len(l.m) >= l.maxIPs {
		// Memory bound: drop addresses with nothing live, then refuse if it is still full.
		for k, v := range l.m {
			if len(v) == 0 || !v[len(v)-1].After(now) {
				delete(l.m, k)
			}
		}
		if len(l.m) >= l.maxIPs {
			return false
		}
	}
	l.m[ip] = append(live, now.Add(l.ttl))
	return true
}
