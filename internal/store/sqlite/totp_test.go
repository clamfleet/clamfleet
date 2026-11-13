// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

// enrolled makes a user with TOTP enabled (a stand-in sealed blob: the store
// never decrypts) and 10 recovery codes "rc0".."rc9" (hash("rc0") ...).
func enrolled(t *testing.T, s *Store, email string) store.User {
	t.Helper()
	u := mkUser(t, s, email, "viewer")
	var codes [][]byte
	for i := 0; i < 10; i++ {
		codes = append(codes, hash(fmt.Sprintf("rc%d", i)))
	}
	if err := s.EnableTOTP(context.Background(), store.EnableTOTP{
		UserID: u.ID, ExpectedVersion: u.AuthVersion, Sealed: []byte("sealed-1"), Step: 100, RecoveryHashes: codes,
	}, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	u, _ = s.UserByEmail(context.Background(), email)
	return u
}

// challenge opens a login challenge for u as the password step would.
func challenge(t *testing.T, s *Store, u store.User, tok string, at time.Time) []byte {
	t.Helper()
	cur, err := s.UserByEmail(context.Background(), u.Email)
	if err != nil {
		t.Fatal(err)
	}
	h := hash(tok)
	err = s.CreateLoginChallenge(context.Background(), store.LoginChallenge{
		TokenHash: h, UserID: u.ID, AuthVersion: cur.AuthVersion, PasswordHash: cur.PasswordHash, Next: "/",
		CreatedAt: at, ExpiresAt: at.Add(5 * time.Minute),
	}, at)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func complete(ch []byte, step *int64, rec []byte) store.CompleteLogin {
	return store.CompleteLogin{
		ChallengeHash: ch, Step: step, RecoveryHash: rec, Limit: store.SecondFactorLockLimit,
		Session: store.Session{TokenHash: hash("sess-" + string(ch)), CSRF: []byte("c"), ExpiresAt: t0.Add(time.Hour)},
	}
}

func step(n int64) *int64 { return &n }

// Invariant (enforced in Go, not by a CHECK): the sealed secret and the
// enrolment time are both set or both NULL.
func assertSecretInvariant(t *testing.T, s *Store, where string) {
	t.Helper()
	if n := count(t, s, `SELECT count(*) FROM users WHERE (totp_secret IS NULL) <> (totp_enabled_at IS NULL)`); n != 0 {
		t.Fatalf("%s: %d users with totp_secret and totp_enabled_at out of step", where, n)
	}
}

func TestEnableReplaceDisableLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer")
	keep := mkSession(t, s, u.ID, "keep", t0, time.Hour)
	other := mkSession(t, s, u.ID, "other", t0, time.Hour)
	var sid int64
	if err := s.r.QueryRow(`SELECT id FROM user_sessions WHERE token_hash=?`, keep).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPendingTOTP(ctx, sid, []byte("pending"), t0); err != nil {
		t.Fatal(err)
	}
	challenge := func() { // a login in flight must die with the change
		_ = s.CreateLoginChallenge(ctx, store.LoginChallenge{TokenHash: hash("ch"), UserID: u.ID, AuthVersion: u.AuthVersion, PasswordHash: u.PasswordHash, Next: "/", CreatedAt: t0, ExpiresAt: t0.Add(time.Minute)}, t0)
	}
	challenge()
	if n := count(t, s, `SELECT count(*) FROM user_login_challenges`); n != 1 {
		t.Fatalf("setup: %d challenges", n)
	}
	assertSecretInvariant(t, s, "before")

	err := s.EnableTOTP(ctx, store.EnableTOTP{
		UserID: u.ID, ExpectedVersion: u.AuthVersion, Sealed: []byte("sealed-1"), Step: 42,
		RecoveryHashes: [][]byte{hash("a"), hash("b")}, SessionID: sid, KeepSession: keep,
	}, t0, cliAudit)
	if err != nil {
		t.Fatal(err)
	}
	assertSecretInvariant(t, s, "after enable")
	st, _ := s.UserTOTP(ctx, u.ID)
	if !st.Enabled || string(st.Sealed) != "sealed-1" || st.LastStep == nil || *st.LastStep != 42 || st.Failures != 0 || st.AuthVersion != u.AuthVersion+1 {
		t.Fatalf("state after enable: %+v", st)
	}
	if left, _ := s.RecoveryCodesLeft(ctx, u.ID); left != 2 {
		t.Fatalf("%d recovery codes", left)
	}
	if _, _, err := s.PendingTOTP(ctx, sid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the pending secret must be cleared: %v", err)
	}
	if _, err := s.SessionByTokenHash(ctx, keep, t0, time.Hour); err != nil {
		t.Fatalf("the enrolling session must survive: %v", err)
	}
	if _, err := s.SessionByTokenHash(ctx, other, t0, time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another session of the user must end: %v", err)
	}
	if n := count(t, s, `SELECT count(*) FROM user_login_challenges`); n != 0 {
		t.Fatalf("%d challenges survived the enrolment", n)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action='user.totp.enable' AND target='a@example.com'`); n != 1 {
		t.Fatalf("%d user.totp.enable rows", n)
	}
	sp, _ := s.SessionByTokenHash(ctx, keep, t0, time.Hour)
	if !sp.TOTPEnabled || sp.AuthSource != "local" {
		t.Fatalf("principal: %+v", sp)
	}

	// Replace: the audit action says so; the old codes are gone.
	if err := s.EnableTOTP(ctx, store.EnableTOTP{UserID: u.ID, ExpectedVersion: st.AuthVersion, Sealed: []byte("sealed-2"), Step: 50,
		RecoveryHashes: [][]byte{hash("c")}, SessionID: sid, KeepSession: keep}, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action='user.totp.replace'`); n != 1 {
		t.Fatalf("%d user.totp.replace rows", n)
	}
	if left, _ := s.RecoveryCodesLeft(ctx, u.ID); left != 1 {
		t.Fatalf("replace must drop the old codes: %d left", left)
	}

	// Disable: everything is cleared and the version bumps again.
	mkSession(t, s, u.ID, "later", t0, time.Hour)
	before, _ := s.UserTOTP(ctx, u.ID)
	if err := s.DisableTOTP(ctx, u.ID, nil, store.ActionTOTPReset, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	assertSecretInvariant(t, s, "after disable")
	st, _ = s.UserTOTP(ctx, u.ID)
	if st.Enabled || st.Sealed != nil || st.LastStep != nil || st.AuthVersion != before.AuthVersion+1 {
		t.Fatalf("state after disable: %+v", st)
	}
	if left, _ := s.RecoveryCodesLeft(ctx, u.ID); left != 0 {
		t.Fatalf("%d codes survived the disable", left)
	}
	if n := count(t, s, `SELECT count(*) FROM user_sessions WHERE user_id=?`, u.ID); n != 0 {
		t.Fatalf("%d sessions survived a reset", n)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action='user.totp.reset'`); n != 1 {
		t.Fatalf("%d user.totp.reset rows", n)
	}
	if err := s.DisableTOTP(ctx, 9999, nil, store.ActionTOTPReset, t0, cliAudit); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestEnableTOTPRefusesAStaleVersion(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer")
	if err := s.SetPassword(ctx, u.ID, store.PasswordChange{Hash: "reset"}, t0, cliAudit); err != nil { // bumps
		t.Fatal(err)
	}
	err := s.EnableTOTP(ctx, store.EnableTOTP{UserID: u.ID, ExpectedVersion: u.AuthVersion, Sealed: []byte("x"), Step: 1}, t0, cliAudit)
	if !errors.Is(err, store.ErrCredentialChanged) {
		t.Fatalf("%v, want ErrCredentialChanged", err)
	}
	assertSecretInvariant(t, s, "after refused enable")
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action LIKE 'user.totp.%'`); n != 0 {
		t.Fatalf("%d audit rows for a refused change", n)
	}
}

func TestChallengeCreationIsConditionalAndBounded(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := enrolled(t, s, "a@example.com")
	mk := func(tok string, hashv string, ver int64, at time.Time) error {
		return s.CreateLoginChallenge(ctx, store.LoginChallenge{TokenHash: hash(tok), UserID: u.ID, AuthVersion: ver, PasswordHash: hashv, Next: "/x", CreatedAt: at, ExpiresAt: at.Add(5 * time.Minute)}, at)
	}
	if err := mk("stale-hash", "$argon2id$other", u.AuthVersion, t0); !errors.Is(err, store.ErrCredentialChanged) {
		t.Fatalf("stale hash: %v", err)
	}
	if err := mk("stale-version", u.PasswordHash, u.AuthVersion-1, t0); !errors.Is(err, store.ErrCredentialChanged) {
		t.Fatalf("stale version: %v", err)
	}
	// At most 5 open per user: the oldest go.
	for i := 0; i < 7; i++ {
		if err := mk(fmt.Sprintf("c%d", i), u.PasswordHash, u.AuthVersion, t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(t, s, `SELECT count(*) FROM user_login_challenges`); n != 5 {
		t.Fatalf("%d open challenges, want 5", n)
	}
	for _, gone := range []string{"c0", "c1"} {
		if _, err := s.LoginChallenge(ctx, hash(gone), t0.Add(10*time.Second)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s should have been pruned: %v", gone, err)
		}
	}
	got, err := s.LoginChallenge(ctx, hash("c6"), t0.Add(10*time.Second))
	if err != nil || got.UserID != u.ID || got.Next != "/x" || got.AuthVersion != u.AuthVersion {
		t.Fatalf("%+v %v", got, err)
	}
	// Expiry is judged by the store: expires_at <= now is gone.
	if _, err := s.LoginChallenge(ctx, hash("c6"), t0.Add(6*time.Second+5*time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an expired challenge was returned: %v", err)
	}
	// A new challenge drops the user's expired ones.
	if err := mk("late", u.PasswordHash, u.AuthVersion, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM user_login_challenges`); n != 1 {
		t.Fatalf("%d challenges after the expired ones were pruned", n)
	}
	// And the explicit sweep.
	if n, err := s.DeleteExpiredChallenges(ctx, t0.Add(2*time.Hour)); err != nil || n != 1 {
		t.Fatalf("DeleteExpiredChallenges: %d %v", n, err)
	}
}

func TestCompleteLoginSuccess(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := enrolled(t, s, "a@example.com")
	if _, err := s.RecordSecondFactorFailure(ctx, u.ID, 100, t0, cliAudit, map[string]string{"reason": "bad code"}); err != nil {
		t.Fatal(err)
	}
	ch := challenge(t, s, u, "ch", t0)
	now := t0.Add(time.Minute)
	c := complete(ch, step(101), nil)
	if err := s.CompleteLogin(ctx, c, now, map[string]string{"ip": "1.2.3.4", "mfa": "totp"}); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM user_login_challenges`); n != 0 {
		t.Fatal("the challenge was not consumed")
	}
	sp, err := s.SessionByTokenHash(ctx, c.Session.TokenHash, now, time.Hour)
	if err != nil || sp.UserID != u.ID {
		t.Fatalf("session: %+v %v", sp, err)
	}
	st, _ := s.UserTOTP(ctx, u.ID)
	if st.Failures != 0 || *st.LastStep != 101 {
		t.Fatalf("failures %d, last step %v", st.Failures, st.LastStep)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action='user.login' AND actor='a@example.com' AND actor_kind='user' AND detail LIKE '%"mfa":"totp"%'`); n != 1 {
		t.Fatalf("%d user.login rows", n)
	}
	if got, _ := s.UserByEmail(ctx, "a@example.com"); got.LastLoginAt == nil || !got.LastLoginAt.Equal(now) {
		t.Fatalf("last_login_at %v", got.LastLoginAt)
	}
	// The challenge is single use.
	if err := s.CompleteLogin(ctx, complete(ch, step(102), nil), now, nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second completion: %v", err)
	}
}

// A refused attempt rolls everything back: the challenge stays usable, no
// session, no counter change, no audit row.
func TestCompleteLoginRefusalsRollBack(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := enrolled(t, s, "a@example.com") // last step 100
	ch := challenge(t, s, u, "ch", t0)
	assertUntouched := func(what string) {
		t.Helper()
		if n := count(t, s, `SELECT count(*) FROM user_login_challenges`); n != 1 {
			t.Fatalf("%s: the challenge was lost (%d)", what, n)
		}
		if n := count(t, s, `SELECT count(*) FROM user_sessions`); n != 0 {
			t.Fatalf("%s: %d sessions", what, n)
		}
		if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action='user.login'`); n != 0 {
			t.Fatalf("%s: a login was audited", what)
		}
	}
	for _, st := range []int64{100, 99} { // equal and older than the last accepted step
		if err := s.CompleteLogin(ctx, complete(ch, step(st), nil), t0, nil); !errors.Is(err, store.ErrReplay) {
			t.Fatalf("step %d: %v, want ErrReplay", st, err)
		}
		assertUntouched(fmt.Sprintf("replay of %d", st))
	}
	if err := s.CompleteLogin(ctx, complete(ch, nil, hash("not-a-code")), t0, nil); !errors.Is(err, store.ErrBadRecovery) {
		t.Fatalf("unknown recovery code: %v", err)
	}
	assertUntouched("bad recovery code")
	if err := s.CompleteLogin(ctx, complete(ch, step(200), nil), t0.Add(5*time.Minute), nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired challenge: %v", err)
	}
}

func TestRecoveryCodeIsOneTime(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := enrolled(t, s, "a@example.com")
	ch1, ch2 := challenge(t, s, u, "ch1", t0), challenge(t, s, u, "ch2", t0)
	if err := s.CompleteLogin(ctx, complete(ch1, nil, hash("rc3")), t0, map[string]string{"mfa": "recovery_code"}); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.RecoveryCodesLeft(ctx, u.ID); left != 9 {
		t.Fatalf("%d left, want 9", left)
	}
	if err := s.CompleteLogin(ctx, complete(ch2, nil, hash("rc3")), t0, nil); !errors.Is(err, store.ErrBadRecovery) {
		t.Fatalf("a used recovery code worked again: %v", err)
	}
}

// 20 parallel logins race for one recovery code, each on its own challenge:
// exactly one wins (used_at IS NULL as a compare-and-swap).
func TestParallelRecoveryCodeOneWins(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := enrolled(t, s, "a@example.com")
	const n = 20
	chs := make([][]byte, 0, n)
	for i := 0; i < 5; i++ { // the store keeps 5 open challenges per user
		chs = append(chs, challenge(t, s, u, fmt.Sprintf("p%d", i), t0))
	}
	var won, bad atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(ch []byte) {
			defer wg.Done()
			c := complete(ch, nil, hash("rc5"))
			c.Session.TokenHash = hash(fmt.Sprintf("s%p", &c))
			switch err := s.CompleteLogin(ctx, c, t0, nil); {
			case err == nil:
				won.Add(1)
			case errors.Is(err, store.ErrBadRecovery), errors.Is(err, store.ErrNotFound):
				bad.Add(1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}(chs[i%len(chs)])
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("%d logins won one recovery code", won.Load())
	}
	if n := count(t, s, `SELECT count(*) FROM user_sessions`); n != 1 {
		t.Fatalf("%d sessions", n)
	}
}

// Parallel completions of ONE challenge with the right code: one session.
func TestParallelCompletionOfOneChallengeYieldsOneSession(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := enrolled(t, s, "a@example.com")
	ch := challenge(t, s, u, "one", t0)
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := complete(ch, step(int64(200+i)), nil)
			c.Session.TokenHash = hash(fmt.Sprintf("sess%d", i))
			if err := s.CompleteLogin(ctx, c, t0, nil); err == nil {
				won.Add(1)
			} else if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("unexpected: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if won.Load() != 1 || count(t, s, `SELECT count(*) FROM user_sessions`) != 1 {
		t.Fatalf("%d completions won, %d sessions", won.Load(), count(t, s, `SELECT count(*) FROM user_sessions`))
	}
}

// Rule: a challenge belongs to the account state the password step saw.
func TestChallengeDiesWithAnyCredentialChange(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(s *Store, u store.User) error{
		"password reset": func(s *Store, u store.User) error {
			return s.SetPassword(ctx, u.ID, store.PasswordChange{Hash: "new"}, t0, cliAudit)
		},
		"disable": func(s *Store, u store.User) error { return s.SetDisabled(ctx, u.ID, true, t0, cliAudit) },
		"disable and enable": func(s *Store, u store.User) error {
			if err := s.SetDisabled(ctx, u.ID, true, t0, cliAudit); err != nil {
				return err
			}
			return s.SetDisabled(ctx, u.ID, false, t0, cliAudit)
		},
		"new authenticator": func(s *Store, u store.User) error {
			return s.EnableTOTP(ctx, store.EnableTOTP{UserID: u.ID, ExpectedVersion: u.AuthVersion, Sealed: []byte("n"), Step: 5}, t0, cliAudit)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := openTemp(t)
			u := enrolled(t, s, "a@example.com")
			ch := challenge(t, s, u, "ch", t0)
			if err := change(s, u); err != nil {
				t.Fatal(err)
			}
			// Challenges are deleted by some of these; the others must be refused by the version.
			err := s.CompleteLogin(ctx, complete(ch, step(500), nil), t0, nil)
			if !errors.Is(err, store.ErrCredentialChanged) && !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("%v: a challenge outlived the change", err)
			}
			if n := count(t, s, `SELECT count(*) FROM user_sessions`); n != 0 {
				t.Fatalf("%d sessions", n)
			}
		})
	}
	// A reset (DisableTOTP) removes the challenges outright.
	s := openTemp(t)
	u := enrolled(t, s, "a@example.com")
	ch := challenge(t, s, u, "ch", t0)
	if err := s.DisableTOTP(ctx, u.ID, nil, store.ActionTOTPReset, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteLogin(ctx, complete(ch, step(500), nil), t0, nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after reset-totp: %v", err)
	}
}

// The version check inside CompleteLogin is what catches a change that leaves the
// challenge row alone (disable then enable): proven with a challenge that survives.
func TestCompleteLoginChecksTheVersionItself(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := enrolled(t, s, "a@example.com")
	ch := challenge(t, s, u, "ch", t0)
	if err := s.SetDisabled(ctx, u.ID, true, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisabled(ctx, u.ID, false, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM user_login_challenges`); n != 1 {
		t.Fatalf("setup: the challenge must survive disable+enable, %d left", n)
	}
	if err := s.CompleteLogin(ctx, complete(ch, step(500), nil), t0, nil); !errors.Is(err, store.ErrCredentialChanged) {
		t.Fatalf("%v, want ErrCredentialChanged", err)
	}
}

func TestSecondFactorLock(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := enrolled(t, s, "a@example.com")
	const limit = 3
	for i := 1; i <= limit; i++ {
		n, err := s.RecordSecondFactorFailure(ctx, u.ID, limit, t0, store.Audit{Kind: store.ActorUser, Actor: "a@example.com"}, map[string]string{"reason": "bad code", "ip": "1.1.1.1"})
		if err != nil || n != i {
			t.Fatalf("failure %d: count %d, %v", i, n, err)
		}
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action='user.login.failed' AND detail LIKE '%bad code%'`); n != limit {
		t.Fatalf("%d failure rows", n)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action='user.totp.locked'`); n != 1 {
		t.Fatalf("%d lock rows, want exactly 1 (written when the limit is reached)", n)
	}
	ch := challenge(t, s, u, "ch", t0)
	c := complete(ch, step(900), nil)
	c.Limit = limit
	if err := s.CompleteLogin(ctx, c, t0, nil); !errors.Is(err, store.ErrSecondFactorLocked) {
		t.Fatalf("a locked user with a correct code: %v", err)
	}
	// The lock survives a restart (it is a column) and the admin password reset lifts it.
	if got, _ := s.UserByEmail(ctx, "a@example.com"); got.TOTPFailures != limit {
		t.Fatalf("totp_failures %d", got.TOTPFailures)
	}
	if err := s.SetPassword(ctx, u.ID, store.PasswordChange{Hash: "self", Self: true, ExpectedHash: u.PasswordHash}, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.UserTOTP(ctx, u.ID); st.Failures != limit {
		t.Fatalf("a self-service password change must not lift the lock: %d", st.Failures)
	}
	if err := s.SetPassword(ctx, u.ID, store.PasswordChange{Hash: "reset"}, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.UserTOTP(ctx, u.ID); st.Failures != 0 {
		t.Fatalf("an admin password reset must lift the lock: %d", st.Failures)
	}
}

func TestPendingEnrolmentBelongsToItsSession(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer")
	mkSession(t, s, u.ID, "a", t0, time.Hour)
	mkSession(t, s, u.ID, "b", t0, time.Hour)
	var a, b int64
	_ = s.r.QueryRow(`SELECT id FROM user_sessions WHERE token_hash=?`, hash("a")).Scan(&a)
	_ = s.r.QueryRow(`SELECT id FROM user_sessions WHERE token_hash=?`, hash("b")).Scan(&b)
	if _, _, err := s.PendingTOTP(ctx, a); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("nothing pending yet: %v", err)
	}
	if err := s.SetPendingTOTP(ctx, a, []byte("blob-a"), t0); err != nil {
		t.Fatal(err)
	}
	got, at, err := s.PendingTOTP(ctx, a)
	if err != nil || string(got) != "blob-a" || !at.Equal(t0) {
		t.Fatalf("%q %v %v", got, at, err)
	}
	if _, _, err := s.PendingTOTP(ctx, b); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another session sees the pending secret: %v", err)
	}
	if err := s.SetPendingTOTP(ctx, a, []byte("blob-a2"), t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.PendingTOTP(ctx, a); string(got) != "blob-a2" {
		t.Fatal("a second setup must overwrite the first")
	}
	if err := s.SetPendingTOTP(ctx, 9999, []byte("x"), t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("pending secret for a missing session: %v", err)
	}
}

func TestReplaceRecoveryCodes(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	plain := mkUser(t, s, "plain@example.com", "viewer")
	if err := s.ReplaceRecoveryCodes(ctx, plain.ID, [][]byte{hash("x")}, t0, cliAudit); !errors.Is(err, store.ErrCredentialChanged) {
		t.Fatalf("codes for a user without TOTP: %v", err)
	}
	u := enrolled(t, s, "a@example.com")
	if err := s.ReplaceRecoveryCodes(ctx, u.ID, [][]byte{hash("n1"), hash("n2"), hash("n3")}, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.RecoveryCodesLeft(ctx, u.ID); left != 3 {
		t.Fatalf("%d codes", left)
	}
	ch := challenge(t, s, u, "ch", t0)
	if err := s.CompleteLogin(ctx, complete(ch, nil, hash("rc0")), t0, nil); !errors.Is(err, store.ErrBadRecovery) {
		t.Fatalf("an old code works after regeneration: %v", err)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action='user.totp.recovery.regenerate'`); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
}

func TestResealCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	a := enrolled(t, s, "a@example.com")
	b := enrolled(t, s, "b@example.com")
	all, err := s.SealedTOTPSecrets(ctx)
	if err != nil || len(all) != 2 || string(all[0].Sealed) != "sealed-1" || all[0].Email != "a@example.com" {
		t.Fatalf("%+v %v", all, err)
	}
	// b's secret is replaced between the listing and the reseal: its reseal must not apply.
	if err := s.EnableTOTP(ctx, store.EnableTOTP{UserID: b.ID, ExpectedVersion: b.AuthVersion, Sealed: []byte("sealed-b2"), Step: 9}, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	n, conflicts, err := s.ResealTOTPSecrets(ctx, []store.Reseal{
		{UserID: a.ID, Old: []byte("sealed-1"), New: []byte("resealed-a")},
		{UserID: b.ID, Old: []byte("sealed-1"), New: []byte("resealed-b")},
	}, t0, cliAudit)
	if err != nil || n != 1 || len(conflicts) != 1 || conflicts[0] != b.ID {
		t.Fatalf("applied %d, conflicts %v, %v; want 1 applied and b's id as the conflict", n, conflicts, err)
	}
	if st, _ := s.UserTOTP(ctx, b.ID); string(st.Sealed) != "sealed-b2" {
		t.Fatalf("a changed secret was overwritten: %q", st.Sealed)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action='secrets.reencrypt' AND target_kind='server' AND detail LIKE '%"count":"1"%'`); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
	// Idempotent: nothing left to apply writes nothing.
	if n, _, err := s.ResealTOTPSecrets(ctx, []store.Reseal{{UserID: a.ID, Old: []byte("sealed-1"), New: []byte("z")}}, t0, cliAudit); err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action='secrets.reencrypt'`); n != 1 {
		t.Fatalf("a no-op reseal was audited: %d rows", n)
	}
	assertSecretInvariant(t, s, "after reseal")
}

func TestNoSecretOrCodeInAudit(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := enrolled(t, s, "a@example.com")
	ch := challenge(t, s, u, "ch", t0)
	_ = s.CompleteLogin(ctx, complete(ch, nil, hash("rc1")), t0, map[string]string{"mfa": "recovery_code"})
	rows, err := s.r.Query(`SELECT detail || action || target FROM audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var line string
		_ = rows.Scan(&line)
		if strings.Contains(line, "sealed-1") || strings.Contains(line, "rc1") {
			t.Fatalf("audit row leaks secret material: %s", line)
		}
	}
}

// A challenge can only exist for an enrolled user; if one somehow exists for a
// user without TOTP it must never turn into a session (a recovery or step check
// against nothing would be a password-only login).
func TestCompleteLoginRefusesAUserWithoutTOTP(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "plain@example.com", "viewer")
	ch := challenge(t, s, u, "ch", t0)
	if err := s.CompleteLogin(ctx, complete(ch, step(500), nil), t0, nil); !errors.Is(err, store.ErrCredentialChanged) {
		t.Fatalf("%v, want ErrCredentialChanged", err)
	}
	if n := count(t, s, `SELECT count(*) FROM user_sessions`); n != 0 {
		t.Fatalf("%d sessions", n)
	}
}

// A lock that lands while a login is in flight (the failures reach the limit
// after the challenge was made) must refuse the session, with the production
// limit: CompleteLogin re-checks inside its transaction.
func TestCompleteLoginRefusesALockThatLandedMidLogin(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := enrolled(t, s, "a@example.com")
	ch := challenge(t, s, u, "ch", t0)
	// 100 is the documented limit, written as a literal on purpose: a test that used the
	// constant would follow it when it is raised. Set directly: 100 round trips add nothing.
	if _, err := s.w.Exec(`UPDATE users SET totp_failures = 100 WHERE id = ?`, u.ID); err != nil {
		t.Fatal(err)
	}
	c := complete(ch, step(900), nil) // Limit: store.SecondFactorLockLimit, as the web layer passes it
	if err := s.CompleteLogin(ctx, c, t0, nil); !errors.Is(err, store.ErrSecondFactorLocked) {
		t.Fatalf("%v, want ErrSecondFactorLocked", err)
	}
	if n := count(t, s, `SELECT count(*) FROM user_sessions`); n != 0 {
		t.Fatalf("%d sessions", n)
	}
}
