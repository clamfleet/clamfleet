// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

var cliAudit = store.Audit{Kind: store.ActorCLI, Actor: "root"}

func mkUser(t *testing.T, s *Store, email, role string) store.User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), store.NewUser{Email: email, Role: role, PasswordHash: "$argon2id$x", MustChange: true}, t0, cliAudit)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mkSession(t *testing.T, s *Store, uid int64, tok string, at time.Time, life time.Duration) []byte {
	t.Helper()
	h := hash(tok)
	if err := s.CreateSession(context.Background(), store.Session{TokenHash: h, UserID: uid, CSRF: []byte("csrf-" + tok), CreatedAt: at, ExpiresAt: at.Add(life)}); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestCreateUserNormalisesAndAudits(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u, err := s.CreateUser(ctx, store.NewUser{Email: "  Ann@Example.COM ", Role: "admin", PasswordHash: "h", MustChange: true}, t0, cliAudit)
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "ann@example.com" || u.Role != "admin" || !u.MustChange || u.Disabled || u.AuthSource != "local" || u.PasswordHash != "h" {
		t.Fatalf("%+v", u)
	}
	if _, err := s.CreateUser(ctx, store.NewUser{Email: "ANN@example.com", Role: "viewer", PasswordHash: "h"}, t0, cliAudit); !errors.Is(err, store.ErrUserExists) {
		t.Fatalf("duplicate (case differs): %v", err)
	}
	for _, bad := range []string{"", "no-at", "@x", "a@", "a@@b", "a b@c", "a@b\nc", "a\x00@b"} {
		if _, err := s.CreateUser(ctx, store.NewUser{Email: bad, Role: "viewer"}, t0, cliAudit); err == nil {
			t.Errorf("email %q accepted", bad)
		}
	}
	if _, err := s.CreateUser(ctx, store.NewUser{Email: "x@y.z", Role: "root"}, t0, cliAudit); err == nil {
		t.Error("role root accepted")
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action='user.add' AND target_kind='user' AND target='ann@example.com' AND actor_kind='cli' AND detail LIKE '%admin%'`); n != 1 {
		t.Fatalf("%d user.add audit rows, want 1", n)
	}
	if n := count(t, s, `SELECT count(*) FROM users`); n != 1 {
		t.Fatalf("%d users after failures, want 1", n)
	}
	got, err := s.UserByEmail(ctx, "ANN@example.com")
	if err != nil || got.ID != u.ID {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	if _, err := s.UserByEmail(ctx, "nobody@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := s.UserByEmail(ctx, "garbage"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("invalid address: %v", err)
	}
}

func TestSessionExpiryIdleAndAbsolute(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer")
	h := mkSession(t, s, u.ID, "tok", t0, 12*time.Hour)
	idle := time.Hour

	p, err := s.SessionByTokenHash(ctx, h, t0.Add(30*time.Minute), idle)
	if err != nil || p.Email != "a@example.com" || p.Role != "viewer" || string(p.CSRF) != "csrf-tok" || !p.MustChange {
		t.Fatalf("fresh: %+v %v", p, err)
	}
	// Idle: valid just before, gone at exactly the idle limit.
	if _, err := s.SessionByTokenHash(ctx, h, t0.Add(idle-time.Second), idle); err != nil {
		t.Fatalf("just inside idle: %v", err)
	}
	if _, err := s.SessionByTokenHash(ctx, h, t0.Add(idle), idle); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("at the idle limit: %v", err)
	}
	// Activity moves the idle window; the absolute limit does not move.
	if err := s.TouchSession(ctx, p.SessionID, t0.Add(50*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByTokenHash(ctx, h, t0.Add(100*time.Minute), idle); err != nil {
		t.Fatalf("touched session within idle: %v", err)
	}
	h2 := mkSession(t, s, u.ID, "tok2", t0, 2*time.Hour)
	if err := s.TouchSession(ctx, 2, t0.Add(100*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByTokenHash(ctx, h2, t0.Add(2*time.Hour-time.Second), idle); err != nil {
		t.Fatalf("just inside absolute: %v", err)
	}
	if _, err := s.SessionByTokenHash(ctx, h2, t0.Add(2*time.Hour), idle); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("at the absolute limit, even though active: %v", err)
	}
	if _, err := s.SessionByTokenHash(ctx, nil, t0, idle); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("empty hash: %v", err)
	}
}

func TestTouchSessionIsThrottled(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer")
	h := mkSession(t, s, u.ID, "tok", t0, 12*time.Hour)
	p, _ := s.SessionByTokenHash(ctx, h, t0, time.Hour)
	_ = s.TouchSession(ctx, p.SessionID, t0.Add(30*time.Second)) // inside the minute: no write
	_ = s.TouchSession(ctx, p.SessionID, t0.Add(61*time.Second)) // outside: written
	p, _ = s.SessionByTokenHash(ctx, h, t0.Add(61*time.Second), time.Hour)
	if !p.LastSeen.Equal(t0.Add(61 * time.Second)) {
		t.Fatalf("last_seen %v", p.LastSeen)
	}
	_ = s.TouchSession(ctx, p.SessionID, t0.Add(90*time.Second))
	p, _ = s.SessionByTokenHash(ctx, h, t0.Add(90*time.Second), time.Hour)
	if !p.LastSeen.Equal(t0.Add(61 * time.Second)) {
		t.Fatalf("a touch 29 s after the last one wrote anyway: %v", p.LastSeen)
	}
}

func TestChangesEndSessionsAtOnce(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(s *Store, id int64) error{
		"disable": func(s *Store, id int64) error { return s.SetDisabled(ctx, id, true, t0, cliAudit) },
		"role":    func(s *Store, id int64) error { return s.SetRole(ctx, id, "admin", t0, cliAudit) },
		"password reset": func(s *Store, id int64) error {
			return s.SetPassword(ctx, id, store.PasswordChange{Hash: "n"}, t0, cliAudit)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := openTemp(t)
			u := mkUser(t, s, "a@example.com", "viewer")
			other := mkUser(t, s, "b@example.com", "viewer")
			h := mkSession(t, s, u.ID, "tok", t0, 12*time.Hour)
			ho := mkSession(t, s, other.ID, "tok-other", t0, 12*time.Hour)
			if err := change(s, u.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.SessionByTokenHash(ctx, h, t0, time.Hour); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("session survived %s: %v", name, err)
			}
			if _, err := s.SessionByTokenHash(ctx, ho, t0, time.Hour); err != nil {
				t.Fatalf("another user's session was removed: %v", err)
			}
			// The row itself is gone, not merely refused by the lookup.
			if n := count(t, s, `SELECT count(*) FROM user_sessions WHERE user_id = ?`, u.ID); n != 0 {
				t.Fatalf("%d session rows of the user left after %s", n, name)
			}
		})
	}
}

func TestDisabledUserSessionRejectedEvenIfRowSurvives(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer")
	h := mkSession(t, s, u.ID, "tok", t0, 12*time.Hour)
	// Disable behind the store's back: the join alone must refuse the session.
	if _, err := s.w.ExecContext(ctx, `UPDATE users SET disabled_at = ? WHERE id = ?`, t0.Unix(), u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByTokenHash(ctx, h, t0, time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestSetPasswordKeepsCurrentSessionAndAudits(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer")
	cur := mkSession(t, s, u.ID, "current", t0, 12*time.Hour)
	old := mkSession(t, s, u.ID, "old", t0, 12*time.Hour)
	if err := s.SetPassword(ctx, u.ID, store.PasswordChange{Hash: "new", Self: true, KeepSession: cur}, t0, store.Audit{Kind: store.ActorUser, Actor: "a@example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByTokenHash(ctx, cur, t0, time.Hour); err != nil {
		t.Fatalf("current session lost: %v", err)
	}
	if _, err := s.SessionByTokenHash(ctx, old, t0, time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other session survived: %v", err)
	}
	got, _ := s.UserByEmail(ctx, "a@example.com")
	if got.PasswordHash != "new" || got.MustChange {
		t.Fatalf("%+v", got)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action='user.password.change' AND actor_kind='user' AND actor='a@example.com' AND target='a@example.com'`); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
	if err := s.SetPassword(ctx, 999, store.PasswordChange{Hash: "x"}, t0, cliAudit); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestRehashKeepsSessionsAndMustChange(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer") // must_change = 1
	h := mkSession(t, s, u.ID, "tok", t0, 12*time.Hour)
	if err := s.RehashPassword(ctx, u.ID, "$argon2id$x", "upgraded", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByTokenHash(ctx, h, t0, time.Hour); err != nil {
		t.Fatalf("rehash ended the session: %v", err)
	}
	got, _ := s.UserByEmail(ctx, "a@example.com")
	if got.PasswordHash != "upgraded" || !got.MustChange {
		t.Fatalf("%+v", got)
	}
}

func TestDisableEnableAndLoginAudit(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer")
	if err := s.SetDisabled(ctx, u.ID, true, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.UserByEmail(ctx, "a@example.com"); !got.Disabled {
		t.Fatal("not disabled")
	}
	if err := s.SetDisabled(ctx, u.ID, false, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.UserByEmail(ctx, "a@example.com"); got.Disabled {
		t.Fatal("still disabled")
	}
	if err := s.RecordLogin(ctx, u.ID, t0.Add(time.Hour), store.Audit{Kind: store.ActorUser, Actor: "a@example.com"}, map[string]string{"ip": "192.0.2.7"}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.UserByEmail(ctx, "a@example.com")
	if got.LastLoginAt == nil || !got.LastLoginAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("last login %v", got.LastLoginAt)
	}
	for _, a := range []string{"user.disable", "user.enable", "user.login"} {
		if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action=?`, a); n != 1 {
			t.Errorf("%s: %d audit rows", a, n)
		}
	}
	if n := count(t, s, `SELECT count(*) FROM audit_log WHERE action='user.login' AND detail LIKE '%192.0.2.7%'`); n != 1 {
		t.Error("login audit lacks the client IP")
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer")
	mkSession(t, s, u.ID, "expired", t0, time.Hour)
	mkSession(t, s, u.ID, "idle", t0.Add(3*time.Hour), 12*time.Hour)
	live := mkSession(t, s, u.ID, "live", t0.Add(4*time.Hour), 12*time.Hour)
	n, err := s.DeleteExpiredSessions(ctx, t0.Add(4*time.Hour+30*time.Minute), time.Hour)
	if err != nil || n != 2 {
		t.Fatalf("deleted %d, %v; want 2 (one absolute, one idle)", n, err)
	}
	if _, err := s.SessionByTokenHash(ctx, live, t0.Add(4*time.Hour+30*time.Minute), time.Hour); err != nil {
		t.Fatal(err)
	}
}

func TestLogoutDeletesSession(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer")
	h := mkSession(t, s, u.ID, "tok", t0, time.Hour)
	if err := s.DeleteSession(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByTokenHash(ctx, h, t0, time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

// Enabling also ends sessions: a login that was verifying while the user was
// disabled could have created a session behind the disable.
func TestEnableDeletesSessionsToo(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer")
	if err := s.SetDisabled(ctx, u.ID, true, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	mkSession(t, s, u.ID, "born-while-disabled", t0, time.Hour) // the race: created behind the disable
	if err := s.SetDisabled(ctx, u.ID, false, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM user_sessions WHERE user_id = ?`, u.ID); n != 0 {
		t.Fatalf("%d sessions survived the enable", n)
	}
}

// A reset between the verification and the rehash must not be undone by a hash
// of the old password.
func TestRehashDoesNotOverwriteANewerPassword(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer") // hash "$argon2id$x"
	if err := s.SetPassword(ctx, u.ID, store.PasswordChange{Hash: "reset-hash", MustChange: true}, t0.Add(time.Second), cliAudit); err != nil {
		t.Fatal(err)
	}
	if err := s.RehashPassword(ctx, u.ID, "$argon2id$x", "upgraded-old-password", t0.Add(2*time.Second)); err != nil {
		t.Fatalf("a lost race is not an error: %v", err)
	}
	got, _ := s.UserByEmail(ctx, "a@example.com")
	if got.PasswordHash != "reset-hash" {
		t.Fatalf("the reset was overwritten: %q", got.PasswordHash)
	}
}

// A session older than the user's last password change is refused, even if its
// row exists (a login that raced a reset).
func TestSessionOlderThanPasswordChangeIsRefused(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer")
	old := mkSession(t, s, u.ID, "old", t0, 12*time.Hour)
	// Change the password behind the store's back, so the session row survives.
	if _, err := s.w.ExecContext(ctx, `UPDATE users SET password_changed_at = ? WHERE id = ?`, t0.Add(time.Minute).Unix(), u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByTokenHash(ctx, old, t0.Add(2*time.Minute), time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a session from before the password change is valid: %v", err)
	}
	fresh := mkSession(t, s, u.ID, "fresh", t0.Add(time.Minute), 12*time.Hour)
	if _, err := s.SessionByTokenHash(ctx, fresh, t0.Add(2*time.Minute), time.Hour); err != nil {
		t.Fatalf("a session created at the change time is refused: %v", err)
	}
}

// The session that survives a self-service change is re-dated, so the rule above does not kill it.
func TestSelfPasswordChangeKeepsItsSessionDespiteTheAgeRule(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u := mkUser(t, s, "a@example.com", "viewer")
	cur := mkSession(t, s, u.ID, "current", t0, 12*time.Hour)
	later := t0.Add(10 * time.Minute)
	if err := s.SetPassword(ctx, u.ID, store.PasswordChange{Hash: "new", Self: true, KeepSession: cur}, later, cliAudit); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByTokenHash(ctx, cur, later.Add(time.Minute), time.Hour); err != nil {
		t.Fatalf("the kept session died: %v", err)
	}
}
