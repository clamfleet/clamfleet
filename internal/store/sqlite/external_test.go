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

var extAudit = store.Audit{Kind: store.ActorUser, Actor: "ldap:ann"}

func extSession(tok string) store.Session {
	return store.Session{TokenHash: hash(tok), CSRF: []byte("csrf-" + tok), CreatedAt: t0, ExpiresAt: t0.Add(12 * time.Hour)}
}

func ldapAnn() store.ExternalIdentity {
	return store.ExternalIdentity{Source: store.AuthLDAP, ExternalID: "uuid-1", Email: "ann@example.org", DisplayName: "Ann", ExternalName: "ann", Role: store.RoleViewer}
}

func auditCount(t *testing.T, s *Store, action string) int {
	t.Helper()
	var n int
	if err := s.r.QueryRow(`SELECT count(*) FROM audit_log WHERE action=?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A first sign-in creates the user (no password, no TOTP), a session and the audit rows in one transaction.
func TestExternalLoginCreatesUserSessionAndAudit(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u, err := s.ExternalLogin(ctx, ldapAnn(), extSession("a"), t0, extAudit, map[string]string{"source": "ldap", "ip": "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if u.AuthSource != "ldap" || u.Email != "ann@example.org" || u.ExternalName != "ann" || u.PasswordHash != "" || u.TOTPEnabled || u.LastLoginAt == nil {
		t.Fatalf("%+v", u)
	}
	sp, err := s.SessionByTokenHash(ctx, hash("a"), t0, time.Hour)
	if err != nil || sp.UserID != u.ID || sp.AuthSource != "ldap" || sp.ExternalName != "ann" {
		t.Fatalf("%+v %v", sp, err)
	}
	if auditCount(t, s, "user.add") != 1 || auditCount(t, s, "user.login") != 1 {
		t.Fatal("want one user.add and one user.login row")
	}
}

// Rule: the identity is the external id, never the email: a second sign-in with a different email and
// name is the SAME row (a rename in the directory must not create a second user).
func TestExternalLoginFindsTheUserByExternalIDAndRefreshesIt(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u1, _ := s.ExternalLogin(ctx, ldapAnn(), extSession("a"), t0, extAudit, nil)
	id := ldapAnn()
	id.Email, id.DisplayName, id.ExternalName, id.Role = "ann.new@example.org", "Ann N", "annn", store.RoleAdmin
	u2, err := s.ExternalLogin(ctx, id, extSession("b"), t0.Add(time.Hour), extAudit, nil)
	if err != nil {
		t.Fatal(err)
	}
	if u2.ID != u1.ID || u2.Email != "ann.new@example.org" || u2.DisplayName != "Ann N" || u2.ExternalName != "annn" || u2.Role != "admin" {
		t.Fatalf("%+v", u2)
	}
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Fatalf("%d users", n)
	}
	if auditCount(t, s, "user.role.mapped") != 1 {
		t.Fatal("a role change at sign-in must be audited")
	}
	// Unchanged role: no new mapped row.
	if _, err := s.ExternalLogin(ctx, id, extSession("c"), t0.Add(2*time.Hour), extAudit, nil); err != nil {
		t.Fatal(err)
	}
	if auditCount(t, s, "user.role.mapped") != 1 {
		t.Fatal("no role change, no mapped row")
	}
	// The same external id under another source is another user.
	oid := store.ExternalIdentity{Source: store.AuthOIDC, ExternalID: "uuid-1", ExternalName: "x", Role: store.RoleViewer}
	u3, err := s.ExternalLogin(ctx, oid, extSession("d"), t0, extAudit, nil)
	if err != nil || u3.ID == u1.ID {
		t.Fatalf("%+v %v", u3, err)
	}
	if u3.Email != "" {
		t.Fatalf("no email stays empty: %q", u3.Email)
	}
}

// Rule (decision 19): an email held by another user refuses the sign-in and changes nothing, in every
// direction: a new external user against a local one, against another external one, and an existing external
// user whose directory email moved into a collision. The local user's row and sessions are untouched.
func TestExternalLoginRefusesAnEmailOfAnotherUser(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	local := mkUser(t, s, "boss@example.org", "admin")
	lsess := mkSession(t, s, local.ID, "local-tok", t0, time.Hour)

	id := ldapAnn()
	id.Email = "boss@example.org"
	if _, err := s.ExternalLogin(ctx, id, extSession("x"), t0, extAudit, nil); !errors.Is(err, store.ErrEmailInUse) {
		t.Fatalf("new external user with a local email: %v", err)
	}
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Fatalf("the refused sign-in left %d users, want 1 (the transaction must roll back the insert)", n)
	}
	if _, err := s.SessionByTokenHash(ctx, hash("x"), t0, time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a session exists for the refused sign-in: %v", err)
	}

	// An existing external user whose email changes into a collision: refused, stored email unchanged.
	ann, err := s.ExternalLogin(ctx, ldapAnn(), extSession("a"), t0, extAudit, nil)
	if err != nil {
		t.Fatal(err)
	}
	id.Email = "boss@example.org"
	if _, err := s.ExternalLogin(ctx, id, extSession("y"), t0, extAudit, nil); !errors.Is(err, store.ErrEmailInUse) {
		t.Fatalf("existing external user moved into a collision: %v", err)
	}
	got, _ := s.userByID(ctx, ann.ID)
	if got.Email != "ann@example.org" {
		t.Fatalf("the stored email changed to %q", got.Email)
	}
	// Another external user's email.
	other := store.ExternalIdentity{Source: store.AuthOIDC, ExternalID: "iss sub-2", Email: "ann@example.org", ExternalName: "o", Role: store.RoleViewer}
	if _, err := s.ExternalLogin(ctx, other, extSession("z"), t0, extAudit, nil); !errors.Is(err, store.ErrEmailInUse) {
		t.Fatalf("another external user's email: %v", err)
	}
	// The local admin is untouched.
	l2, _ := s.userByID(ctx, local.ID)
	if l2.Email != "boss@example.org" || l2.Role != "admin" || l2.AuthSource != "local" || l2.PasswordHash != "$argon2id$x" {
		t.Fatalf("%+v", l2)
	}
	if _, err := s.SessionByTokenHash(ctx, lsess, t0, time.Hour); err != nil {
		t.Fatalf("the local admin's session: %v", err)
	}
	// Signing in again with its own email is fine (the collision check excludes the user itself).
	if _, err := s.ExternalLogin(ctx, ldapAnn(), extSession("a2"), t0, extAudit, nil); err != nil {
		t.Fatalf("own email: %v", err)
	}
}

func TestExternalLoginRefusesADisabledUser(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u, _ := s.ExternalLogin(ctx, ldapAnn(), extSession("a"), t0, extAudit, nil)
	if err := s.SetDisabled(ctx, u.ID, true, t0, cliAudit); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExternalLogin(ctx, ldapAnn(), extSession("b"), t0, extAudit, nil); !errors.Is(err, store.ErrUserDisabled) {
		t.Fatalf("%v", err)
	}
	if _, err := s.SessionByTokenHash(ctx, hash("b"), t0, time.Hour); err == nil {
		t.Fatal("a disabled user got a session")
	}
}

func TestExternalLoginRejectsBadInput(t *testing.T) {
	s := openTemp(t)
	for name, mod := range map[string]func(*store.ExternalIdentity){
		"local source": func(i *store.ExternalIdentity) { i.Source = "local" },
		"no id":        func(i *store.ExternalIdentity) { i.ExternalID = "" },
		"no role":      func(i *store.ExternalIdentity) { i.Role = "" },
		"bad email":    func(i *store.ExternalIdentity) { i.Email = "not an email" },
	} {
		id := ldapAnn()
		mod(&id)
		if _, err := s.ExternalLogin(context.Background(), id, extSession("q"), t0, extAudit, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Plan 4.15: the state is one-time. The second take finds nothing, an expired one is never returned,
// and the cleanup removes only expired rows.
func TestOIDCStateIsOneTime(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	st := store.OIDCState{TokenHash: hash("c1"), State: "s", Nonce: "n", CodeVerifier: "v", NextPath: "/events", CreatedAt: t0, ExpiresAt: t0.Add(10 * time.Minute)}
	if err := s.CreateOIDCState(ctx, st); err != nil {
		t.Fatal(err)
	}
	got, err := s.TakeOIDCState(ctx, hash("c1"), t0.Add(time.Minute))
	if err != nil || got.State != "s" || got.Nonce != "n" || got.CodeVerifier != "v" || got.NextPath != "/events" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := s.TakeOIDCState(ctx, hash("c1"), t0.Add(time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second take: %v", err)
	}
	if _, err := s.TakeOIDCState(ctx, hash("other"), t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another browser's cookie: %v", err)
	}
	// Expired.
	st.TokenHash = hash("c2")
	_ = s.CreateOIDCState(ctx, st)
	if _, err := s.TakeOIDCState(ctx, hash("c2"), t0.Add(10*time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired state returned: %v", err)
	}
	// Cleanup: the expired one goes, a live one stays.
	st.TokenHash = hash("c3")
	st.ExpiresAt = t0.Add(time.Hour)
	_ = s.CreateOIDCState(ctx, st)
	n, err := s.DeleteExpiredOIDCStates(ctx, t0.Add(30*time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := s.TakeOIDCState(ctx, hash("c3"), t0.Add(30*time.Minute)); err != nil {
		t.Fatalf("the live state was deleted: %v", err)
	}
}
