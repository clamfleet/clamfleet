// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package extauth

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/testldap"
	"github.com/clamfleet/clamfleet/internal/testtls"
)

const (
	base      = "dc=example,dc=org"
	annDN     = "uid=ann,ou=people," + base
	adminsDN  = "cn=admins,ou=groups," + base
	viewersDN = "cn=viewers,ou=groups," + base
)

type rig struct {
	srv  *testldap.Server
	cfg  LDAPConfig
	pool *x509.CertPool
}

func newRig(t *testing.T, implicit bool) *rig {
	t.Helper()
	b, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := testldap.Start(testldap.Options{CertFile: b.Cert, KeyFile: b.Key, Implicit: implicit})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	pem, _ := os.ReadFile(b.CA)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	srv.Add("cn=svc,"+base, map[string][]string{"cn": {"svc"}})
	srv.SetPassword("cn=svc,"+base, "svc-pw")
	srv.Add(annDN, map[string][]string{
		"objectClass": {"inetOrgPerson"}, "uid": {"ann"}, "cn": {"Ann Example"}, "mail": {"Ann@Example.org"},
		"entryUUID": {"A1B2C3D4-0000-1111-2222-333344445555"}, "memberOf": {adminsDN},
	})
	srv.SetPassword(annDN, "ann-pw")
	cfg := LDAPConfig{
		URL: srv.URL(), StartTLS: !implicit, RootCAs: pool, Timeout: 2 * time.Second,
		BindDN: "cn=svc," + base, BindPassword: "svc-pw",
		UserBaseDN: "ou=people," + base, UserFilter: "(&(objectClass=inetOrgPerson)(|(uid={username})(mail={username})))",
		IDAttribute: "entryUUID", EmailAttribute: "mail", NameAttribute: "cn", UsernameAttribute: "uid", GroupAttribute: "memberOf",
		AdminGroups: []string{adminsDN}, ViewerGroups: []string{viewersDN},
	}
	return &rig{srv: srv, cfg: cfg, pool: pool}
}

func (r *rig) dir(t *testing.T) *Directory {
	t.Helper()
	d, err := NewDirectory(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func isRefused(err error, reason string) bool {
	var rf *Refusal
	return errors.Is(err, ErrRefused) && errors.As(err, &rf) && strings.Contains(rf.Reason, reason)
}

func TestLDAPGoodSignInOverImplicitTLSAndStartTLS(t *testing.T) {
	for _, implicit := range []bool{true, false} {
		r := newRig(t, implicit)
		id, err := r.dir(t).Authenticate(context.Background(), "ann", "ann-pw")
		if err != nil {
			t.Fatalf("implicit=%v: %v", implicit, err)
		}
		if id.Source != "ldap" || id.Role != "admin" || id.ExternalID != "a1b2c3d4-0000-1111-2222-333344445555" ||
			id.Email != "ann@example.org" || id.DisplayName != "Ann Example" || id.ExternalName != "ann" || id.DN != annDN {
			t.Fatalf("%+v", id)
		}
		// Every bind, the service account's and the user's, travelled encrypted.
		bs := r.srv.Binds()
		if len(bs) != 2 || bs[0].DN != "cn=svc,"+base || bs[1].DN != annDN || !bs[0].TLS || !bs[1].TLS {
			t.Fatalf("implicit=%v: %+v", implicit, bs)
		}
		if !implicit && r.srv.StartTLSRequests() != 1 {
			t.Fatal("no StartTLS")
		}
	}
}

// Step 1: an empty password sends nothing to the directory: no connection, no bind, no search. (An empty
// password bind "succeeds" on many servers, so the user would be signed in without a password.)
func TestLDAPEmptyPasswordNeverReachesTheDirectory(t *testing.T) {
	r := newRig(t, false)
	_, err := r.dir(t).Authenticate(context.Background(), "ann", "")
	if !isRefused(err, "empty password") {
		t.Fatalf("%v", err)
	}
	if n := len(r.srv.Binds()) + len(r.srv.Searches()) + r.srv.StartTLSRequests(); n != 0 {
		t.Fatalf("the directory saw %d operations for an empty password", n)
	}
}

func TestLDAPUnusableUsernamesNeverReachTheDirectory(t *testing.T) {
	r := newRig(t, false)
	for name, u := range map[string]string{"empty": "", "control": "an\x00n", "newline": "ann\n", "too long": strings.Repeat("a", 257), "invalid utf8": "an\xffn"} {
		if _, err := r.dir(t).Authenticate(context.Background(), u, "pw"); !isRefused(err, "invalid user name") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(r.srv.Searches()) != 0 {
		t.Fatal("a search was sent")
	}
}

// Step 4: the name is escaped into the filter. The fake shows what arrived on the wire, and nothing matches.
func TestLDAPFilterInjectionArrivesEscaped(t *testing.T) {
	r := newRig(t, false)
	_, err := r.dir(t).Authenticate(context.Background(), "*)(uid=*", "pw")
	if !isRefused(err, "no unique entry") {
		t.Fatalf("%v", err)
	}
	ss := r.srv.Searches()
	if len(ss) != 1 {
		t.Fatalf("%+v", ss)
	}
	want := `(&(objectClass=inetOrgPerson)(|(uid=\2a\29\28uid=\2a)(mail=\2a\29\28uid=\2a)))`
	if ss[0].Filter != want {
		t.Fatalf("filter on the wire:\n got %s\nwant %s", ss[0].Filter, want)
	}
	// Only the service account bound: the user's bind (the password check) never happened.
	if bs := r.srv.Binds(); len(bs) != 1 {
		t.Fatalf("%+v", bs)
	}
}

// Two entries match: refused, never "the first one".
func TestLDAPTwoEntriesAreRefused(t *testing.T) {
	r := newRig(t, false)
	r.srv.Add("uid=ann2,ou=people,"+base, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"ann2"}, "mail": {"ann@example.org"}, "entryUUID": {"x"}, "memberOf": {adminsDN}})
	r.srv.SetPassword("uid=ann2,ou=people,"+base, "ann-pw")
	// "ann@example.org" matches both through mail (case-insensitively).
	_, err := r.dir(t).Authenticate(context.Background(), "ann@example.org", "ann-pw")
	if !isRefused(err, "no unique entry") {
		t.Fatalf("%v", err)
	}
	for _, b := range r.srv.Binds() {
		if b.DN != "cn=svc,"+base {
			t.Fatalf("bound as %s although the entry was not unique", b.DN)
		}
	}
}

func TestLDAPWrongPasswordAndUnknownUser(t *testing.T) {
	r := newRig(t, false)
	if _, err := r.dir(t).Authenticate(context.Background(), "ann", "wrong"); !isRefused(err, "invalid credentials") {
		t.Fatalf("%v", err)
	}
	if _, err := r.dir(t).Authenticate(context.Background(), "ghost", "pw"); !isRefused(err, "no unique entry") {
		t.Fatalf("%v", err)
	}
}

// M6 decision 19: the identity is the entry's id attribute, never the DN. After a rename the same user signs in.
func TestLDAPRenameKeepsTheExternalID(t *testing.T) {
	r := newRig(t, false)
	first, err := r.dir(t).Authenticate(context.Background(), "ann", "ann-pw")
	if err != nil {
		t.Fatal(err)
	}
	r.srv.Rename(annDN, "uid=ann,ou=staff,"+base)
	r.cfg.UserBaseDN = base
	second, err := r.dir(t).Authenticate(context.Background(), "ann", "ann-pw")
	if err != nil {
		t.Fatal(err)
	}
	if second.DN == first.DN || second.ExternalID != first.ExternalID {
		t.Fatalf("%q/%q vs %q/%q", first.DN, first.ExternalID, second.DN, second.ExternalID)
	}
}

func TestLDAPGroupMapping(t *testing.T) {
	for _, c := range []struct {
		name    string
		groups  []string
		role    string
		refused bool
	}{
		{"admin", []string{adminsDN}, "admin", false},
		{"viewer", []string{viewersDN}, "viewer", false},
		{"admin wins", []string{viewersDN, adminsDN}, "admin", false},
		{"DN case and spacing", []string{"CN=Viewers, OU=Groups, DC=example, DC=org"}, "viewer", false},
		{"other group", []string{"cn=other,ou=groups," + base}, "", true},
		{"no groups", nil, "", true},
	} {
		r := newRig(t, false)
		r.srv.SetAttr(annDN, "memberOf", c.groups...)
		id, err := r.dir(t).Authenticate(context.Background(), "ann", "ann-pw")
		if c.refused {
			if !isRefused(err, "no role") {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err != nil || id.Role != c.role {
			t.Errorf("%s: %+v %v", c.name, id, err)
		}
	}
}

// Removing a group at the directory changes the next sign-in: viewer, or refused.
func TestLDAPGroupRemovalAppliesAtTheNextSignIn(t *testing.T) {
	r := newRig(t, false)
	r.srv.SetAttr(annDN, "memberOf", adminsDN, viewersDN)
	if id, err := r.dir(t).Authenticate(context.Background(), "ann", "ann-pw"); err != nil || id.Role != "admin" {
		t.Fatalf("%+v %v", id, err)
	}
	r.srv.SetAttr(annDN, "memberOf", viewersDN)
	if id, err := r.dir(t).Authenticate(context.Background(), "ann", "ann-pw"); err != nil || id.Role != "viewer" {
		t.Fatalf("%+v %v", id, err)
	}
	r.srv.SetAttr(annDN, "memberOf")
	if _, err := r.dir(t).Authenticate(context.Background(), "ann", "ann-pw"); !isRefused(err, "no role") {
		t.Fatalf("%v", err)
	}
}

// With an empty group_attribute the groups are searched as the service account (the connection was the user's).
func TestLDAPGroupSearch(t *testing.T) {
	r := newRig(t, false)
	r.srv.SetAttr(annDN, "memberOf")
	r.srv.Add(adminsDN, map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"admins"}, "member": {annDN}})
	r.cfg.GroupAttribute, r.cfg.GroupBaseDN = "", "ou=groups,"+base
	r.cfg.GroupFilter = "(&(objectClass=groupOfNames)(member={dn}))"
	id, err := r.dir(t).Authenticate(context.Background(), "ann", "ann-pw")
	if err != nil || id.Role != "admin" {
		t.Fatalf("%+v %v", id, err)
	}
	bs := r.srv.Binds()
	if len(bs) != 3 || bs[0].DN != "cn=svc,"+base || bs[1].DN != annDN || bs[2].DN != "cn=svc,"+base {
		t.Fatalf("the group search must run as the service account: %+v", bs)
	}
	ss := r.srv.Searches()
	if len(ss) != 2 || ss[1].AsDN != "cn=svc,"+base || ss[1].Filter != "(&(objectClass=groupOfNames)(member="+annDN+"))" {
		t.Fatalf("%+v", ss)
	}
}

// A binary id (AD's objectGUID) is stored as hex.
func TestLDAPBinaryIDIsHex(t *testing.T) {
	r := newRig(t, false)
	r.srv.SetRawAttr(annDN, "objectGUID", []byte{0x01, 0x02, 0xff, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0})
	r.cfg.IDAttribute = "objectGUID"
	id, err := r.dir(t).Authenticate(context.Background(), "ann", "ann-pw")
	if err != nil || id.ExternalID != "0102ff00102030405060708090a0b0c0" {
		t.Fatalf("%+v %v", id, err)
	}
}

// An entry that has no usable mail still signs in (email empty); an invalid one is treated as absent.
func TestLDAPMissingOrInvalidMailIsEmpty(t *testing.T) {
	for _, mail := range [][]string{nil, {"not an address"}} {
		r := newRig(t, false)
		r.srv.SetAttr(annDN, "mail", mail...)
		id, err := r.dir(t).Authenticate(context.Background(), "ann", "ann-pw")
		if err != nil || id.Email != "" {
			t.Fatalf("%v: %+v %v", mail, id, err)
		}
	}
}

// Step 2: a refused StartTLS ends the attempt. No bind of any kind is ever sent, so no password travels in clear.
func TestLDAPRefusedStartTLSSendsNoBind(t *testing.T) {
	r := newRig(t, false)
	r.srv.RefuseStartTLS(true)
	_, err := r.dir(t).Authenticate(context.Background(), "ann", "ann-pw")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if n := len(r.srv.Binds()) + len(r.srv.Searches()); n != 0 {
		t.Fatalf("%d operations followed a refused StartTLS", n)
	}
	if strings.Contains(err.Error(), "ann-pw") || strings.Contains(err.Error(), "svc-pw") {
		t.Fatal("a password is in the error text")
	}
}

// Verification is never skipped: a directory whose certificate the configured CAs do not vouch for is refused, and no bind is sent.
func TestLDAPUntrustedCertificateIsRefused(t *testing.T) {
	for _, implicit := range []bool{true, false} {
		r := newRig(t, implicit)
		r.cfg.RootCAs = x509.NewCertPool() // trusts nothing
		if _, err := r.dir(t).Authenticate(context.Background(), "ann", "ann-pw"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("implicit=%v: %v", implicit, err)
		}
		if len(r.srv.Binds()) != 0 {
			t.Fatalf("implicit=%v: a bind was sent over an unverified connection", implicit)
		}
	}
}

func TestLDAPFaultsAreNotRefusals(t *testing.T) {
	r := newRig(t, false)
	// The directory is down.
	r.srv.Close()
	if _, err := r.dir(t).Authenticate(context.Background(), "ann", "ann-pw"); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrRefused) {
		t.Fatalf("down: %v", err)
	}
	// The service account is rejected (a configuration fault): not the user's failure.
	r2 := newRig(t, false)
	r2.cfg.BindPassword = "wrong"
	if _, err := r2.dir(t).Authenticate(context.Background(), "ann", "ann-pw"); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrRefused) {
		t.Fatalf("service bind: %v", err)
	}
	// A busy directory (result code 51) on the user's bind is a fault, not "invalid credentials".
	r3 := newRig(t, false)
	r3.srv.FailBinds(51)
	if _, err := r3.dir(t).Authenticate(context.Background(), "ann", "ann-pw"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("busy: %v", err)
	}
	// Too slow.
	r4 := newRig(t, false)
	r4.cfg.Timeout = 200 * time.Millisecond
	r4.srv.Delay(time.Second)
	start := time.Now()
	if _, err := r4.dir(t).Authenticate(context.Background(), "ann", "ann-pw"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("timeout: %v", err)
	}
	if time.Since(start) > 900*time.Millisecond {
		t.Fatalf("the timeout did not bound the operation: %s", time.Since(start))
	}
}

// Anonymous search: no service bind, one bind in all (the user's).
func TestLDAPAnonymousSearch(t *testing.T) {
	r := newRig(t, false)
	r.cfg.BindDN, r.cfg.BindPassword = "", ""
	if _, err := r.dir(t).Authenticate(context.Background(), "ann", "ann-pw"); err != nil {
		t.Fatal(err)
	}
	if bs := r.srv.Binds(); len(bs) != 1 || bs[0].DN != annDN {
		t.Fatalf("%+v", bs)
	}
}

func TestNewDirectoryRefusesWhatConfigurationRefuses(t *testing.T) {
	r := newRig(t, false)
	for name, mut := range map[string]func(*LDAPConfig){
		"plaintext to a remote host": func(c *LDAPConfig) { c.URL = "ldap://ldap.example"; c.StartTLS = false },
		"plaintext to a private IP":  func(c *LDAPConfig) { c.URL = "ldap://10.0.0.5"; c.StartTLS = false },
		"bind dn without password":   func(c *LDAPConfig) { c.BindPassword = "" },
		"password without bind dn":   func(c *LDAPConfig) { c.BindDN = "" },
		"bad scheme":                 func(c *LDAPConfig) { c.URL = "http://ldap.example" },
		"no timeout":                 func(c *LDAPConfig) { c.Timeout = 0 },
		"no id attribute":            func(c *LDAPConfig) { c.IDAttribute = "" },
	} {
		c := r.cfg
		mut(&c)
		if _, err := NewDirectory(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Loopback plaintext is allowed.
	c := r.cfg
	c.StartTLS = false
	if _, err := NewDirectory(c); err != nil {
		t.Fatalf("loopback plaintext: %v", err)
	}
}

// At most four sign-ins talk to the directory at once.
func TestLDAPConcurrencyIsBounded(t *testing.T) {
	r := newRig(t, false)
	r.srv.Delay(150 * time.Millisecond)
	d := r.dir(t)
	done := make(chan struct{}, 8)
	for i := 0; i < 8; i++ {
		go func() {
			_, _ = d.Authenticate(context.Background(), "ann", "ann-pw")
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if cap(d.sem) != 4 {
		t.Fatalf("semaphore capacity %d", cap(d.sem))
	}
}

// The user's DN goes into the group filter ESCAPED. A DN may legally hold ( ) and *, so an unescaped
// {dn} lets an entry name change the filter (here it would not even parse, and with a "*" it could
// match every group). The fake shows what arrived on the wire, and the user still gets the right role.
func TestLDAPGroupSearchEscapesTheDNWithFilterMetacharacters(t *testing.T) {
	r := newRig(t, false)
	weirdDN := "uid=a*b(c),ou=people," + base
	r.srv.Add(weirdDN, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"a*b(c)"}, "entryUUID": {"weird-1"}})
	r.srv.SetPassword(weirdDN, "weird-pw")
	r.srv.Add(adminsDN, map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"admins"}, "member": {weirdDN}})
	r.cfg.GroupAttribute, r.cfg.GroupBaseDN = "", "ou=groups,"+base
	r.cfg.GroupFilter = "(&(objectClass=groupOfNames)(member={dn}))"
	id, err := r.dir(t).Authenticate(context.Background(), "a*b(c)", "weird-pw")
	if err != nil || id.Role != "admin" {
		t.Fatalf("%+v %v", id, err)
	}
	ss := r.srv.Searches()
	want := `(&(objectClass=groupOfNames)(member=uid=a\2ab\28c\29,ou=people,` + base + `))`
	if len(ss) != 2 || ss[1].Filter != want {
		t.Fatalf("group filter on the wire:\n got %v\nwant %s", ss, want)
	}
}
