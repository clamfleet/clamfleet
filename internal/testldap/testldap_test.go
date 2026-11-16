// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package testldap

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/clamfleet/clamfleet/internal/testtls"
)

func startWithTLS(t *testing.T, implicit bool) (*Server, *tls.Config) {
	t.Helper()
	b, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := Start(Options{CertFile: b.Cert, KeyFile: b.Key, Implicit: implicit})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	pem, _ := os.ReadFile(b.CA)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	s.Add("uid=ann,ou=people,dc=example,dc=org", map[string][]string{"uid": {"ann"}, "mail": {"ann@example.org"}, "objectClass": {"inetOrgPerson"}, "memberOf": {"cn=a,ou=g,dc=example,dc=org"}})
	s.SetPassword("uid=ann,ou=people,dc=example,dc=org", "pw-ann")
	s.Add("uid=bob,ou=people,dc=example,dc=org", map[string][]string{"uid": {"bob"}, "objectClass": {"inetOrgPerson"}})
	return s, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
}

func TestFakeServesBindSearchAndRecords(t *testing.T) {
	s, cfg := startWithTLS(t, true)
	c, err := ldap.DialURL(s.URL(), ldap.DialWithTLSConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bind("uid=ann,ou=people,dc=example,dc=org", "pw-ann"); err != nil {
		t.Fatal(err)
	}
	if err := c.Bind("uid=ann,ou=people,dc=example,dc=org", "nope"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	res, err := c.Search(ldap.NewSearchRequest("ou=people,dc=example,dc=org", ldap.ScopeWholeSubtree, 0, 0, 0, false,
		"(&(objectClass=inetOrgPerson)(|(uid="+ldap.EscapeFilter("ann")+")(mail=x)))", []string{"mail", "memberOf"}, nil))
	if err != nil || len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("mail") != "ann@example.org" || res.Entries[0].GetAttributeValue("uid") != "" {
		t.Fatalf("%+v %v", res, err)
	}
	// A hostile name arrives escaped and matches nothing; the fake shows what was on the wire.
	hostile := ldap.EscapeFilter("*)(uid=*")
	res, err = c.Search(ldap.NewSearchRequest("ou=people,dc=example,dc=org", ldap.ScopeWholeSubtree, 0, 0, 0, false, "(uid="+hostile+")", nil, nil))
	if err != nil || len(res.Entries) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	ss := s.Searches()
	if len(ss) != 2 || ss[1].Filter != "(uid="+hostile+")" || !ss[0].TLS {
		t.Fatalf("%+v", ss)
	}
	// Substrings and presence work, and the size limit gives code 4 with the first entries.
	res, err = c.Search(ldap.NewSearchRequest("dc=example,dc=org", ldap.ScopeWholeSubtree, 0, 1, 0, false, "(uid=*)", nil, nil))
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) || len(res.Entries) != 1 {
		t.Fatalf("%v %v", res, err)
	}
	bs := s.Binds()
	if len(bs) != 2 || !bs[0].TLS || bs[0].Code != 0 || bs[1].Code != 49 {
		t.Fatalf("%+v", bs)
	}
}

func TestFakeStartTLSAndItsRefusal(t *testing.T) {
	s, cfg := startWithTLS(t, false)
	c, err := ldap.DialURL(s.URL())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.StartTLS(cfg); err != nil {
		t.Fatal(err)
	}
	if err := c.Bind("uid=ann,ou=people,dc=example,dc=org", "pw-ann"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if bs := s.Binds(); len(bs) != 1 || !bs[0].TLS {
		t.Fatalf("a bind after StartTLS must be recorded as encrypted: %+v", bs)
	}

	s.RefuseStartTLS(true)
	c2, err := ldap.DialURL(s.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := c2.StartTLS(cfg); err == nil {
		t.Fatal("a refused StartTLS succeeded")
	}
	if s.StartTLSRequests() != 2 {
		t.Fatalf("%d StartTLS requests", s.StartTLSRequests())
	}
}

func TestFakeScriptsFailuresAndRenames(t *testing.T) {
	s, _ := startWithTLS(t, false)
	c, err := ldap.DialURL(s.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s.FailBinds(51)
	if err := c.Bind("uid=ann,ou=people,dc=example,dc=org", "pw-ann"); !ldap.IsErrorWithCode(err, 51) {
		t.Fatalf("%v", err)
	}
	s.FailBinds(0)
	s.Rename("uid=ann,ou=people,dc=example,dc=org", "uid=ann,ou=staff,dc=example,dc=org")
	if err := c.Bind("uid=ann,ou=people,dc=example,dc=org", "pw-ann"); !ldap.IsErrorWithCode(err, 49) {
		t.Fatalf("the old DN still binds: %v", err)
	}
	if err := c.Bind("UID=ann, ou=staff, dc=example, dc=org", "pw-ann"); err != nil {
		t.Fatalf("the new DN (case and spaces differ): %v", err)
	}
	s.Reset()
	if len(s.Binds()) != 0 {
		t.Fatal("Reset")
	}
}
