// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package extauth

import "testing"

func TestRoleMapResolve(t *testing.T) {
	m := RoleMap{
		Admin:     []string{"CN=Admins, OU=Groups, DC=example, DC=org"},
		Viewer:    []string{"cn=viewers,ou=groups,dc=example,dc=org"},
		Normalize: NormalizeDN,
	}
	for _, c := range []struct {
		name   string
		values []string
		role   string
		ok     bool
	}{
		{"admin", []string{"cn=admins,ou=groups,dc=example,dc=org"}, "admin", true},
		{"admin wins over viewer", []string{"cn=viewers,ou=groups,dc=example,dc=org", "CN=ADMINS,OU=GROUPS,DC=EXAMPLE,DC=ORG"}, "admin", true},
		{"viewer", []string{"cn=other,dc=x", "cn=viewers, ou=groups , dc=example,dc=org"}, "viewer", true},
		{"none", []string{"cn=other,ou=groups,dc=example,dc=org"}, "", false},
		{"no groups", nil, "", false},
		// A DN that merely contains an admin DN as a suffix or substring is a different group.
		{"suffix is not a match", []string{"cn=x,cn=admins,ou=groups,dc=example,dc=org"}, "", false},
		{"prefix is not a match", []string{"cn=admins,ou=groups,dc=example"}, "", false},
	} {
		role, ok := m.Resolve(c.values)
		if role != c.role || ok != c.ok {
			t.Errorf("%s: %q %v, want %q %v", c.name, role, ok, c.role, c.ok)
		}
	}
}

// OIDC values are compared exactly: "Admins" is not "admins".
func TestRoleMapExactComparisonWithoutNormalizer(t *testing.T) {
	m := RoleMap{Admin: []string{"clamfleet-admins"}, Viewer: []string{"clamfleet-viewers"}}
	if r, ok := m.Resolve([]string{"Clamfleet-Admins"}); ok {
		t.Fatalf("case-insensitive match: %q", r)
	}
	if r, ok := m.Resolve([]string{"x", "clamfleet-viewers"}); !ok || r != "viewer" {
		t.Fatalf("%q %v", r, ok)
	}
	// Nothing configured, nothing matches (not even an empty value).
	if _, ok := (RoleMap{}).Resolve([]string{""}); ok {
		t.Fatal("an empty mapping granted a role")
	}
}

func TestNormalizeDN(t *testing.T) {
	for _, c := range [][2]string{
		{"CN=Admins, OU=Groups", "cn=admins,ou=groups"},
		{"cn = admins ,ou= groups", "cn=admins,ou=groups"},
		{"uid=a+cn=b,dc=x", "uid=a+cn=b,dc=x"},
		{"not a dn", "not a dn"},
		{"  Mixed Case  ", "mixed case"},
	} {
		if got := NormalizeDN(c[0]); got != c[1] {
			t.Errorf("%q -> %q, want %q", c[0], got, c[1])
		}
	}
	if NormalizeDN(`cn=a\,b,dc=x`) == NormalizeDN(`cn=a,b,dc=x`) {
		t.Error("an escaped comma collapsed into a separator")
	}
}
