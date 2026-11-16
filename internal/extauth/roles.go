// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package extauth is external sign-in: LDAP (search-then-bind) and OpenID Connect
// (authorization code flow with PKCE), and the mapping of groups or claims to a console
// role (docs/plans/milestone-6.md 4.16 to 4.18, docs/auth.md).
//
// The package knows nothing of HTTP handlers, sessions or the database: it turns
// credentials or a callback into a verified identity (an ExternalIdentity with a role),
// and the caller (internal/web) creates the user and the session in one store
// transaction. Secrets (the bind password, the client secret, a user's password, codes,
// tokens) never appear in an error text or a log line here: this package does not log,
// and its errors carry result codes and reasons only.
//
// roles.go: the mapping of group DNs (LDAP) or claim values (OIDC) to a role.
package extauth

import (
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/clamfleet/clamfleet/internal/store"
)

// RoleMap maps what a provider says about a user to a role (decision 20).
//
// Rule: admin wins if any admin value matches; otherwise viewer if any viewer value
// matches; otherwise there is NO role and the sign-in is refused (no access by default).
// The mapping runs at every sign-in, so a removal at the provider takes effect at the
// next one.
type RoleMap struct {
	Admin, Viewer []string
	// Normalize is applied to both sides before comparing: NormalizeDN for LDAP group DNs,
	// nil for OIDC values (compared exactly).
	Normalize func(string) string
}

// Resolve returns the role for the values a user presents, and false when none matches.
func (m RoleMap) Resolve(values []string) (role string, ok bool) {
	norm := m.Normalize
	if norm == nil {
		norm = func(s string) string { return s }
	}
	has := func(wanted []string) bool {
		for _, w := range wanted {
			nw := norm(w)
			for _, v := range values {
				if norm(v) == nw {
					return true
				}
			}
		}
		return false
	}
	switch {
	case has(m.Admin):
		return store.RoleAdmin, true
	case has(m.Viewer):
		return store.RoleViewer, true
	}
	return "", false
}

// NormalizeDN makes two spellings of one DN compare equal: attribute types and values are
// case-folded, and the spaces around "=", "," and "+" are removed ("CN=Admins, OU=Groups"
// equals "cn=admins,ou=groups"). A string that is not a DN is only trimmed and case-folded,
// so it can still match an identical entry. Escaped characters are kept as the parser
// reports them, so two different DNs never collapse into one.
func NormalizeDN(s string) string {
	dn, err := ldap.ParseDN(s)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(s))
	}
	rdns := make([]string, 0, len(dn.RDNs))
	for _, r := range dn.RDNs {
		attrs := make([]string, 0, len(r.Attributes))
		for _, a := range r.Attributes {
			attrs = append(attrs, strings.ToLower(a.Type)+"="+ldap.EscapeDN(strings.ToLower(a.Value)))
		}
		rdns = append(rdns, strings.Join(attrs, "+"))
	}
	return strings.Join(rdns, ",")
}
