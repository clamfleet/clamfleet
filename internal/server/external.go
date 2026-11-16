// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// external.go: builds the LDAP and OIDC sign-in from the configuration. The files they name
// (bind password, client secret, CA bundles) are read here, once, under the key-file
// permission rule, so a bad one refuses the start with its reason and never turns a
// provider quietly off.
package server

import (
	"fmt"

	"github.com/clamfleet/clamfleet/internal/extauth"
	"github.com/clamfleet/clamfleet/internal/secrets"
)

// BuildLDAP returns the directory for auth.ldap, or nil when it is switched off.
// The configuration must have passed Validate.
func BuildLDAP(c Config) (*extauth.Directory, error) {
	l := c.Auth.LDAP
	if !l.Enabled {
		return nil, nil
	}
	pool, err := loadPool(l.CAFile, "auth.ldap.ca_file")
	if err != nil {
		return nil, err
	}
	pw := ""
	if l.BindPasswordFile != "" {
		if pw, err = secrets.ReadProtectedFileExact(l.BindPasswordFile, "auth.ldap.bind_password_file"); err != nil {
			return nil, err
		}
	}
	d, err := extauth.NewDirectory(extauth.LDAPConfig{
		URL: l.URL, StartTLS: l.StartTLS, RootCAs: pool, Timeout: l.Timeout, BindDN: l.BindDN, BindPassword: pw,
		UserBaseDN: l.UserBaseDN, UserFilter: l.UserFilter, IDAttribute: l.IDAttribute, EmailAttribute: l.EmailAttribute,
		NameAttribute: l.NameAttribute, UsernameAttribute: l.UsernameAttribute, GroupAttribute: l.GroupAttribute,
		GroupBaseDN: l.GroupBaseDN, GroupFilter: l.GroupFilter, AdminGroups: l.AdminGroups, ViewerGroups: l.ViewerGroups,
	})
	if err != nil {
		return nil, fmt.Errorf("auth.ldap: %w", err)
	}
	return d, nil
}
