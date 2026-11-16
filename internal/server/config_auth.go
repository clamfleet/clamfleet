// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// config_auth.go: the auth.ldap and auth.oidc configuration subtrees and their
// validation (docs/plans/milestone-6.md 4.16 and 4.17; M3 decision 3: one subtree per
// provider, several on at once). Only string, int, bool, duration and []string values
// are used, so the shared loader (internal/config) takes them without changes.
//
// Validation does no I/O: the secret files and CA bundles are read when the server
// starts (NewHandlerFromConfig), under the key-file permission rule, so a bad one
// refuses the start with its reason.
package server

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/clamfleet/clamfleet/internal/config"
	"github.com/clamfleet/clamfleet/internal/extauth"
)

// AuthLDAP configures sign-in against one LDAP directory (search-then-bind).
type AuthLDAP struct {
	Enabled bool `yaml:"enabled"`
	// URL is ldaps://host[:port] or ldap://host[:port]. ldap:// needs StartTLS unless
	// the host is loopback (M6 decision 22: LDAP carries every user's password).
	URL      string `yaml:"url"`
	StartTLS bool   `yaml:"start_tls"`
	// CAFile adds trust anchors (PEM) to the system roots; verification is never skipped.
	CAFile  string        `yaml:"ca_file"`
	Timeout time.Duration `yaml:"timeout"`
	// BindDN and BindPasswordFile are the service account of the search; both empty means an
	// anonymous search. The password is only ever read from a file.
	BindDN           string `yaml:"bind_dn"`
	BindPasswordFile string `yaml:"bind_password_file"`
	UserBaseDN       string `yaml:"user_base_dn"`
	// UserFilter must contain {username}, which is escaped (RFC 4515) before it is used.
	UserFilter string `yaml:"user_filter"`
	// IDAttribute is the stable identity of the user: entryUUID, or objectGUID on AD (binary,
	// stored as hex). Never the DN: it changes when an entry is renamed.
	IDAttribute       string `yaml:"id_attribute"`
	EmailAttribute    string `yaml:"email_attribute"`
	NameAttribute     string `yaml:"name_attribute"`
	UsernameAttribute string `yaml:"username_attribute"`
	// GroupAttribute is read from the user entry (memberOf); empty means groups are searched
	// under GroupBaseDN with GroupFilter, as the service account.
	GroupAttribute string `yaml:"group_attribute"`
	GroupBaseDN    string `yaml:"group_base_dn"`
	// GroupFilter must contain {dn} (escaped).
	GroupFilter  string   `yaml:"group_filter"`
	AdminGroups  []string `yaml:"admin_groups"`
	ViewerGroups []string `yaml:"viewer_groups"`
}

// AuthOIDC configures sign-in with one OpenID Connect provider (authorization-code flow with PKCE).
type AuthOIDC struct {
	Enabled     bool   `yaml:"enabled"`
	DisplayName string `yaml:"display_name"`
	// Issuer is https, or http for a loopback host only (tests).
	Issuer           string `yaml:"issuer"`
	ClientID         string `yaml:"client_id"`
	ClientSecretFile string `yaml:"client_secret_file"`
	// ClientAuth is basic (client_secret_basic) or post (client_secret_post).
	ClientAuth string        `yaml:"client_auth"`
	Scopes     []string      `yaml:"scopes"`
	CAFile     string        `yaml:"ca_file"`
	Timeout    time.Duration `yaml:"timeout"`
	// RoleClaim is a dotted path into the ID token claims ("groups", "realm_access.roles"); the
	// value is a string or an array of strings.
	RoleClaim    string   `yaml:"role_claim"`
	AdminValues  []string `yaml:"admin_values"`
	ViewerValues []string `yaml:"viewer_values"`
}

// Bounds of the per-operation timeouts of both providers.
const (
	minExtTimeout = time.Second
	maxExtTimeout = 30 * time.Second
)

// defaultAuthLDAP and defaultAuthOIDC are the documented defaults (docs/auth.md); both are off.
func defaultAuthLDAP() AuthLDAP {
	return AuthLDAP{
		Timeout:    10 * time.Second,
		UserFilter: "(&(objectClass=inetOrgPerson)(|(uid={username})(mail={username})))",
		// entryUUID is what OpenLDAP and 389-ds provide; AD sites set objectGUID.
		IDAttribute: "entryUUID", EmailAttribute: "mail", NameAttribute: "cn", UsernameAttribute: "uid",
		GroupAttribute: "memberOf",
		GroupFilter:    "(&(objectClass=groupOfNames)(member={dn}))",
		AdminGroups:    []string{}, ViewerGroups: []string{},
		UserBaseDN: "ou=people,dc=example,dc=org",
	}
}

func defaultAuthOIDC() AuthOIDC {
	return AuthOIDC{
		DisplayName: "Single sign-on", ClientAuth: "basic", Scopes: []string{"openid", "email", "profile"},
		Timeout: 10 * time.Second, RoleClaim: "groups", AdminValues: []string{}, ViewerValues: []string{},
	}
}

// validateTimeout is shared by both providers.
func validateTimeout(key string, d time.Duration) error {
	if d < minExtTimeout || d > maxExtTimeout {
		return fmt.Errorf("%s must be between 1s and 30s, got %s", key, d)
	}
	return nil
}

func absIfSet(key, p string) error {
	if p != "" && !filepath.IsAbs(p) {
		return fmt.Errorf("%s must be an absolute path, got %q", key, p)
	}
	return nil
}

// Validate checks auth.ldap. A disabled provider is not checked: its keys may be half-filled.
func (l AuthLDAP) Validate() error {
	if !l.Enabled {
		return nil
	}
	u, err := url.Parse(l.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return fmt.Errorf("auth.ldap.url must look like ldaps://ldap.example:636 or ldap://ldap.example, got %q", l.URL)
	}
	switch {
	case u.Scheme == "ldaps" && l.StartTLS:
		return fmt.Errorf("auth.ldap.start_tls does not apply to an ldaps:// URL (it is encrypted from the first byte): use ldap:// with start_tls, or ldaps:// without it")
	case u.Scheme == "ldap" && !l.StartTLS && !config.IsLoopbackHost(u.Hostname()):
		// M6 decision 22: no plaintext LDAP beyond the same machine, not even on a private network.
		return fmt.Errorf("auth.ldap.url %q would send every user's password unencrypted: use ldaps:// or set auth.ldap.start_tls (plaintext is only allowed to a directory on this machine)", l.URL)
	}
	if err := validateTimeout("auth.ldap.timeout", l.Timeout); err != nil {
		return err
	}
	if (l.BindDN == "") != (l.BindPasswordFile == "") {
		return fmt.Errorf("auth.ldap.bind_dn and auth.ldap.bind_password_file must be set together (the password is only read from a file; leave both empty for an anonymous search)")
	}
	for k, p := range map[string]string{"auth.ldap.ca_file": l.CAFile, "auth.ldap.bind_password_file": l.BindPasswordFile} {
		if err := absIfSet(k, p); err != nil {
			return err
		}
	}
	if l.UserBaseDN == "" {
		return fmt.Errorf("auth.ldap.user_base_dn is required")
	}
	if !strings.Contains(l.UserFilter, "{username}") {
		return fmt.Errorf("auth.ldap.user_filter must contain {username}")
	}
	if err := CheckLDAPFilterTemplate(l.UserFilter, "{username}"); err != nil {
		return fmt.Errorf("auth.ldap.user_filter: %w", err)
	}
	if l.IDAttribute == "" {
		return fmt.Errorf("auth.ldap.id_attribute is required (entryUUID, or objectGUID on Active Directory): the DN is never used as an identity, it changes on a rename")
	}
	if l.UsernameAttribute == "" {
		return fmt.Errorf("auth.ldap.username_attribute is required (uid, or sAMAccountName on Active Directory)")
	}
	if len(l.AdminGroups) == 0 && len(l.ViewerGroups) == 0 {
		return fmt.Errorf("auth.ldap needs at least one of admin_groups and viewer_groups: without a mapping nobody would get a role")
	}
	if l.GroupAttribute == "" {
		if l.GroupBaseDN == "" || !strings.Contains(l.GroupFilter, "{dn}") {
			return fmt.Errorf("auth.ldap: with an empty group_attribute, groups are searched: set group_base_dn and a group_filter that contains {dn}")
		}
		if err := CheckLDAPFilterTemplate(l.GroupFilter, "{dn}"); err != nil {
			return fmt.Errorf("auth.ldap.group_filter: %w", err)
		}
	}
	return nil
}

// Validate checks auth.oidc (publicURL is the top-level public_url, which the redirect URL is built from).
func (o AuthOIDC) Validate(publicURL string) error {
	if !o.Enabled {
		return nil
	}
	if err := checkHTTPSOrLoopback("auth.oidc.issuer", o.Issuer); err != nil {
		return err
	}
	if iu, _ := url.Parse(o.Issuer); iu.RawQuery != "" || iu.Fragment != "" {
		return fmt.Errorf("auth.oidc.issuer must not contain a query or fragment")
	}
	if publicURL == "" {
		return fmt.Errorf("auth.oidc needs public_url: the provider is told to return the browser to public_url/login/oidc/callback")
	}
	if o.ClientID == "" {
		return fmt.Errorf("auth.oidc.client_id is required")
	}
	if o.ClientSecretFile == "" || !filepath.IsAbs(o.ClientSecretFile) {
		return fmt.Errorf("auth.oidc.client_secret_file must be an absolute path (the secret is only read from a file), got %q", o.ClientSecretFile)
	}
	if err := absIfSet("auth.oidc.ca_file", o.CAFile); err != nil {
		return err
	}
	if o.ClientAuth != "basic" && o.ClientAuth != "post" {
		return fmt.Errorf("auth.oidc.client_auth must be basic or post, got %q", o.ClientAuth)
	}
	hasOpenID := false
	for _, s := range o.Scopes {
		hasOpenID = hasOpenID || s == "openid"
		if s == "" || strings.ContainsAny(s, " \t\r\n") {
			return fmt.Errorf("auth.oidc.scopes: %q is not a scope", s)
		}
	}
	if !hasOpenID {
		return fmt.Errorf("auth.oidc.scopes must include openid")
	}
	if err := validateTimeout("auth.oidc.timeout", o.Timeout); err != nil {
		return err
	}
	if o.RoleClaim == "" {
		return fmt.Errorf("auth.oidc.role_claim is required (a dotted path such as groups or realm_access.roles)")
	}
	if len(o.AdminValues) == 0 && len(o.ViewerValues) == 0 {
		return fmt.Errorf("auth.oidc needs at least one of admin_values and viewer_values: without a mapping nobody would get a role")
	}
	if o.DisplayName == "" || len(o.DisplayName) > 64 {
		return fmt.Errorf("auth.oidc.display_name must be 1 to 64 characters (it is the button text)")
	}
	return nil
}

// checkHTTPSOrLoopback requires an absolute https URL, or http for a loopback host (test providers).
func checkHTTPSOrLoopback(key, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("%s must be an absolute https URL such as https://id.example/realms/main, got %q", key, raw)
	}
	if u.Scheme == "http" && !config.IsLoopbackHost(u.Hostname()) {
		return fmt.Errorf("%s %q is plain http: the tokens would travel unencrypted. Use https (http is only accepted for a loopback host)", key, raw)
	}
	return nil
}

// OIDCRedirectURL is where the provider returns the browser: public_url + /login/oidc/callback.
func (c Config) OIDCRedirectURL() string { return c.PublicBase() + "/login/oidc/callback" }

// CheckLDAPFilterTemplate checks that an LDAP filter template compiles once its
// placeholder (such as {username}) is replaced by a harmless value.
func CheckLDAPFilterTemplate(tmpl, placeholder string) error {
	return extauth.CheckFilterTemplate(tmpl, placeholder)
}
