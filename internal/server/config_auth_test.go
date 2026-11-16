// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ldapOK() Config {
	c := DefaultConfig()
	c.Auth.LDAP.Enabled = true
	c.Auth.LDAP.URL = "ldaps://ldap.example:636"
	c.Auth.LDAP.AdminGroups = []string{"cn=admins,ou=groups,dc=example,dc=org"}
	return c
}

func oidcOK() Config {
	c := DefaultConfig()
	c.PublicURL = "https://clamfleet.example"
	c.Auth.OIDC.Enabled = true
	c.Auth.OIDC.Issuer = "https://id.example/realms/main"
	c.Auth.OIDC.ClientID = "clamfleet"
	c.Auth.OIDC.ClientSecretFile = "/etc/clamfleet/oidc-client-secret"
	c.Auth.OIDC.AdminValues = []string{"clamfleet-admins"}
	return c
}

// Both providers are off by default, and a disabled one is not validated (its keys may be half-filled).
func TestExternalAuthIsOffByDefault(t *testing.T) {
	c := DefaultConfig()
	if c.Auth.LDAP.Enabled || c.Auth.OIDC.Enabled {
		t.Fatal("an external provider is on by default")
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := c.Auth.EnabledSources(); !got["local"] || got["ldap"] || got["oidc"] {
		t.Fatalf("%v", got)
	}
	c.Auth.LDAP.URL = "garbage"
	if err := c.Validate(); err != nil {
		t.Fatalf("a disabled provider was validated: %v", err)
	}
}

func TestLDAPConfigValidation(t *testing.T) {
	if err := ldapOK().Validate(); err != nil {
		t.Fatalf("the good configuration: %v", err)
	}
	for _, tc := range []struct {
		name string
		mut  func(*AuthLDAP)
		want string // text of the error; "" means accepted
	}{
		{"ldaps", func(l *AuthLDAP) {}, ""},
		{"starttls on ldap", func(l *AuthLDAP) { l.URL = "ldap://ldap.example"; l.StartTLS = true }, ""},
		// Decision 22: plaintext LDAP only to the same machine, not to private networks either.
		{"plain ldap to a host", func(l *AuthLDAP) { l.URL = "ldap://ldap.example" }, "unencrypted"},
		{"plain ldap to a private address", func(l *AuthLDAP) { l.URL = "ldap://10.1.2.3:389" }, "unencrypted"},
		{"plain ldap to localhost", func(l *AuthLDAP) { l.URL = "ldap://localhost" }, ""},
		{"plain ldap to 127.0.0.1", func(l *AuthLDAP) { l.URL = "ldap://127.0.0.1:389" }, ""},
		{"plain ldap to ::1", func(l *AuthLDAP) { l.URL = "ldap://[::1]:389" }, ""},
		{"starttls on ldaps", func(l *AuthLDAP) { l.StartTLS = true }, "start_tls does not apply"},
		{"http scheme", func(l *AuthLDAP) { l.URL = "http://ldap.example" }, "auth.ldap.url"},
		{"no url", func(l *AuthLDAP) { l.URL = "" }, "auth.ldap.url"},
		{"url with user info", func(l *AuthLDAP) { l.URL = "ldaps://u:p@ldap.example" }, "auth.ldap.url"},
		{"timeout too small", func(l *AuthLDAP) { l.Timeout = 0 }, "timeout"},
		{"timeout too large", func(l *AuthLDAP) { l.Timeout = 31e9 }, "timeout"},
		{"bind dn without a password file", func(l *AuthLDAP) { l.BindDN = "cn=ro,dc=x" }, "together"},
		{"password file without a bind dn", func(l *AuthLDAP) { l.BindPasswordFile = "/etc/p" }, "together"},
		{"bind with both", func(l *AuthLDAP) { l.BindDN = "cn=ro,dc=x"; l.BindPasswordFile = "/etc/p" }, ""},
		{"relative password file", func(l *AuthLDAP) { l.BindDN = "cn=ro,dc=x"; l.BindPasswordFile = "p" }, "absolute"},
		{"relative ca file", func(l *AuthLDAP) { l.CAFile = "ca.pem" }, "absolute"},
		{"no base dn", func(l *AuthLDAP) { l.UserBaseDN = "" }, "user_base_dn"},
		{"filter without the placeholder", func(l *AuthLDAP) { l.UserFilter = "(uid=ann)" }, "{username}"},
		{"unbalanced filter", func(l *AuthLDAP) { l.UserFilter = "(&(uid={username})" }, "user_filter"},
		{"two filters side by side", func(l *AuthLDAP) { l.UserFilter = "(uid={username})(cn=x)" }, "user_filter"},
		{"no id attribute", func(l *AuthLDAP) { l.IDAttribute = "" }, "id_attribute"},
		{"no username attribute", func(l *AuthLDAP) { l.UsernameAttribute = "" }, "username_attribute"},
		{"no group mapping", func(l *AuthLDAP) { l.AdminGroups = nil }, "admin_groups and viewer_groups"},
		{"viewer groups only", func(l *AuthLDAP) { l.AdminGroups = nil; l.ViewerGroups = []string{"cn=v,dc=x"} }, ""},
		{"group search without a base", func(l *AuthLDAP) { l.GroupAttribute = "" }, "group_base_dn"},
		{"group search without {dn}", func(l *AuthLDAP) { l.GroupAttribute = ""; l.GroupBaseDN = "ou=g,dc=x"; l.GroupFilter = "(member=x)" }, "{dn}"},
		{"group search", func(l *AuthLDAP) { l.GroupAttribute = ""; l.GroupBaseDN = "ou=g,dc=x" }, ""},
	} {
		c := ldapOK()
		tc.mut(&c.Auth.LDAP)
		err := c.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want an error containing %q", tc.name, err, tc.want)
		}
	}
}

func TestOIDCConfigValidation(t *testing.T) {
	if err := oidcOK().Validate(); err != nil {
		t.Fatalf("the good configuration: %v", err)
	}
	for _, tc := range []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"issuer over plain http", func(c *Config) { c.Auth.OIDC.Issuer = "http://id.example" }, "plain http"},
		{"issuer over http to loopback", func(c *Config) { c.Auth.OIDC.Issuer = "http://127.0.0.1:8080/realms/x" }, ""},
		{"issuer not a url", func(c *Config) { c.Auth.OIDC.Issuer = "id.example" }, "auth.oidc.issuer"},
		{"issuer with a query", func(c *Config) { c.Auth.OIDC.Issuer = "https://id.example/?a=b" }, "query"},
		{"no public url", func(c *Config) { c.PublicURL = "" }, "public_url"},
		{"no client id", func(c *Config) { c.Auth.OIDC.ClientID = "" }, "client_id"},
		{"no secret file", func(c *Config) { c.Auth.OIDC.ClientSecretFile = "" }, "client_secret_file"},
		{"relative secret file", func(c *Config) { c.Auth.OIDC.ClientSecretFile = "secret" }, "client_secret_file"},
		{"client auth post", func(c *Config) { c.Auth.OIDC.ClientAuth = "post" }, ""},
		{"client auth other", func(c *Config) { c.Auth.OIDC.ClientAuth = "jwt" }, "client_auth"},
		{"scopes without openid", func(c *Config) { c.Auth.OIDC.Scopes = []string{"email"} }, "openid"},
		{"scope with a space", func(c *Config) { c.Auth.OIDC.Scopes = []string{"openid", "a b"} }, "scopes"},
		{"timeout", func(c *Config) { c.Auth.OIDC.Timeout = 31e9 }, "timeout"},
		{"no role claim", func(c *Config) { c.Auth.OIDC.RoleClaim = "" }, "role_claim"},
		{"no mapping", func(c *Config) { c.Auth.OIDC.AdminValues = nil }, "admin_values and viewer_values"},
		{"long button text", func(c *Config) { c.Auth.OIDC.DisplayName = strings.Repeat("x", 65) }, "display_name"},
	} {
		c := oidcOK()
		tc.mut(&c)
		err := c.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want an error containing %q", tc.name, err, tc.want)
		}
	}
	if got := oidcOK().OIDCRedirectURL(); got != "https://clamfleet.example/login/oidc/callback" {
		t.Fatal(got)
	}
	c := oidcOK()
	c.PublicURL = "https://clamfleet.example/"
	if got := c.OIDCRedirectURL(); got != "https://clamfleet.example/login/oidc/callback" {
		t.Fatalf("a trailing slash gives %q", got)
	}
}

// Decision 21: LDAP has no second factor ClamFleet can enforce; the start-up says so.
func TestLDAPWithTOTPRequiredWarns(t *testing.T) {
	c := ldapOK()
	if w := c.Warnings(); len(w) != 0 {
		t.Fatalf("warns without totp_required: %v", w)
	}
	c.Auth.Local.TOTPRequired = true
	w := c.Warnings()
	if len(w) != 1 || !strings.Contains(w[0], "password-only") {
		t.Fatalf("%v", w)
	}
	c.Auth.LDAP.Enabled = false
	if w := c.Warnings(); len(w) != 0 {
		t.Fatalf("warns with LDAP off: %v", w)
	}
}

// The new keys load from the file and the environment like every other setting.
func TestExternalAuthKeysLoadFromFileAndEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(path, []byte("auth:\n  ldap:\n    enabled: true\n    url: ldaps://ldap.example\n    admin_groups: [\"cn=a,dc=x\", \"cn=b,dc=x\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := noEnv()
	o.Environ = func() []string { return []string{"CLAMFLEET_SERVER_AUTH_OIDC_VIEWER_VALUES=v1,v2"} }
	o.LookupEnv = func(k string) (string, bool) {
		if k == "CLAMFLEET_SERVER_AUTH_OIDC_VIEWER_VALUES" {
			return "v1,v2", true
		}
		return "", false
	}
	c, _, err := LoadConfig(path, true, o)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Auth.LDAP.Enabled || len(c.Auth.LDAP.AdminGroups) != 2 || c.Auth.LDAP.AdminGroups[1] != "cn=b,dc=x" || c.Auth.LDAP.IDAttribute != "entryUUID" {
		t.Fatalf("%+v", c.Auth.LDAP)
	}
	if len(c.Auth.OIDC.ViewerValues) != 2 || c.Auth.OIDC.ViewerValues[0] != "v1" {
		t.Fatalf("%+v", c.Auth.OIDC)
	}
}
