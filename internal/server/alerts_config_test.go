// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package server

import (
	"github.com/clamfleet/clamfleet/internal/alert"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/config"
)

func TestAlertConfigDefaults(t *testing.T) {
	c := DefaultConfig()
	if c.PublicURL != "" || c.Alert.Cooldown != 15*time.Minute || c.Alert.Webhook.Timeout != 10*time.Second ||
		!c.Alert.Webhook.AllowPrivate || c.Alert.Webhook.AllowLoopback || len(c.Alert.Webhook.DenyNetworks) != 0 {
		t.Fatalf("%+v", c.Alert)
	}
	if c.SMTP.Host != "" || c.SMTP.Port != 587 || c.SMTP.TLS != "starttls" || c.SMTP.Timeout != 30*time.Second {
		t.Fatalf("%+v", c.SMTP)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("the defaults must validate (email is simply off): %v", err)
	}
}

func TestAlertConfigValidate(t *testing.T) {
	mut := func(f func(*Config)) Config { c := DefaultConfig(); f(&c); return c }
	withSMTP := func(f func(*SMTP)) Config {
		return mut(func(c *Config) { c.SMTP.Host, c.SMTP.From = "relay.example", "clamfleet@example.org"; f(&c.SMTP) })
	}
	cases := []struct {
		name string
		c    Config
		want string // "" = valid; otherwise a fragment of the error
	}{
		{"public_url https", mut(func(c *Config) { c.PublicURL = "https://clamfleet.example" }), ""},
		{"public_url trailing slash", mut(func(c *Config) { c.PublicURL = "https://clamfleet.example/" }), ""},
		{"public_url with a path", mut(func(c *Config) { c.PublicURL = "https://x.example/cf" }), ""},
		{"public_url no scheme", mut(func(c *Config) { c.PublicURL = "clamfleet.example" }), "public_url"},
		{"public_url ftp", mut(func(c *Config) { c.PublicURL = "ftp://x.example" }), "public_url"},
		{"public_url userinfo", mut(func(c *Config) { c.PublicURL = "https://u:p@x.example" }), "public_url"},
		{"public_url query", mut(func(c *Config) { c.PublicURL = "https://x.example/?a=1" }), "public_url"},
		{"public_url fragment", mut(func(c *Config) { c.PublicURL = "https://x.example/#a" }), "public_url"},
		{"cooldown 0 (no holds)", mut(func(c *Config) { c.Alert.Cooldown = 0 }), ""},
		{"cooldown 24h", mut(func(c *Config) { c.Alert.Cooldown = 24 * time.Hour }), ""},
		{"cooldown above 24h", mut(func(c *Config) { c.Alert.Cooldown = 25 * time.Hour }), "alert.cooldown"},
		{"cooldown negative", mut(func(c *Config) { c.Alert.Cooldown = -time.Second }), "alert.cooldown"},
		{"webhook timeout 1s", mut(func(c *Config) { c.Alert.Webhook.Timeout = time.Second }), ""},
		{"webhook timeout 30s", mut(func(c *Config) { c.Alert.Webhook.Timeout = 30 * time.Second }), ""},
		{"webhook timeout 500ms", mut(func(c *Config) { c.Alert.Webhook.Timeout = 500 * time.Millisecond }), "alert.webhook.timeout"},
		{"webhook timeout 31s", mut(func(c *Config) { c.Alert.Webhook.Timeout = 31 * time.Second }), "alert.webhook.timeout"},
		{"deny_networks", mut(func(c *Config) { c.Alert.Webhook.DenyNetworks = []string{"10.9.0.0/16", "192.0.2.7", "fd12::/16"} }), ""},
		{"deny_networks invalid", mut(func(c *Config) { c.Alert.Webhook.DenyNetworks = []string{"10.9.0.0/33"} }), "deny_networks"},
		{"deny_networks garbage", mut(func(c *Config) { c.Alert.Webhook.DenyNetworks = []string{"office"} }), "deny_networks"},
		{"nat64 prefix /96", mut(func(c *Config) { c.Alert.Webhook.NAT64Prefixes = []string{"64:ff9b:1::/96"} }), ""},
		{"nat64 prefix /48", mut(func(c *Config) { c.Alert.Webhook.NAT64Prefixes = []string{"2001:db8:122::/48"} }), ""},
		{"nat64 prefix /60", mut(func(c *Config) { c.Alert.Webhook.NAT64Prefixes = []string{"2001:db8:122::/60"} }), "RFC 6052"},
		{"nat64 prefix IPv4", mut(func(c *Config) { c.Alert.Webhook.NAT64Prefixes = []string{"10.0.0.0/8"} }), "IPv6 prefix"},
		{"nat64 prefix garbage", mut(func(c *Config) { c.Alert.Webhook.NAT64Prefixes = []string{"translator"} }), "nat64_prefixes"},
		{"nat64 prefix with the u octet set", mut(func(c *Config) { c.Alert.Webhook.NAT64Prefixes = []string{"2001:db8:0:0:100::/96"} }), "bits 64-71"},
		{"nat64 prefix with host bits", mut(func(c *Config) { c.Alert.Webhook.NAT64Prefixes = []string{"2001:db8::1/32"} }), "beyond its length"},
		{"webhook ca_file relative", mut(func(c *Config) { c.Alert.Webhook.CAFile = "ca.pem" }), "ca_file"},

		{"smtp starttls", withSMTP(func(*SMTP) {}), ""},
		{"smtp port 0", withSMTP(func(m *SMTP) { m.Port = 0 }), "smtp.port"},
		{"smtp port 65536", withSMTP(func(m *SMTP) { m.Port = 65536 }), "smtp.port"},
		{"smtp tls bogus", withSMTP(func(m *SMTP) { m.TLS = "ssl" }), "smtp.tls"},
		{"smtp from required", withSMTP(func(m *SMTP) { m.From = "" }), "smtp.from"},
		{"smtp from invalid", withSMTP(func(m *SMTP) { m.From = "not an address" }), "smtp.from"},
		{"smtp username needs password_file", withSMTP(func(m *SMTP) { m.Username = "u" }), "password_file"},
		{"smtp password_file needs username", withSMTP(func(m *SMTP) { m.PasswordFile = "/etc/clamfleet/p" }), "username"},
		{"smtp username and password_file", withSMTP(func(m *SMTP) { m.Username, m.PasswordFile = "u", "/etc/clamfleet/p" }), ""},
		{"smtp password_file relative", withSMTP(func(m *SMTP) { m.Username, m.PasswordFile = "u", "p" }), "absolute"},
		{"smtp timeout 4s", withSMTP(func(m *SMTP) { m.Timeout = 4 * time.Second }), "smtp.timeout"},
		{"smtp timeout 121s", withSMTP(func(m *SMTP) { m.Timeout = 121 * time.Second }), "smtp.timeout"},

		// Decision 19.
		{"none to a public literal", withSMTP(func(m *SMTP) { m.Host, m.TLS = "203.0.113.5", "none" }), "public"},
		{"none to a NAT64 literal of a public address", withSMTP(func(m *SMTP) { m.Host, m.TLS = "64:ff9b::808:808", "none" }), "public"},
		{"none to a NAT64 literal of a private address", withSMTP(func(m *SMTP) { m.Host, m.TLS = "64:ff9b::a00:1", "none" }), ""},
		{"none to a 6to4 literal", withSMTP(func(m *SMTP) { m.Host, m.TLS = "2002:7f00:1::1", "none" }), "cannot be judged"},
		{"none to loopback", withSMTP(func(m *SMTP) { m.Host, m.TLS = "127.0.0.1", "none" }), ""},
		{"none to a private literal", withSMTP(func(m *SMTP) { m.Host, m.TLS = "10.0.0.25", "none" }), ""},
		{"none to a CGNAT literal", withSMTP(func(m *SMTP) { m.Host, m.TLS = "100.64.1.1", "none" }), ""},
		{"none to ipv6 loopback", withSMTP(func(m *SMTP) { m.Host, m.TLS = "::1", "none" }), ""},
		{"none to a hostname (checked at dial)", withSMTP(func(m *SMTP) { m.Host, m.TLS = "relay.example", "none" }), ""},
		{"none with credentials to loopback", withSMTP(func(m *SMTP) {
			m.Host, m.TLS, m.Username, m.PasswordFile = "127.0.0.1", "none", "u", "/etc/clamfleet/p"
		}), ""},
		{"none with credentials to localhost", withSMTP(func(m *SMTP) {
			m.Host, m.TLS, m.Username, m.PasswordFile = "localhost", "none", "u", "/etc/clamfleet/p"
		}), ""},
		{"none with credentials to a private literal", withSMTP(func(m *SMTP) {
			m.Host, m.TLS, m.Username, m.PasswordFile = "10.0.0.25", "none", "u", "/etc/clamfleet/p"
		}), "clear"},
		{"none with credentials to a hostname", withSMTP(func(m *SMTP) {
			m.Host, m.TLS, m.Username, m.PasswordFile = "relay.example", "none", "u", "/etc/clamfleet/p"
		}), "clear"},
		{"starttls to a public literal is fine", withSMTP(func(m *SMTP) { m.Host = "203.0.113.5" }), ""},
		{"smtp keys are not checked while host is empty", mut(func(c *Config) { c.SMTP.Port = 0 }), ""},
	}
	for _, tc := range cases {
		err := tc.c.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err=%v, want it to mention %q", tc.name, err, tc.want)
		}
	}
	if got := (Config{PublicURL: "https://x.example//"}).PublicBase(); got != "https://x.example" {
		t.Errorf("PublicBase %q", got)
	}
}

func TestAlertConfigFromYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "server.yaml")
	yaml := `
public_url: https://clamfleet.example/
alert:
  cooldown: 0s
  webhook: {timeout: 5s, allow_private: false, allow_loopback: true, deny_networks: ["10.9.0.0/16"]}
smtp: {host: relay.example, port: 465, tls: tls, from: "ClamFleet <cf@example.org>", username: u, password_file: /etc/clamfleet/p, timeout: 20s}
`
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, warns, err := LoadConfig(p, true, noEnv())
	if err != nil || len(warns) != 0 {
		t.Fatalf("%v %v", err, warns)
	}
	if c.Alert.Cooldown != 0 || c.Alert.Webhook.AllowPrivate || !c.Alert.Webhook.AllowLoopback || c.SMTP.Port != 465 || c.SMTP.TLS != "tls" {
		t.Fatalf("%+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	// The environment overrides, with the names derived from the keys.
	o := noEnv()
	o.LookupEnv = func(k string) (string, bool) {
		return map[string]string{"CLAMFLEET_SERVER_SMTP_HOST": "other.example", "CLAMFLEET_SERVER_ALERT_WEBHOOK_ALLOW_PRIVATE": "true"}[k], k == "CLAMFLEET_SERVER_SMTP_HOST" || k == "CLAMFLEET_SERVER_ALERT_WEBHOOK_ALLOW_PRIVATE"
	}
	o.Environ = func() []string {
		return []string{"CLAMFLEET_SERVER_SMTP_HOST=other.example", "CLAMFLEET_SERVER_ALERT_WEBHOOK_ALLOW_PRIVATE=true"}
	}
	c2, _, err := LoadConfig(p, true, o)
	if err != nil || c2.SMTP.Host != "other.example" || !c2.Alert.Webhook.AllowPrivate {
		t.Fatalf("%+v %v", c2, err)
	}
	// A password cannot be given in YAML: the key does not exist.
	if err := os.WriteFile(p, []byte("smtp: {host: x, password: hunter2}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadConfig(p, true, noEnv()); err == nil {
		t.Fatal("a smtp.password key must be refused")
	}
	var _ config.Options
}

// The test-send cap must stay below the HTTP write timeout, or its result
// fragment is lost to a closed connection.
func TestTestSendCapIsBelowTheWriteTimeout(t *testing.T) {
	if alert.MaxTestSend >= writeTimeout {
		t.Fatalf("alert.MaxTestSend %v must be below the write timeout %v", alert.MaxTestSend, writeTimeout)
	}
}

// smtp.password_file keeps leading and trailing spaces of the password.
func TestBuildAlertsKeepsPasswordSpaces(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(p, []byte(" pass word \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.SMTP.Host, cfg.SMTP.From, cfg.SMTP.Username, cfg.SMTP.PasswordFile = "relay.example", "cf@example.org", "u", p
	a, err := BuildAlerts(cfg, nil, nil, time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Dispatcher.Mail.(*alert.SMTPSender).Config.Password; got != " pass word " {
		t.Fatalf("password %q", got)
	}
}
