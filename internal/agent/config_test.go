// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/config"
)

// The env names are public interface (README table). A renamed key or prefix fails here.
func TestEnvNamesMatchDocumentedTable(t *testing.T) {
	c := DefaultConfig()
	want := []string{
		"CLAMFLEET_AGENT_CLAMD_CONF", "CLAMFLEET_AGENT_DB_DIR", "CLAMFLEET_AGENT_FRESHCLAM_LOG", "CLAMFLEET_AGENT_INTERVAL",
		"CLAMFLEET_AGENT_SCAN_PATHS", "CLAMFLEET_AGENT_SCAN_SUMMARY", "CLAMFLEET_AGENT_SCAN_TIMEOUT", "CLAMFLEET_AGENT_SERVER",
		"CLAMFLEET_AGENT_SPOOL_DIR", "CLAMFLEET_AGENT_SPOOL_MAX_EVENT_DAYS", "CLAMFLEET_AGENT_SPOOL_MAX_MB", "CLAMFLEET_AGENT_TAGS", "CLAMFLEET_AGENT_TLS_CLIENT_CERT",
		"CLAMFLEET_AGENT_TLS_CLIENT_KEY", "CLAMFLEET_AGENT_TOKEN_FILE",
		"CLAMFLEET_AGENT_UNITS_CLAMD", "CLAMFLEET_AGENT_UNITS_CLAMONACC", "CLAMFLEET_AGENT_UNITS_FRESHCLAM",
	}
	if got := config.EnvNames(&c, EnvPrefix); !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestDefaultsValidate(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	for name, mut := range map[string]func(*Config){
		"zero interval":          func(c *Config) { c.Interval = 0 },
		"zero max_mb":            func(c *Config) { c.Spool.MaxMB = 0 },
		"huge max_mb":            func(c *Config) { c.Spool.MaxMB = 10241 },
		"short expiry":           func(c *Config) { c.Spool.MaxEventDays = 29 },
		"long expiry":            func(c *Config) { c.Spool.MaxEventDays = 3651 },
		"relative db":            func(c *Config) { c.DBDir = "var/lib/clamav" },
		"relative scan":          func(c *Config) { c.Scan.Paths = []string{"srv"} },
		"relative clamd":         func(c *Config) { c.ClamdConf = "clamd.conf" },
		"scan.timeout below 1m":  func(c *Config) { c.Scan.Timeout = 59 * time.Second },
		"scan.timeout above 72h": func(c *Config) { c.Scan.Timeout = 72*time.Hour + time.Second },
		"scan.timeout zero":      func(c *Config) { c.Scan.Timeout = 0 },
	} {
		c := DefaultConfig()
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSpoolBoundsAccepted(t *testing.T) {
	for _, mut := range []func(*Config){
		func(c *Config) { c.Spool.MaxMB = 1 },
		func(c *Config) { c.Spool.MaxMB = 10240 },
		func(c *Config) { c.Spool.MaxEventDays = 30 },
		func(c *Config) { c.Spool.MaxEventDays = 3650 },
	} {
		c := DefaultConfig()
		mut(&c)
		if err := c.Validate(); err != nil {
			t.Errorf("%+v: %v", c.Spool, err)
		}
	}
	if DefaultConfig().Spool.MaxEventDays != 365 {
		t.Fatal("default expiry is 365 days")
	}
}

func TestLoadConfigFileAndEnv(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.yaml")
	yml := "server: https://clamfleet.example:8443\ninterval: 1m\ntags: [prod]\nunits: {clamd: clamd@scan}\n"
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	o := config.Options{
		LookupEnv: func(k string) (string, bool) { return "9", k == "CLAMFLEET_AGENT_SPOOL_MAX_MB" },
		Environ:   func() []string { return nil },
	}
	c, _, err := LoadConfig(p, true, o)
	if err != nil {
		t.Fatal(err)
	}
	if c.Interval != time.Minute || c.Units.Clamd != "clamd@scan" || c.Units.Freshclam != "clamav-freshclam" ||
		c.Spool.MaxMB != 9 || !reflect.DeepEqual(c.Tags, []string{"prod"}) {
		t.Fatalf("got %+v", c)
	}
}

// The shipped example configs must stay loadable under strict decoding, or
// the first user to copy one gets an error.
func TestExampleConfigsLoad(t *testing.T) {
	for _, f := range []string{"agent.yaml.example", "agent.rhel9.yaml.example", "test/agent.yaml"} {
		_, _, err := LoadConfig(filepath.Join("..", "..", "deploy", f), true, config.Options{
			LookupEnv: func(string) (string, bool) { return "", false },
			Environ:   func() []string { return nil },
		})
		if err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if _, _, err := LoadConfig("/nonexistent/x.yaml", true, config.Options{}); err == nil || !strings.Contains(err.Error(), "x.yaml") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateRun(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		ok   bool
	}{
		{"https", func(c *Config) { c.Server = "https://clamfleet.example:8443" }, true},
		{"https with proxy prefix", func(c *Config) { c.Server = "https://clamfleet.example/api/cf" }, true},
		{"http to 127.0.0.1", func(c *Config) { c.Server = "http://127.0.0.1:8443" }, true},
		{"http to ::1", func(c *Config) { c.Server = "http://[::1]:8443" }, true},
		{"http to localhost", func(c *Config) { c.Server = "http://localhost:8443" }, true},
		{"http to a LAN host", func(c *Config) { c.Server = "http://10.0.0.5:8443" }, false},
		{"http to a name", func(c *Config) { c.Server = "http://clamfleet.example" }, false},
		{"http to a lookalike", func(c *Config) { c.Server = "http://localhost.example.com" }, false},
		{"empty server", func(c *Config) { c.Server = "" }, false},
		{"no scheme", func(c *Config) { c.Server = "clamfleet.example:8443" }, false},
		{"ftp", func(c *Config) { c.Server = "ftp://clamfleet.example" }, false},
		{"credentials in the URL", func(c *Config) { c.Server = "https://u:p@clamfleet.example" }, false},
		{"query", func(c *Config) { c.Server = "https://clamfleet.example/?x=1" }, false},
		{"relative token_file", func(c *Config) { c.Server = "https://x.example"; c.TokenFile = "token" }, false},
		{"client cert without key", func(c *Config) { c.Server = "https://x.example"; c.TLS.ClientCert = "/c" }, false},
		{"client key without cert", func(c *Config) { c.Server = "https://x.example"; c.TLS.ClientKey = "/k" }, false},
		{"client pair", func(c *Config) { c.Server = "https://x.example"; c.TLS = TLS{ClientCert: "/c", ClientKey: "/k"} }, true},
		{"relative client pair", func(c *Config) { c.Server = "https://x.example"; c.TLS = TLS{ClientCert: "c", ClientKey: "k"} }, false},
	}
	for _, tc := range cases {
		c := DefaultConfig()
		tc.mut(&c)
		if err := c.ValidateRun(); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	// collect needs none of it: the plain Validate still accepts no server.
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestScanTimeoutBounds(t *testing.T) {
	if DefaultConfig().Scan.Timeout != 12*time.Hour {
		t.Fatalf("default %s", DefaultConfig().Scan.Timeout)
	}
	for _, d := range []time.Duration{time.Minute, 12 * time.Hour, 72 * time.Hour} {
		c := DefaultConfig()
		c.Scan.Timeout = d
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", d, err)
		}
	}
}

// docs/configuration.md lists every environment variable the agent derives from its configuration, and no other.
func TestConfigurationDocMatchesTheEnvNames(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]bool{}
	for _, m := range regexp.MustCompile("`("+EnvPrefix+"[A-Z0-9_]+)`").FindAllStringSubmatch(string(b), -1) {
		doc[m[1]] = true
	}
	c := DefaultConfig()
	for _, n := range config.EnvNames(&c, EnvPrefix) {
		if !doc[n] {
			t.Errorf("%s is not documented in docs/configuration.md", n)
		}
		delete(doc, n)
	}
	for n := range doc {
		t.Errorf("docs/configuration.md documents %s, which is not an agent setting", n)
	}
}
