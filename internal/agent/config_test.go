// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"os"
	"path/filepath"
	"reflect"
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
		"CLAMFLEET_AGENT_SCAN_PATHS", "CLAMFLEET_AGENT_SCAN_SUMMARY", "CLAMFLEET_AGENT_SERVER",
		"CLAMFLEET_AGENT_SPOOL_DIR", "CLAMFLEET_AGENT_SPOOL_MAX_MB", "CLAMFLEET_AGENT_TAGS", "CLAMFLEET_AGENT_TOKEN_FILE",
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
		"zero interval":  func(c *Config) { c.Interval = 0 },
		"zero max_mb":    func(c *Config) { c.Spool.MaxMB = 0 },
		"relative db":    func(c *Config) { c.DBDir = "var/lib/clamav" },
		"relative scan":  func(c *Config) { c.Scan.Paths = []string{"srv"} },
		"relative clamd": func(c *Config) { c.ClamdConf = "clamd.conf" },
	} {
		c := DefaultConfig()
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
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
