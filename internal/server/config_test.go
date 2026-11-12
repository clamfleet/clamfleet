// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package server

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/clamfleet/clamfleet/internal/config"
)

func noEnv() config.Options {
	return config.Options{
		LookupEnv: func(string) (string, bool) { return "", false },
		Environ:   func() []string { return nil },
	}
}

// The env names are public interface (README table).
func TestEnvNamesMatchDocumentedTable(t *testing.T) {
	c := DefaultConfig()
	want := []string{
		"CLAMFLEET_SERVER_DB_PATH", "CLAMFLEET_SERVER_LISTEN", "CLAMFLEET_SERVER_TLS_CERT",
		"CLAMFLEET_SERVER_TLS_CLIENT_CA", "CLAMFLEET_SERVER_TLS_KEY", "CLAMFLEET_SERVER_TRUSTED_PROXIES",
	}
	if got := config.EnvNames(&c, EnvPrefix); !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

// Both programs may share a host: the server must not warn about the agent's variables.
func TestAgentEnvironmentIsIgnoredSilently(t *testing.T) {
	o := noEnv()
	o.Environ = func() []string { return []string{"CLAMFLEET_AGENT_SERVER=https://x", "CLAMFLEET_AGENT_INTERVAL=1m"} }
	_, warnings, err := LoadConfig("", false, o)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("warnings %v err %v", warnings, err)
	}
	// ...but a typo with the server prefix is still reported.
	o.Environ = func() []string { return []string{"CLAMFLEET_SERVER_LISTN=:1"} }
	if _, warnings, _ = LoadConfig("", false, o); len(warnings) != 1 {
		t.Fatalf("warnings %v", warnings)
	}
}

func TestDefaultsArePlaintextOnLoopback(t *testing.T) {
	c := DefaultConfig()
	if c.TLSEnabled() || c.Listen != "127.0.0.1:8443" || c.DBPath != "/var/lib/clamfleet-server/clamfleet.db" {
		t.Fatalf("%+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidate(t *testing.T) {
	plain := func(listen string) Config {
		c := DefaultConfig()
		c.TLS = TLS{}
		c.Listen = listen
		return c
	}
	cases := []struct {
		name string
		c    Config
		ok   bool
	}{
		{"plaintext on :8443", plain(":8443"), false},
		{"plaintext on 0.0.0.0", plain("0.0.0.0:8443"), false},
		{"plaintext on a LAN address", plain("10.1.2.3:8443"), false},
		{"plaintext on 127.0.0.1:0", plain("127.0.0.1:0"), true},
		{"plaintext on ::1", plain("[::1]:8443"), true},
		{"empty listen", plain(""), false},
		{"cert without key", Config{Listen: ":8443", TLS: TLS{Cert: "/c"}, DBPath: "/d"}, false},
		{"key without cert", Config{Listen: "127.0.0.1:1", TLS: TLS{Key: "/k"}, DBPath: "/d"}, false},
		{"tls on a public address", Config{Listen: ":8443", TLS: TLS{Cert: "/c", Key: "/k"}, DBPath: "/d"}, true},
		{"client_ca with tls", Config{Listen: ":8443", TLS: TLS{Cert: "/c", Key: "/k", ClientCA: "/ca"}, DBPath: "/d"}, true},
		{"client_ca without tls", Config{Listen: "127.0.0.1:1", TLS: TLS{ClientCA: "/ca"}, DBPath: "/d"}, false},
		{"relative db_path", Config{Listen: ":8443", TLS: TLS{Cert: "/c", Key: "/k"}, DBPath: "db"}, false},
		{"relative cert", Config{Listen: ":8443", TLS: TLS{Cert: "c", Key: "/k"}, DBPath: "/d"}, false},
		{"relative client_ca", Config{Listen: ":8443", TLS: TLS{Cert: "/c", Key: "/k", ClientCA: "ca"}, DBPath: "/d"}, false},
	}
	for _, tc := range cases {
		if err := tc.c.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestEnvOverridesFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(p, []byte("listen: 127.0.0.1:9000\ntls: {cert: '', key: ''}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := noEnv()
	o.LookupEnv = func(k string) (string, bool) { return "/x/db", k == "CLAMFLEET_SERVER_DB_PATH" }
	c, _, err := LoadConfig(p, true, o)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:9000" || c.DBPath != "/x/db" || c.TLSEnabled() {
		t.Fatalf("%+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

// A copy of spec 12 with keys of a later milestone must fail loudly, not be ignored.
func TestUnknownKeyIsAnError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(p, []byte("listen: 127.0.0.1:1\nretention: {reports_days: 90}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadConfig(p, true, noEnv()); err == nil || !strings.Contains(err.Error(), "retention") {
		t.Fatalf("err = %v", err)
	}
}

// The shipped configs must stay loadable under strict decoding, or the first
// user (or the e2e suite) to use one gets an error.
func TestExampleConfigsLoadAndValidate(t *testing.T) {
	for _, f := range []string{"server.yaml.example", "test/server.yaml"} {
		c, _, err := LoadConfig(filepath.Join("..", "..", "deploy", f), true, noEnv())
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
}

func TestTrustedProxies(t *testing.T) {
	good := []string{"10.0.0.5", "10.0.0.0/8", "::1", "fd00::/8", " 192.168.1.1 ", "::ffff:10.1.2.3", "::ffff:10.0.0.0/104"}
	ps, err := ParseTrustedProxies(good)
	if err != nil || len(ps) != len(good) {
		t.Fatalf("%v %v", ps, err)
	}
	if ps[0].String() != "10.0.0.5/32" || ps[5].String() != "10.1.2.3/32" || ps[6].String() != "10.0.0.0/8" {
		t.Fatalf("%v", ps)
	}
	for _, bad := range []string{"nope", "10.0.0.0/33", "10.0.0.256", "10.0.0.0/", "1.2.3.4/x", "", "::ffff:10.0.0.0/64"} {
		c := DefaultConfig()
		c.TrustedProxies = []string{"127.0.0.1", bad}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "trusted_proxies") {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	if len(DefaultConfig().TrustedProxies) != 0 {
		t.Fatal("trusted_proxies must default to empty")
	}
	// Environment override: comma separated, like every list key of the loader.
	o := noEnv()
	o.LookupEnv = func(k string) (string, bool) { return "10.0.0.0/8, 127.0.0.1", k == "CLAMFLEET_SERVER_TRUSTED_PROXIES" }
	c, _, err := LoadConfig("", false, o)
	if err != nil || len(c.TrustedProxies) != 2 || c.Validate() != nil {
		t.Fatalf("%+v %v", c.TrustedProxies, err)
	}
}
