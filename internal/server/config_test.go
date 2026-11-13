// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package server

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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
		"CLAMFLEET_SERVER_ALERT_COOLDOWN", "CLAMFLEET_SERVER_ALERT_WEBHOOK_ALLOW_LOOPBACK",
		"CLAMFLEET_SERVER_ALERT_WEBHOOK_ALLOW_PRIVATE", "CLAMFLEET_SERVER_ALERT_WEBHOOK_CA_FILE",
		"CLAMFLEET_SERVER_ALERT_WEBHOOK_DENY_NETWORKS", "CLAMFLEET_SERVER_ALERT_WEBHOOK_TIMEOUT",
		"CLAMFLEET_SERVER_AUTH_COOKIE_SECURE", "CLAMFLEET_SERVER_AUTH_LOCAL_ENABLED",
		"CLAMFLEET_SERVER_AUTH_LOCAL_TOTP_REQUIRED",
		"CLAMFLEET_SERVER_AUTH_SESSION_IDLE", "CLAMFLEET_SERVER_AUTH_SESSION_MAX_AGE",
		"CLAMFLEET_SERVER_DB_PATH",
		"CLAMFLEET_SERVER_HEALTH_BEHIND_WARN", "CLAMFLEET_SERVER_HEALTH_DAILY_CRIT_HOURS",
		"CLAMFLEET_SERVER_HEALTH_DAILY_WARN_HOURS", "CLAMFLEET_SERVER_HEALTH_DEFAULT_INTERVAL",
		"CLAMFLEET_SERVER_HEALTH_EVAL_INTERVAL", "CLAMFLEET_SERVER_HEALTH_SCAN_WARN_HOURS",
		"CLAMFLEET_SERVER_HEALTH_STALE_FACTOR",
		"CLAMFLEET_SERVER_LISTEN", "CLAMFLEET_SERVER_PUBLIC_URL", "CLAMFLEET_SERVER_SECRET_KEY_FILE",
		"CLAMFLEET_SERVER_SMTP_CA_FILE", "CLAMFLEET_SERVER_SMTP_FROM", "CLAMFLEET_SERVER_SMTP_HELO",
		"CLAMFLEET_SERVER_SMTP_HOST", "CLAMFLEET_SERVER_SMTP_PASSWORD_FILE", "CLAMFLEET_SERVER_SMTP_PORT",
		"CLAMFLEET_SERVER_SMTP_TIMEOUT", "CLAMFLEET_SERVER_SMTP_TLS", "CLAMFLEET_SERVER_SMTP_USERNAME",
		"CLAMFLEET_SERVER_TLS_CERT",
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
		{"relative secret_key_file", Config{Listen: ":8443", TLS: TLS{Cert: "/c", Key: "/k"}, DBPath: "/d", SecretKeyFile: "k.key"}, false},
		{"empty secret_key_file", Config{Listen: ":8443", TLS: TLS{Cert: "/c", Key: "/k"}, DBPath: "/d", SecretKeyFile: ""}, false},
		{"absolute secret_key_file", Config{Listen: ":8443", TLS: TLS{Cert: "/c", Key: "/k"}, DBPath: "/d", SecretKeyFile: "/etc/x.key"}, true},
	}
	for _, tc := range cases {
		// A literal without a health block stands for a loaded config, which always has the defaults.
		if tc.c.Health == (Health{}) {
			tc.c.Health = DefaultConfig().Health
		}
		if tc.c.Auth == (Auth{}) {
			tc.c.Auth = DefaultConfig().Auth
		}
		if tc.c.Alert.Webhook.Timeout == 0 {
			tc.c.Alert = DefaultConfig().Alert
		}
		if tc.c.SecretKeyFile == "" && !strings.Contains(tc.name, "secret_key_file") {
			tc.c.SecretKeyFile = DefaultConfig().SecretKeyFile
		}
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

// The spec 9 / plan 4.6 defaults, pinned: they are what an operator gets with no health: block.
func TestHealthDefaults(t *testing.T) {
	h := DefaultConfig().Health
	want := Health{StaleFactor: 3, DefaultInterval: 5 * time.Minute, DailyWarnHours: 24, DailyCritHours: 72,
		BehindWarn: 2, ScanWarnHours: 48, EvalInterval: 60 * time.Second}
	if h != want {
		t.Fatalf("%+v", h)
	}
	if th := h.Thresholds(); th.StaleFactor != 3 || th.DailyCritHours != 72 || th.DefaultInterval != 5*time.Minute || th.ScanWarnHours != 48 || th.BehindWarn != 2 {
		t.Fatalf("%+v", th)
	}
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestHealthValidate(t *testing.T) {
	cases := []struct {
		name string
		mut  func(h *Health)
		bad  string // substring of the error, "" = valid
	}{
		{"stale_factor 2 is the floor", func(h *Health) { h.StaleFactor = 2 }, ""},
		{"stale_factor 1", func(h *Health) { h.StaleFactor = 1 }, "stale_factor"},
		{"default_interval 9s", func(h *Health) { h.DefaultInterval = 9 * time.Second }, "default_interval"},
		{"default_interval 10s", func(h *Health) { h.DefaultInterval = 10 * time.Second }, ""},
		{"default_interval 25h", func(h *Health) { h.DefaultInterval = 25 * time.Hour }, "default_interval"},
		{"daily_warn_hours 0", func(h *Health) { h.DailyWarnHours = 0 }, "daily_warn_hours"},
		{"crit equal to warn", func(h *Health) { h.DailyCritHours = h.DailyWarnHours }, "daily_crit_hours"},
		{"crit below warn", func(h *Health) { h.DailyCritHours = 1 }, "daily_crit_hours"},
		{"behind_warn 0 is valid", func(h *Health) { h.BehindWarn = 0 }, ""},
		{"behind_warn negative", func(h *Health) { h.BehindWarn = -1 }, "behind_warn"},
		{"scan_warn_hours 0 switches off", func(h *Health) { h.ScanWarnHours = 0 }, ""},
		{"scan_warn_hours negative", func(h *Health) { h.ScanWarnHours = -1 }, "scan_warn_hours"},
		{"eval_interval 999ms", func(h *Health) { h.EvalInterval = 999 * time.Millisecond }, "eval_interval"},
		{"eval_interval 1s", func(h *Health) { h.EvalInterval = time.Second }, ""},
		{"eval_interval 61s", func(h *Health) { h.EvalInterval = 61 * time.Second }, "eval_interval"},
	}
	for _, tc := range cases {
		c := DefaultConfig()
		tc.mut(&c.Health)
		err := c.Validate()
		switch {
		case tc.bad == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.bad != "" && (err == nil || !strings.Contains(err.Error(), tc.bad)):
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.bad)
		}
	}
}

// File and environment both reach the health keys; a typo is an error.
func TestHealthKeysFromFileAndEnvironment(t *testing.T) {
	p := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(p, []byte("listen: 127.0.0.1:9000\nhealth: {daily_warn_hours: 100000, daily_crit_hours: 200000, eval_interval: 2s}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := noEnv()
	o.LookupEnv = func(k string) (string, bool) { return "7", k == "CLAMFLEET_SERVER_HEALTH_STALE_FACTOR" }
	c, _, err := LoadConfig(p, true, o)
	if err != nil {
		t.Fatal(err)
	}
	h := c.Health
	if h.DailyWarnHours != 100000 || h.EvalInterval != 2*time.Second || h.StaleFactor != 7 || h.BehindWarn != 2 {
		t.Fatalf("%+v", h)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("health: {stale_factr: 3}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadConfig(p, true, noEnv()); err == nil || !strings.Contains(err.Error(), "stale_factr") {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthDefaultsAndValidation(t *testing.T) {
	c := DefaultConfig()
	if !c.Auth.Local.Enabled || c.Auth.SessionMaxAge != 12*time.Hour || c.Auth.SessionIdle != time.Hour || !c.Auth.CookieSecure {
		t.Fatalf("%+v", c.Auth)
	}
	cases := []struct {
		name string
		mut  func(a *Auth)
		bad  string
	}{
		{"defaults", func(a *Auth) {}, ""},
		{"idle 59s", func(a *Auth) { a.SessionIdle = 59 * time.Second }, "session_idle"},
		{"idle 1m", func(a *Auth) { a.SessionIdle = time.Minute }, ""},
		{"max age below idle", func(a *Auth) { a.SessionMaxAge = 30 * time.Minute }, "session_max_age"},
		{"max age equals idle", func(a *Auth) { a.SessionMaxAge = a.SessionIdle }, ""},
		{"max age 30d", func(a *Auth) { a.SessionMaxAge = 30 * 24 * time.Hour }, ""},
		{"max age over 30d", func(a *Auth) { a.SessionMaxAge = 30*24*time.Hour + time.Second }, "session_max_age"},
	}
	for _, tc := range cases {
		c := DefaultConfig()
		tc.mut(&c.Auth)
		err := c.Validate()
		switch {
		case tc.bad == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.bad != "" && (err == nil || !strings.Contains(err.Error(), tc.bad)):
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.bad)
		}
	}
}

// auth.local.* reaches the config from the file and from the environment.
func TestAuthKeysFromFileAndEnvironment(t *testing.T) {
	p := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(p, []byte("auth: {local: {enabled: false}, session_idle: 30m}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := noEnv()
	o.LookupEnv = func(k string) (string, bool) { return "false", k == "CLAMFLEET_SERVER_AUTH_COOKIE_SECURE" }
	c, _, err := LoadConfig(p, true, o)
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth.Local.Enabled || c.Auth.SessionIdle != 30*time.Minute || c.Auth.CookieSecure || c.Auth.SessionMaxAge != 12*time.Hour {
		t.Fatalf("%+v", c.Auth)
	}
	if err := os.WriteFile(p, []byte("auth: {mode: local}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadConfig(p, true, noEnv()); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("the spec's auth.mode is not a key here (decision 3b); err = %v", err)
	}
}

// The second-factor keys: defaults, the file, and the environment names.
func TestTOTPAndSecretKeyConfig(t *testing.T) {
	c := DefaultConfig()
	if c.Auth.Local.TOTPRequired || c.SecretKeyFile != "/etc/clamfleet/server-secret.key" {
		t.Fatalf("defaults: totp_required=%v secret_key_file=%q", c.Auth.Local.TOTPRequired, c.SecretKeyFile)
	}
	p := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(p, []byte("secret_key_file: /srv/k.key\nauth: {local: {totp_required: true}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _, err := LoadConfig(p, true, noEnv())
	if err != nil || !c.Auth.Local.TOTPRequired || c.SecretKeyFile != "/srv/k.key" || !c.Auth.Local.Enabled {
		t.Fatalf("from file: %+v %v", c, err)
	}
	// The documented environment names override the file.
	o := noEnv()
	env := map[string]string{"CLAMFLEET_SERVER_AUTH_LOCAL_TOTP_REQUIRED": "false", "CLAMFLEET_SERVER_SECRET_KEY_FILE": "/other.key"}
	o.LookupEnv = func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	c, _, err = LoadConfig(p, true, o)
	if err != nil || c.Auth.Local.TOTPRequired || c.SecretKeyFile != "/other.key" {
		t.Fatalf("from env: %+v %v", c, err)
	}
}
