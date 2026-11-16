// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package agent holds the ClamFleet agent: configuration and the collectors
// that build a proto.Report from the local ClamAV installation.
package agent

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"github.com/clamfleet/clamfleet/internal/config"
)

// DefaultConfigPath is used when neither --config nor CLAMFLEET_AGENT_CONFIG is set.
const DefaultConfigPath = "/etc/clamfleet/agent.yaml"

// EnvPrefix starts the agent's environment overrides. It departs from spec 12
// (plain CLAMFLEET_) by decision: the server gets CLAMFLEET_SERVER_ and both
// may run on one host without reading each other's variables.
const EnvPrefix = "CLAMFLEET_AGENT_"

// Config is the agent configuration (spec 12). The yaml tags are public
// interface; the CLAMFLEET_AGENT_* environment names derive from them (see package
// config). Defaults are those of Debian; deploy/agent.rhel9.yaml.example has
// the RHEL family names.
type Config struct {
	Server       string        `yaml:"server"`
	TokenFile    string        `yaml:"token_file"` // read on every send; only the path lives here so the token cannot be logged
	TLS          TLS           `yaml:"tls"`
	Interval     time.Duration `yaml:"interval"`
	Tags         []string      `yaml:"tags"`
	ClamdConf    string        `yaml:"clamd_conf"`
	DBDir        string        `yaml:"db_dir"`
	FreshclamLog string        `yaml:"freshclam_log"`
	Units        Units         `yaml:"units"`
	Spool        Spool         `yaml:"spool"`
	Scan         Scan          `yaml:"scan"`
}

// TLS is the agent's client certificate for servers that require mTLS
// (server tls.client_ca). Both keys or neither. Optional: the bearer token
// is always sent, the certificate only adds a transport-level requirement.
// A private CA for the server certificate needs no key here: Go reads the
// standard SSL_CERT_FILE / SSL_CERT_DIR environment variables (see README).
type TLS struct {
	ClientCert string `yaml:"client_cert"`
	ClientKey  string `yaml:"client_key"`
}

// Units names the systemd units. An empty name means "not present on this
// host". For Clamd it also means "not managed by systemd": the socket is then
// probed without a unit check (decision Q4); a non-empty name that systemd does
// not know is an error, never a license to probe.
type Units struct {
	Clamd     string `yaml:"clamd"`
	Freshclam string `yaml:"freshclam"`
	Clamonacc string `yaml:"clamonacc"`
}

// Spool configures the on-disk queue. The keys must be set in the config
// FILE: the event command runs as clamd's user with only PATH and two
// variables, so an environment override would reach `run` but not `event`, and
// the two would use different spools.
type Spool struct {
	Dir string `yaml:"dir"`
	// MaxMB is the hard cap on the real disk use of everything under Dir (1-10240).
	MaxMB int `yaml:"max_mb"`
	// MaxEventDays: a spooled event older than this is deleted instead of sent
	// (30-3650). It bounds how long an undeliverable path stays on the host.
	MaxEventDays int `yaml:"max_event_days"`
}

// Bounds of the spool keys.
const (
	MaxSpoolMB            = 10240
	MinSpoolEventDays     = 30
	MaxSpoolEventDays     = 3650
	DefaultSpoolEventDays = 365
)

// Scan configures the scheduled scan wrapper (`clamfleet-agent scan`, milestone 6).
type Scan struct {
	Paths   []string `yaml:"paths"`
	Summary string   `yaml:"summary"`
	// Timeout bounds one scan: when it expires the clamdscan process group is
	// stopped and the summary records exit 2 with the counts so far. Additive key
	// (milestone 6): without it a hung clamdscan would hold the timer's service forever.
	Timeout time.Duration `yaml:"timeout"`
}

// Bounds of scan.timeout.
const (
	MinScanTimeout     = time.Minute
	MaxScanTimeout     = 72 * time.Hour
	DefaultScanTimeout = 12 * time.Hour
)

// DefaultConfig returns the Debian defaults.
func DefaultConfig() Config {
	return Config{
		TokenFile:    "/etc/clamfleet/token",
		Interval:     5 * time.Minute,
		Tags:         []string{},
		ClamdConf:    "/etc/clamav/clamd.conf",
		DBDir:        "/var/lib/clamav",
		FreshclamLog: "/var/log/clamav/freshclam.log",
		Units:        Units{Clamd: "clamav-daemon", Freshclam: "clamav-freshclam", Clamonacc: "clamav-clamonacc"},
		Spool:        Spool{Dir: "/var/lib/clamfleet/spool", MaxMB: 50, MaxEventDays: DefaultSpoolEventDays},
		Scan:         Scan{Paths: []string{}, Summary: "/var/lib/clamfleet/last_scan.json", Timeout: DefaultScanTimeout},
	}
}

// LoadConfig builds the configuration from defaults, the YAML file at path
// and the environment (see config.Load). explicit says whether the user chose
// the path. It returns non-fatal warnings for the caller to log.
func LoadConfig(path string, explicit bool, o config.Options) (Config, []string, error) {
	c := DefaultConfig()
	o.Path, o.Explicit, o.EnvPrefix = path, explicit, EnvPrefix
	w, err := config.Load(&c, o)
	return c, w, err
}

// Validate checks the values collect needs. The server is not required
// here: only `run` needs it (ValidateRun).
func (c Config) Validate() error {
	if c.Interval <= 0 {
		return fmt.Errorf("interval must be positive, got %s", c.Interval)
	}
	if c.Spool.MaxMB < 1 || c.Spool.MaxMB > MaxSpoolMB {
		return fmt.Errorf("spool.max_mb must be between 1 and %d, got %d", MaxSpoolMB, c.Spool.MaxMB)
	}
	if c.Spool.MaxEventDays < MinSpoolEventDays || c.Spool.MaxEventDays > MaxSpoolEventDays {
		return fmt.Errorf("spool.max_event_days must be between %d and %d, got %d", MinSpoolEventDays, MaxSpoolEventDays, c.Spool.MaxEventDays)
	}
	if c.Scan.Timeout < MinScanTimeout || c.Scan.Timeout > MaxScanTimeout {
		return fmt.Errorf("scan.timeout must be between %s and %s, got %s", MinScanTimeout, MaxScanTimeout, c.Scan.Timeout)
	}
	paths := map[string]string{
		"token_file": c.TokenFile, "clamd_conf": c.ClamdConf, "db_dir": c.DBDir,
		"freshclam_log": c.FreshclamLog, "spool.dir": c.Spool.Dir, "scan.summary": c.Scan.Summary,
	}
	for i, p := range c.Scan.Paths {
		paths[fmt.Sprintf("scan.paths[%d]", i)] = p
	}
	for k, p := range paths {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be an absolute path, got %q", k, p)
		}
	}
	return nil
}

// ValidateRun checks what `run` needs on top of Validate: a server URL and a
// coherent TLS client pair.
//
// Rule: the server URL must be https, or http only to a loopback host (an
// agent on the same machine as a plaintext server behind nothing else, or a
// test). A bearer token must never cross a network in clear. The URL may
// carry a path prefix (reverse proxy) but no credentials: a user:password in
// a URL would end up in logs and error messages.
func (c Config) ValidateRun() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Server == "" {
		return errors.New("server is required to send reports (set server in the config or CLAMFLEET_AGENT_SERVER)")
	}
	u, err := url.Parse(c.Server)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("server %q is not a valid URL (want https://host[:port][/prefix])", c.Server)
	}
	switch {
	case u.User != nil:
		return errors.New("server must not contain credentials: the token comes from token_file")
	case u.RawQuery != "" || u.Fragment != "":
		return errors.New("server must not contain a query or fragment")
	case u.Scheme == "https":
	case u.Scheme == "http" && config.IsLoopbackHost(u.Hostname()):
	case u.Scheme == "http":
		return fmt.Errorf("server %q uses plain http to a non-loopback host: the token would travel in clear; use https", c.Server)
	default:
		return fmt.Errorf("server %q: scheme must be https", c.Server)
	}
	if (c.TLS.ClientCert == "") != (c.TLS.ClientKey == "") {
		return errors.New("tls.client_cert and tls.client_key must be set together")
	}
	for k, p := range map[string]string{"tls.client_cert": c.TLS.ClientCert, "tls.client_key": c.TLS.ClientKey} {
		if p != "" && !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be an absolute path, got %q", k, p)
		}
	}
	return nil
}
