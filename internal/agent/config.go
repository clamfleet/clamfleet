// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package agent holds the ClamFleet agent: configuration and the collectors
// that build a proto.Report from the local ClamAV installation.
package agent

import (
	"fmt"
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
	TokenFile    string        `yaml:"token_file"` // read from Milestone 2 on; only the path lives here so the token cannot be logged
	Interval     time.Duration `yaml:"interval"`
	Tags         []string      `yaml:"tags"`
	ClamdConf    string        `yaml:"clamd_conf"`
	DBDir        string        `yaml:"db_dir"`
	FreshclamLog string        `yaml:"freshclam_log"`
	Units        Units         `yaml:"units"`
	Spool        Spool         `yaml:"spool"`
	Scan         Scan          `yaml:"scan"`
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

// Spool configures the on-disk queue (used from Milestone 5).
type Spool struct {
	Dir   string `yaml:"dir"`
	MaxMB int    `yaml:"max_mb"`
}

// Scan configures the scheduled scan wrapper (used from a later milestone).
type Scan struct {
	Paths   []string `yaml:"paths"`
	Summary string   `yaml:"summary"`
}

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
		Spool:        Spool{Dir: "/var/lib/clamfleet/spool", MaxMB: 50},
		Scan:         Scan{Paths: []string{}, Summary: "/var/lib/clamfleet/last_scan.json"},
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

// Validate checks the values collect needs. The server and token_file are
// not required: only `run` (Milestone 2) needs them.
func (c Config) Validate() error {
	if c.Interval <= 0 {
		return fmt.Errorf("interval must be positive, got %s", c.Interval)
	}
	if c.Spool.MaxMB <= 0 {
		return fmt.Errorf("spool.max_mb must be positive, got %d", c.Spool.MaxMB)
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
