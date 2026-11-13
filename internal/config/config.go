// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package config loads a YAML file into a struct and applies environment
// overrides to it. It is generic so the server (Milestone 2) can reuse it with
// its own struct and its own prefix: the caller passes the prefix
// (CLAMFLEET_AGENT_, later CLAMFLEET_SERVER_) because both programs may run on
// one host and must not read, or warn about, each other's variables.
//
// Precedence, lowest to highest: defaults (the values already in the struct),
// the YAML file, environment variables. Command-line flags are applied by the
// caller afterwards.
//
// Dependency: go.yaml.in/yaml/v3, the maintained continuation of the
// unmaintained gopkg.in/yaml.v3 (the spec names the latter; decision Q2).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"go.yaml.in/yaml/v3"
)

// envConfigSuffix, appended to a prefix, names the variable that selects the
// config file (CLAMFLEET_AGENT_CONFIG). It is reserved: it is not a config key,
// so it is never reported as an unknown variable.
const envConfigSuffix = "CONFIG"

// Options controls Load. The zero value reads nothing from the file system
// and uses the real environment.
type Options struct {
	// EnvPrefix starts every environment override of this program, e.g.
	// "CLAMFLEET_AGENT_". Required: an empty prefix would turn every variable of
	// the host into a config key, so Load refuses it.
	EnvPrefix string
	// Path of the YAML file; "" means no file.
	Path string
	// Explicit is true when the user chose Path (flag or <prefix>CONFIG).
	// A missing explicit file is an error; a missing default file only warns.
	Explicit bool
	// LookupEnv and Environ default to os.LookupEnv and os.Environ. Tests inject them.
	LookupEnv func(string) (string, bool)
	Environ   func() []string
	// ReadFile defaults to os.ReadFile. Tests inject it to prove which files a
	// command opens (the agent's event command must never touch the token).
	ReadFile func(string) ([]byte, error)
}

// ResolvePath picks the config path: the flag value, else
// <prefix>CONFIG, else def. explicit reports whether the user chose it.
func ResolvePath(prefix, flagValue, def string, lookup func(string) (string, bool)) (path string, explicit bool) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	if flagValue != "" {
		return flagValue, true
	}
	if v, ok := lookup(prefix + envConfigSuffix); ok && v != "" {
		return v, true
	}
	return def, false
}

// Load fills cfg (a pointer to a struct that already holds the defaults)
// from the file and then from the environment. It returns non-fatal warnings
// (missing default file, unknown variables with the prefix). Errors name the file
// or the variable at fault. The file is decoded strictly: an unknown key is an
// error, so a typo fails loudly instead of silently using a default
// (assumption A4; the cost is that an old agent rejects a newer key).
func Load(cfg any, o Options) (warnings []string, err error) {
	if o.EnvPrefix == "" {
		return nil, errors.New("config: Options.EnvPrefix is required")
	}
	if o.LookupEnv == nil {
		o.LookupEnv = os.LookupEnv
	}
	if o.Environ == nil {
		o.Environ = os.Environ
	}
	if o.ReadFile == nil {
		o.ReadFile = os.ReadFile
	}
	if o.Path != "" {
		raw, rerr := o.ReadFile(o.Path)
		switch {
		case rerr == nil:
			if err := decodeStrict(raw, cfg); err != nil {
				return warnings, fmt.Errorf("config %s: %w", o.Path, err)
			}
		case errors.Is(rerr, fs.ErrNotExist) && !o.Explicit:
			warnings = append(warnings, fmt.Sprintf("config file %s not found, using defaults", o.Path))
		default:
			return warnings, fmt.Errorf("config: %w", rerr)
		}
	}
	w, err := applyEnv(cfg, o.EnvPrefix, o.LookupEnv, o.Environ)
	return append(warnings, w...), err
}

func decodeStrict(raw []byte, cfg any) error {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	// io.EOF means an empty (or comment-only) file: keep the defaults.
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
