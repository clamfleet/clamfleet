// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package server holds the ClamFleet server: its configuration, the HTTP
// router (NewHandler) and the listener (Serve).
//
// config.go: the server configuration (spec 12, reduced to the keys that
// exist so far). The loader is internal/config, shared with the agent, with
// the prefix CLAMFLEET_SERVER_: both programs may run on one host and must
// not read, or warn about, each other's variables.
package server

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/clamfleet/clamfleet/internal/config"
)

// DefaultConfigPath is used when neither --config nor CLAMFLEET_SERVER_CONFIG is set.
const DefaultConfigPath = "/etc/clamfleet/server.yaml"

// EnvPrefix starts the server's environment overrides. The agent neither
// reads nor warns about it (and the server not about CLAMFLEET_AGENT_*).
const EnvPrefix = "CLAMFLEET_SERVER_"

// Config is the server configuration. The yaml tags are public interface and
// the CLAMFLEET_SERVER_* names derive from them. Only the keys that exist are
// defined: the file is decoded strictly, so a copy of spec 12 with keys of a
// later milestone (retention, smtp) fails until that milestone adds them.
type Config struct {
	Listen string `yaml:"listen"`
	TLS    TLS    `yaml:"tls"`
	DBPath string `yaml:"db_path"`
	// TrustedProxies lists IPs or CIDRs of reverse proxies. Only when the TCP
	// peer is one of them is X-Forwarded-For used for the logged client IP.
	// Empty by default: the header is then ignored.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// TLS configures direct TLS. The intended deployment is plaintext on loopback
// behind a reverse proxy (decision 7); direct TLS is optional.
type TLS struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	// ClientCA, when set, turns on mTLS: every client must present a
	// certificate that chains to this CA bundle. It is a transport requirement
	// only; the bearer token stays mandatory on top of it (decision 11).
	ClientCA string `yaml:"client_ca"`
}

// DefaultConfig returns the defaults: plaintext on loopback, the intended
// deployment behind a reverse proxy (decision 7). Setting tls.cert and tls.key
// turns on direct TLS. db_path departs from spec 12 by
// decision: the server runs as its own user with its own state directory, so
// it never shares an identity or directory with an agent on the same host.
func DefaultConfig() Config {
	return Config{
		Listen:         "127.0.0.1:8443",
		DBPath:         "/var/lib/clamfleet-server/clamfleet.db",
		TrustedProxies: []string{},
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

// TLSEnabled reports whether the server terminates TLS itself.
func (c Config) TLSEnabled() bool { return c.TLS.Cert != "" }

// Validate checks the configuration.
//
// Rule: without TLS the listen address must be loopback (decision 5/7).
// Plaintext is for a local reverse proxy that terminates TLS; a plaintext
// listener on a public interface would carry bearer tokens in clear.
func (c Config) Validate() error {
	if (c.TLS.Cert == "") != (c.TLS.Key == "") {
		return fmt.Errorf("tls.cert and tls.key must be set together (got cert=%q key=%q)", c.TLS.Cert, c.TLS.Key)
	}
	if c.TLS.ClientCA != "" && !c.TLSEnabled() {
		return fmt.Errorf("tls.client_ca needs tls.cert and tls.key: client certificates are verified by this server's own TLS listener, not by a proxy in front of it")
	}
	if !c.TLSEnabled() && !config.IsLoopbackAddr(c.Listen) {
		return fmt.Errorf("listen %q is not a loopback address and tls is off: plaintext is only allowed on loopback behind a reverse proxy; set tls.cert and tls.key, or listen on 127.0.0.1", c.Listen)
	}
	if _, err := ParseTrustedProxies(c.TrustedProxies); err != nil {
		return err
	}
	if c.Listen == "" {
		return fmt.Errorf("listen must not be empty")
	}
	for k, p := range map[string]string{"db_path": c.DBPath} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be an absolute path, got %q", k, p)
		}
	}
	for k, p := range map[string]string{"tls.cert": c.TLS.Cert, "tls.key": c.TLS.Key, "tls.client_ca": c.TLS.ClientCA} {
		if p != "" && !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be an absolute path, got %q", k, p)
		}
	}
	return nil
}

// ParseTrustedProxies turns IP or CIDR strings ("10.0.0.5", "10.0.0.0/8",
// "::1") into prefixes; a bare IP is a single-address prefix. An invalid entry
// is an error (Validate calls this, so the server refuses to start): a typo
// must not silently leave the real proxy untrusted.
func ParseTrustedProxies(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, e := range list {
		e = strings.TrimSpace(e)
		var p netip.Prefix
		var err error
		if strings.Contains(e, "/") {
			p, err = netip.ParsePrefix(e)
			if err == nil && p.Addr().Is4In6() { // checked before Masked: /64 would zero the ::ffff marker
				// A 4in6 CIDR (::ffff:10.0.0.0/104) would never match: peers are
				// unmapped before comparing. Convert it to the IPv4 prefix; a
				// prefix shorter than /96 spans more than IPv4 and is refused.
				if p.Bits() < 96 {
					return nil, fmt.Errorf("trusted_proxies: %q is not an IP address or CIDR this server can match (IPv4-mapped prefixes need at least /96)", e)
				}
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			p = p.Masked()
		} else {
			var a netip.Addr
			if a, err = netip.ParseAddr(e); err == nil {
				a = a.Unmap()
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies: %q is not an IP address or CIDR", e)
		}
		out = append(out, p)
	}
	return out, nil
}
