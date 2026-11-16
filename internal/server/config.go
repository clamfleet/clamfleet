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
	"net/mail"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/clamfleet/clamfleet/internal/alert"
	"github.com/clamfleet/clamfleet/internal/config"
	"github.com/clamfleet/clamfleet/internal/health"
	"github.com/clamfleet/clamfleet/internal/secrets"
	"github.com/clamfleet/clamfleet/internal/store"
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
	Health         Health   `yaml:"health"`
	Auth           Auth     `yaml:"auth"`
	// SecretKeyFile holds the key that protects secrets at rest (TOTP secrets;
	// webhook secrets in M4); see internal/secrets. It lives outside the state
	// directory on purpose: a backup of the database must not carry the key.
	// Intended ownership: root:clamfleet-server mode 0640. Absolute path.
	SecretKeyFile string `yaml:"secret_key_file"`
	// PublicURL is the address of the console as people reach it
	// ("https://clamfleet.example"), used for links in alerts only (M4 decision
	// 12). Empty: alert links are null. No path prefix support in the console.
	PublicURL string    `yaml:"public_url"`
	Alert     Alert     `yaml:"alert"`
	SMTP      SMTP      `yaml:"smtp"`
	Retention Retention `yaml:"retention"`
	Backup    Backup    `yaml:"backup"`
	Metrics   Metrics   `yaml:"metrics"`
}

// Backup configures `clamfleet-server backup` and the automatic backup before a
// migration (milestone 6, plan 4.4 and 4.5).
type Backup struct {
	// Dir holds the backups: absolute, a real directory owned by the server user
	// with mode 0700 (the command checks it). It defaults under the state directory.
	Dir string `yaml:"dir"`
	// Keep is how many regular backups `backup` leaves (0 = keep every backup).
	// Pre-migration backups are kept separately: the newest 3.
	Keep int `yaml:"keep"`
}

// packagedStateDir is the directory the packaged unit makes writable (StateDirectory=clamfleet-server).
const packagedStateDir = "/var/lib/clamfleet-server"

// Warnings returns non-fatal configuration problems for the caller to log. Today: a backup.dir
// outside the state directory. The packaged unit has ProtectSystem=strict, so such a directory is
// read-only for the service and for the backup timer unless a drop-in adds it to ReadWritePaths=;
// without it the daily backup fails and so does the backup before a migration (the next upgrade
// that brings one would refuse to start).
func (c Config) Warnings() []string {
	var w []string
	d := filepath.Clean(c.Backup.Dir)
	if d != packagedStateDir && !strings.HasPrefix(d, packagedStateDir+"/") {
		w = append(w, fmt.Sprintf("backup.dir %s is outside %s: under the packaged systemd units (ProtectSystem=strict) it is read-only unless a drop-in adds ReadWritePaths=%s; see docs/operations.md", d, packagedStateDir, d))
	}
	return w
}

// Bounds of backup.keep.
const (
	MaxBackupKeep     = 365
	DefaultBackupKeep = 7
	// DefaultBackupDir is inside the state directory, which is 0700 for the server user.
	DefaultBackupDir = "/var/lib/clamfleet-server/backups"
)

// Validate checks the backup keys.
func (b Backup) Validate() error {
	if !filepath.IsAbs(b.Dir) {
		return fmt.Errorf("backup.dir must be an absolute path, got %q", b.Dir)
	}
	if b.Keep < 0 || b.Keep > MaxBackupKeep {
		return fmt.Errorf("backup.keep must be between 0 (keep every backup) and %d, got %d", MaxBackupKeep, b.Keep)
	}
	return nil
}

// Retention says how long data is kept, in days, per table (spec 8.2; plan
// docs/plans/milestone-6.md 4.3). Every key counts from ARRIVAL on the server
// clock (received_at or ts of the server's own rows), never from the agent's
// clock: a spooled event or report can be old when it arrives.
type Retention struct {
	// ReportsDays: heartbeat reports. The fleet page does not depend on them
	// (hosts.last_report and hosts.state live on the host row).
	ReportsDays int `yaml:"reports_days"`
	// EventsDays: events (and, by cascade, their receipts, window membership and
	// alert rows). A file path is personal data, so this is also how long paths
	// live here. An event whose alert is unfinished, or held in an open detection
	// window, is kept until that is over.
	EventsDays int `yaml:"events_days"`
	// StateChangesDays: health state history. One whose alert is still pending is kept.
	StateChangesDays int `yaml:"state_changes_days"`
	// AlertLogDays: the alert attempt log, finished deliveries and closed
	// detection windows (the M4 constant alert.Retention, now configurable).
	AlertLogDays int `yaml:"alert_log_days"`
	// AuditDays: the audit log. Audit rows hold emails and client IPs (personal
	// data), and a security log still needs a bound.
	AuditDays int `yaml:"audit_days"`
}

// Defaults and bounds of the retention keys (plan 4.3).
const (
	MinReportsDays, MaxReportsDays, DefaultReportsDays                = 14, 90, 30
	MinEventsDays, MaxEventsDays, DefaultEventsDays                   = 7, 3650, 365
	MinStateChangesDays, MaxStateChangesDays, DefaultStateChangesDays = 30, 3650, 365
	MinAlertLogDays, MaxAlertLogDays, DefaultAlertLogDays             = 30, 3650, 90
	MinAuditDays, MaxAuditDays, DefaultAuditDays                      = 90, 3650, 365
)

// DefaultRetention returns the defaults of every retention key.
func DefaultRetention() Retention {
	return Retention{
		ReportsDays: DefaultReportsDays, EventsDays: DefaultEventsDays, StateChangesDays: DefaultStateChangesDays,
		AlertLogDays: DefaultAlertLogDays, AuditDays: DefaultAuditDays,
	}
}

// Validate checks every retention key against its bounds, so a typo cannot
// delete history at once (a day count of 0) or keep personal data for centuries.
func (r Retention) Validate() error {
	for _, k := range []struct {
		key         string
		v, min, max int
	}{
		{"reports_days", r.ReportsDays, MinReportsDays, MaxReportsDays},
		{"events_days", r.EventsDays, MinEventsDays, MaxEventsDays},
		{"state_changes_days", r.StateChangesDays, MinStateChangesDays, MaxStateChangesDays},
		{"alert_log_days", r.AlertLogDays, MinAlertLogDays, MaxAlertLogDays},
		{"audit_days", r.AuditDays, MinAuditDays, MaxAuditDays},
	} {
		if k.v < k.min || k.v > k.max {
			return fmt.Errorf("retention.%s must be between %d and %d, got %d", k.key, k.min, k.max, k.v)
		}
	}
	return nil
}

// Alert configures alert delivery (docs/plans/milestone-4.md 4.9).
type Alert struct {
	// Cooldown: at most one state alert per host per target per window; changes
	// inside it are held and summarised at its end. 0 turns holds off.
	Cooldown time.Duration `yaml:"cooldown"`
	Webhook  AlertWebhook  `yaml:"webhook"`
}

// AlertWebhook is the webhook destination policy (SSRF, plan 4.7) and timeout.
type AlertWebhook struct {
	// Timeout bounds one attempt, from the claim.
	Timeout time.Duration `yaml:"timeout"`
	// AllowPrivate: RFC 1918, 100.64.0.0/10 and fc00::/7 (and plaintext to them).
	AllowPrivate bool `yaml:"allow_private"`
	// AllowLoopback: 127.0.0.0/8, ::1 and the localhost names.
	AllowLoopback bool `yaml:"allow_loopback"`
	// DenyNetworks are extra CIDRs that are always blocked.
	DenyNetworks []string `yaml:"deny_networks"`
	// CAFile adds trust anchors (PEM) to the system roots.
	CAFile string `yaml:"ca_file"`
	// NAT64Prefixes are the operator's own NAT64 translation prefixes (/32, /40,
	// /48, /56, /64 or /96, RFC 6052). An address under one is judged by the IPv4
	// it carries, like the well-known 64:ff9b::/96. A local-use NAT64 address
	// (64:ff9b:1::/48) of a translator that is not listed is blocked, because the
	// destination cannot be known. It also applies to the SMTP relay.
	NAT64Prefixes []string `yaml:"nat64_prefixes"`
}

// SMTP configures email alerts; an empty Host switches email off.
type SMTP struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	// TLS is starttls (default, mandatory once chosen: no fallback to plaintext),
	// tls (implicit, port 465) or none (decision 19: only to a relay on a
	// loopback or private address, and never with credentials beyond loopback).
	TLS      string `yaml:"tls"`
	From     string `yaml:"from"`
	Username string `yaml:"username"`
	// PasswordFile holds the password (never YAML or environment: one secret
	// store, file-based). Read once at start under the key-file permission rule.
	PasswordFile string `yaml:"password_file"`
	// Helo is the name announced in EHLO; empty = the host of public_url, else
	// os.Hostname(), else localhost.
	Helo    string        `yaml:"helo"`
	CAFile  string        `yaml:"ca_file"`
	Timeout time.Duration `yaml:"timeout"`
}

// validateAlerting checks public_url, alert.* and smtp.*. Files are not read here
// (Validate does no I/O); serve checks password_file and the CA files.
func (c Config) validateAlerting() error {
	if c.PublicURL != "" {
		u, err := url.Parse(c.PublicURL)
		switch {
		case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
			return fmt.Errorf("public_url must be an absolute http or https URL such as https://clamfleet.example")
		case u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(c.PublicURL, "?#"):
			return fmt.Errorf("public_url must not contain a user name, query or fragment")
		}
	}
	a := c.Alert
	if a.Cooldown < 0 || a.Cooldown > 24*time.Hour {
		return fmt.Errorf("alert.cooldown must be between 0 and 24h, got %s", a.Cooldown)
	}
	if a.Webhook.Timeout < time.Second || a.Webhook.Timeout > 30*time.Second {
		return fmt.Errorf("alert.webhook.timeout must be between 1s and 30s, got %s", a.Webhook.Timeout)
	}
	if _, err := ParseDenyNetworks(a.Webhook.DenyNetworks); err != nil {
		return err
	}
	nat64, err := ParseNAT64Prefixes(a.Webhook.NAT64Prefixes)
	if err != nil {
		return err
	}
	if a.Webhook.CAFile != "" && !filepath.IsAbs(a.Webhook.CAFile) {
		return fmt.Errorf("alert.webhook.ca_file must be an absolute path, got %q", a.Webhook.CAFile)
	}

	m := c.SMTP
	if m.Host == "" {
		return nil
	}
	if m.Port < 1 || m.Port > 65535 {
		return fmt.Errorf("smtp.port must be between 1 and 65535, got %d", m.Port)
	}
	if m.TLS != "starttls" && m.TLS != "tls" && m.TLS != "none" {
		return fmt.Errorf("smtp.tls must be starttls, tls or none, got %q", m.TLS)
	}
	if m.From == "" {
		return fmt.Errorf("smtp.from is required when smtp.host is set")
	}
	if addr, err := mail.ParseAddress(m.From); err != nil || strings.ContainsAny(m.From, "\r\n") || addr.Address == "" {
		return fmt.Errorf("smtp.from is not a valid email address")
	}
	if m.Username != "" && m.PasswordFile == "" {
		return fmt.Errorf("smtp.password_file is required when smtp.username is set (the password is never read from YAML or the environment)")
	}
	if m.Username == "" && m.PasswordFile != "" {
		return fmt.Errorf("smtp.password_file needs smtp.username")
	}
	for k, p := range map[string]string{"smtp.password_file": m.PasswordFile, "smtp.ca_file": m.CAFile} {
		if p != "" && !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be an absolute path, got %q", k, p)
		}
	}
	if m.Timeout < 5*time.Second || m.Timeout > 120*time.Second {
		return fmt.Errorf("smtp.timeout must be between 5s and 120s, got %s", m.Timeout)
	}
	if m.TLS == "none" {
		// Decision 19. An IP literal can be checked now; a host name is checked at
		// dial, on the address it resolves to.
		if ip, err := netip.ParseAddr(strings.Trim(m.Host, "[]")); err == nil {
			ip = ip.Unmap()
			// The same classification as the dialer: a NAT64 form of a public IPv4
			// address is public, and a deprecated embedding cannot be judged at all.
			if err := (alert.Policy{NAT64Prefixes: nat64}).CheckPlaintext(ip); err != nil {
				return fmt.Errorf("smtp.tls: none is only allowed for a relay on a loopback or private address, and %s is public or cannot be judged (%v): use starttls or tls", ip, err)
			}
			if m.Username != "" && !ip.IsLoopback() {
				return fmt.Errorf("smtp.tls: none with smtp.username would send the password in clear to %s: credentials are only sent unencrypted to loopback; use starttls or tls", ip)
			}
		} else if m.Username != "" && !config.IsLoopbackHost(m.Host) {
			return fmt.Errorf("smtp.tls: none with smtp.username would send the password in clear to %q: credentials are only sent unencrypted to loopback; use starttls or tls", m.Host)
		}
	}
	return nil
}

// ParseNAT64Prefixes parses alert.webhook.nat64_prefixes: IPv6 prefixes of an
// RFC 6052 length whose bits 64-71 (the "u" octet) are zero. An invalid entry is
// an error (Validate calls this): a typo must not silently leave a translator undecoded.
func ParseNAT64Prefixes(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, e := range list {
		p, err := netip.ParsePrefix(strings.TrimSpace(e))
		switch {
		case err != nil || p.Addr().Is4() || p.Addr().Is4In6():
			return nil, fmt.Errorf("alert.webhook.nat64_prefixes: %q is not an IPv6 prefix such as 64:ff9b:1::/96", e)
		case !alert.ValidNAT64Length(p.Bits()):
			return nil, fmt.Errorf("alert.webhook.nat64_prefixes: %q has length /%d, but RFC 6052 allows only /32, /40, /48, /56, /64 and /96", e, p.Bits())
		case p.Bits() > 64 && p.Addr().As16()[8] != 0:
			return nil, fmt.Errorf("alert.webhook.nat64_prefixes: %q sets bits 64-71, which RFC 6052 reserves as zero", e)
		case p != p.Masked():
			return nil, fmt.Errorf("alert.webhook.nat64_prefixes: %q has bits set beyond its length (did you mean %s?)", e, p.Masked())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// ParseDenyNetworks parses alert.webhook.deny_networks. An invalid entry is an
// error (Validate calls this): a typo must not silently leave a network allowed.
func ParseDenyNetworks(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, e := range list {
		e = strings.TrimSpace(e)
		p, err := netip.ParsePrefix(e)
		if err != nil {
			a, aerr := netip.ParseAddr(e)
			if aerr != nil {
				return nil, fmt.Errorf("alert.webhook.deny_networks: %q is not an IP address or CIDR", e)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return nil, fmt.Errorf("alert.webhook.deny_networks: %q is not an IP address or CIDR this server can match (IPv4-mapped prefixes need at least /96)", e)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// PublicBase is public_url without a trailing slash.
func (c Config) PublicBase() string { return strings.TrimRight(c.PublicURL, "/") }

// Auth configures console sign-in (docs/plans/milestone-3.md 4.4, 4.6). The
// shape is one subtree per provider, so local accounts, LDAP and OIDC can be
// on at the same time later (M6): a local break-glass admin next to SSO.
type Auth struct {
	Local AuthLocal `yaml:"local"`
	// SessionMaxAge is the absolute lifetime of a session; SessionIdle ends it
	// after that long without a request (htmx polls count as activity, so an open
	// fleet tab stays signed in until SessionMaxAge).
	SessionMaxAge time.Duration `yaml:"session_max_age"`
	SessionIdle   time.Duration `yaml:"session_idle"`
	// CookieSecure false drops the Secure flag and the __Host- cookie prefix.
	// It exists only for plain-HTTP development (an SSH tunnel); the server
	// logs a warning at start when it is off.
	CookieSecure bool `yaml:"cookie_secure"`
}

// AuthLocal configures email + password accounts.
type AuthLocal struct {
	Enabled bool `yaml:"enabled"`
	// TOTPRequired makes every local user enrol a TOTP authenticator: a user
	// without one can reach only the enrolment pages until they have. Trust on
	// first use: until a user has enrolled, their password alone can enrol (docs/web.md).
	// Turning it on needs a usable secret_key_file (the server refuses to start without).
	TOTPRequired bool `yaml:"totp_required"`
}

// EnabledSources is the set of identity sources switched on in this configuration,
// which is what may hold a console session (webauth.Manager.Sources). A provider that
// is switched off ends its users' sessions at their next request.
func (a Auth) EnabledSources() map[string]bool {
	return map[string]bool{store.AuthLocal: a.Local.Enabled}
}

// Validate checks the auth keys. The bounds keep a typo from creating sessions
// that never expire or that expire before a page has loaded.
func (a Auth) Validate() error {
	switch {
	case a.SessionIdle < time.Minute:
		return fmt.Errorf("auth.session_idle must be at least 1m, got %s", a.SessionIdle)
	case a.SessionMaxAge < a.SessionIdle:
		return fmt.Errorf("auth.session_max_age (%s) must not be shorter than auth.session_idle (%s)", a.SessionMaxAge, a.SessionIdle)
	case a.SessionMaxAge > 30*24*time.Hour:
		return fmt.Errorf("auth.session_max_age must be at most 720h (30 days), got %s", a.SessionMaxAge)
	}
	return nil
}

// Health holds the thresholds of the health rules (spec 9) and how often the
// evaluator runs. The key names follow spec 12; default_interval and
// eval_interval are additions (docs/plans/milestone-3.md 4.6): the first is
// the fallback for agents that do not report their interval, the second lets
// the e2e test see STALE in seconds.
type Health struct {
	StaleFactor     int           `yaml:"stale_factor"`
	DefaultInterval time.Duration `yaml:"default_interval"`
	DailyWarnHours  int           `yaml:"daily_warn_hours"`
	DailyCritHours  int           `yaml:"daily_crit_hours"`
	BehindWarn      int           `yaml:"behind_warn"`
	ScanWarnHours   int           `yaml:"scan_warn_hours"` // 0 switches the scan_missed rule off
	EvalInterval    time.Duration `yaml:"eval_interval"`
	// RequireVirusEvent: WARN (virusevent_missing) for a host whose clamd.conf
	// has no VirusEvent line. Switch it off for hosts that are scanned only on a schedule.
	RequireVirusEvent bool `yaml:"require_virus_event"`
}

// Thresholds converts the configuration for the rules.
func (h Health) Thresholds() health.Thresholds {
	return health.Thresholds{
		StaleFactor: h.StaleFactor, DefaultInterval: h.DefaultInterval,
		DailyWarnHours: h.DailyWarnHours, DailyCritHours: h.DailyCritHours,
		BehindWarn: h.BehindWarn, ScanWarnHours: h.ScanWarnHours,
		RequireVirusEvent: h.RequireVirusEvent,
	}
}

// Validate checks the health keys. The floors keep a typo from producing a
// fleet that is permanently STALE or never STALE.
func (h Health) Validate() error {
	switch {
	case h.StaleFactor < 2:
		return fmt.Errorf("health.stale_factor must be at least 2 (one late report must not make a host STALE), got %d", h.StaleFactor)
	case h.DefaultInterval < 10*time.Second || h.DefaultInterval > 24*time.Hour:
		return fmt.Errorf("health.default_interval must be between 10s and 24h, got %s", h.DefaultInterval)
	case h.DailyWarnHours < 1:
		return fmt.Errorf("health.daily_warn_hours must be at least 1, got %d", h.DailyWarnHours)
	case h.DailyCritHours <= h.DailyWarnHours:
		return fmt.Errorf("health.daily_crit_hours (%d) must be greater than health.daily_warn_hours (%d)", h.DailyCritHours, h.DailyWarnHours)
	case h.BehindWarn < 0:
		return fmt.Errorf("health.behind_warn must not be negative, got %d", h.BehindWarn)
	case h.ScanWarnHours < 0:
		return fmt.Errorf("health.scan_warn_hours must not be negative (0 switches the rule off), got %d", h.ScanWarnHours)
	case h.EvalInterval < time.Second || h.EvalInterval > time.Minute:
		return fmt.Errorf("health.eval_interval must be between 1s and 60s, got %s", h.EvalInterval)
	}
	return nil
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
		SecretKeyFile:  secrets.DefaultKeyPath,
		TrustedProxies: []string{},
		Health: Health{
			StaleFactor: 3, DefaultInterval: 5 * time.Minute,
			DailyWarnHours: 24, DailyCritHours: 72, BehindWarn: 2, ScanWarnHours: 48,
			EvalInterval: 60 * time.Second, RequireVirusEvent: true,
		},
		Auth: Auth{
			Local:         AuthLocal{Enabled: true},
			SessionMaxAge: 12 * time.Hour, SessionIdle: time.Hour, CookieSecure: true,
		},
		Alert: Alert{
			Cooldown: 15 * time.Minute,
			Webhook:  AlertWebhook{Timeout: 10 * time.Second, AllowPrivate: true, DenyNetworks: []string{}, NAT64Prefixes: []string{}},
		},
		SMTP:      SMTP{Port: 587, TLS: "starttls", Timeout: 30 * time.Second},
		Retention: DefaultRetention(),
		Backup:    Backup{Dir: DefaultBackupDir, Keep: DefaultBackupKeep},
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
	if err := c.Health.Validate(); err != nil {
		return err
	}
	if err := c.Auth.Validate(); err != nil {
		return err
	}
	if err := c.validateAlerting(); err != nil {
		return err
	}
	if err := c.Retention.Validate(); err != nil {
		return err
	}
	if err := c.Backup.Validate(); err != nil {
		return err
	}
	if err := c.Metrics.Validate(); err != nil {
		return err
	}
	if c.Listen == "" {
		return fmt.Errorf("listen must not be empty")
	}
	for k, p := range map[string]string{"db_path": c.DBPath, "secret_key_file": c.SecretKeyFile} {
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
