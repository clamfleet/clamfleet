// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// alerts.go: builds the alert dispatcher and the settings the console needs
// from the configuration (docs/plans/milestone-4.md 4.9).
//
// This is where files named in the configuration are read (smtp.password_file
// under the key-file permission rule, the CA bundles), so a bad one refuses
// `serve` with its reason instead of failing the first alert.
package server

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"time"

	"github.com/clamfleet/clamfleet/internal/alert"
	"github.com/clamfleet/clamfleet/internal/secrets"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/version"
)

// Alerts is what the configuration yields for alerting: the dispatcher plus the
// settings the console pages and the CLI show or enforce.
type Alerts struct {
	Dispatcher *alert.Dispatcher
	// Policy is the webhook destination policy; the console validates URLs with it.
	Policy alert.Policy
	// EmailEnabled is true when smtp.host is set.
	EmailEnabled bool
	// SMTPPlaintext is true for smtp.tls: none (the console marks it "unencrypted").
	SMTPPlaintext bool
	// PublicURL is public_url without a trailing slash ("" = links are null).
	PublicURL string
}

func loadPool(path, what string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	// Extra anchors ADD to the system roots (a private CA for one receiver must
	// not make every public receiver unverifiable).
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s %s holds no PEM certificate", what, path)
	}
	return pool, nil
}

// BuildAlerts assembles the dispatcher from cfg (which must have passed
// Validate). keys may be nil (no key file): webhook secrets then cannot be
// opened and their deliveries fail permanently with a clear text.
func BuildAlerts(cfg Config, st store.AlertStore, keys *secrets.Keyring, now func() time.Time, log *slog.Logger) (*Alerts, error) {
	deny, err := ParseDenyNetworks(cfg.Alert.Webhook.DenyNetworks)
	if err != nil {
		return nil, err
	}
	policy := alert.Policy{AllowPrivate: cfg.Alert.Webhook.AllowPrivate, AllowLoopback: cfg.Alert.Webhook.AllowLoopback, DenyNetworks: deny}
	hookCAs, err := loadPool(cfg.Alert.Webhook.CAFile, "alert.webhook.ca_file")
	if err != nil {
		return nil, err
	}
	d := &alert.Dispatcher{
		Store: st, Now: now, Log: log, Cooldown: cfg.Alert.Cooldown,
		Webhook:        &alert.WebhookSender{Policy: policy, Timeout: cfg.Alert.Webhook.Timeout, RootCAs: hookCAs, Now: now, Version: version.Version},
		WebhookTimeout: cfg.Alert.Webhook.Timeout, MailTimeout: cfg.SMTP.Timeout,
		Planner: alert.Planner{NewID: alert.NewAlertID, PublicURL: cfg.PublicBase()},
		Open: func(blob []byte, targetID int64) ([]byte, error) {
			if keys == nil {
				return nil, fmt.Errorf("no secret key file")
			}
			return keys.Open(secrets.PurposeAlertTarget, blob, uint64(targetID))
		},
	}
	out := &Alerts{Dispatcher: d, Policy: policy, PublicURL: cfg.PublicBase()}

	if m := cfg.SMTP; m.Host != "" {
		smtpCAs, err := loadPool(m.CAFile, "smtp.ca_file")
		if err != nil {
			return nil, err
		}
		password := ""
		if m.PasswordFile != "" {
			if password, err = secrets.ReadProtectedFile(m.PasswordFile, "smtp.password_file"); err != nil {
				return nil, err
			}
		}
		d.Mail = &alert.SMTPSender{
			Config: alert.SMTPConfig{
				Host: m.Host, Port: m.Port, TLS: m.TLS, From: m.From, Username: m.Username, Password: password,
				Helo: heloName(cfg), Timeout: m.Timeout, RootCAs: smtpCAs,
			},
			Now: now,
		}
		d.MailFrom = m.From
		out.EmailEnabled, out.SMTPPlaintext = true, m.TLS == "none"
	}
	return out, nil
}

// heloName: smtp.helo, else the host part of public_url, else os.Hostname(),
// else "localhost".
func heloName(cfg Config) string {
	if cfg.SMTP.Helo != "" {
		return cfg.SMTP.Helo
	}
	if u, err := url.Parse(cfg.PublicURL); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "localhost"
}
