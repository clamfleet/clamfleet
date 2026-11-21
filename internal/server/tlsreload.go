// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// tlsreload.go: TLS settings that can be reloaded without a restart (M6 decision 15). A renewed certificate (an ACME client, a manual
// renewal) is picked up with `systemctl reload clamfleet-server` (SIGHUP).
//
// Design:
//   - The listener's base tls.Config never changes. Its GetConfigForClient returns
//     a CLONE of it with the current certificate and client CA pool, so
//     MinVersion, ClientAuth and the cipher policy can never be lost by a reload.
//   - The current certificate and CA pool live in one atomically swapped value, so
//     a handshake sees either the old pair or the new pair, never a mix.
//   - Reload is all or nothing: the files named in the configuration at start are
//     re-read, and the swap happens only if the key matches the certificate AND the
//     CA bundle holds at least one certificate. Anything else logs an error and
//     keeps the old state. A good certificate with a bad CA swaps nothing.
//   - With tls.client_ca set, session tickets are off: every connection is a full
//     handshake against the CURRENT pool, so a resumed session cannot outlive a
//     change of the client CA (a revoked CA would otherwise keep working for the
//     ticket lifetime). Without mTLS tickets stay on.
//   - Connections that are already open keep the handshake they made; a keep-alive
//     connection lives at most idleTimeout after its last request. A restart drops
//     them at once.
//   - Adding or removing tls.client_ca in the configuration changes the listener's
//     mode and needs a restart; SIGHUP re-reads files, not the configuration.
package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
)

// tlsState is what a handshake uses; it is replaced as one value.
type tlsState struct {
	cert     tls.Certificate
	clientCA *x509.CertPool // nil without mTLS
}

// tlsReloader owns the listener's TLS configuration.
type tlsReloader struct {
	certFile, keyFile, caFile string
	state                     atomic.Pointer[tlsState]
	base                      *tls.Config
}

// newTLSReloader loads the files named in c and builds the base configuration.
// It returns nil when TLS is off.
func newTLSReloader(c Config) (*tlsReloader, error) {
	if !c.TLSEnabled() {
		return nil, nil
	}
	r := &tlsReloader{certFile: c.TLS.Cert, keyFile: c.TLS.Key, caFile: c.TLS.ClientCA}
	st, err := r.load()
	if err != nil {
		return nil, err
	}
	r.state.Store(st)
	r.base = &tls.Config{MinVersion: tls.VersionTLS12}
	if r.caFile != "" {
		r.base.ClientAuth = tls.RequireAndVerifyClientCert
		r.base.SessionTicketsDisabled = true
	}
	// The returned config is a clone of base plus the current state; the listener's
	// own config carries only this callback.
	r.base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		st := r.state.Load()
		cfg := r.base.Clone()
		cfg.GetConfigForClient = nil
		cfg.Certificates = []tls.Certificate{st.cert}
		cfg.ClientCAs = st.clientCA
		return cfg, nil
	}
	return r, nil
}

// config is the tls.Config for the listener.
func (r *tlsReloader) config() *tls.Config {
	// A fresh config that only forwards to GetConfigForClient, so crypto/tls
	// never serves a certificate or CA pool that was captured at start.
	return &tls.Config{
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: r.caFile != "",
		GetConfigForClient:     r.base.GetConfigForClient,
	}
}

// load reads and validates the files. It never changes the live state.
func (r *tlsReloader) load() (*tlsState, error) {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls.cert/tls.key: %w", err)
	}
	st := &tlsState{cert: cert}
	if r.caFile != "" {
		pemBytes, err := os.ReadFile(r.caFile)
		if err != nil {
			return nil, fmt.Errorf("read tls.client_ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			// An empty pool would reject every agent with a handshake error that
			// looks like a network problem.
			return nil, fmt.Errorf("tls.client_ca %s contains no PEM certificate", r.caFile)
		}
		st.clientCA = pool
	}
	return st, nil
}

// reload re-reads the files and swaps the state, all or nothing. A failure keeps
// the old state and is returned (and logged by the caller).
func (r *tlsReloader) reload(log *slog.Logger) error {
	st, err := r.load()
	if err != nil {
		return err
	}
	r.state.Store(st)
	leaf, perr := x509.ParseCertificate(st.cert.Certificate[0])
	if perr != nil {
		return errors.New("reloaded certificate is not parseable") // cannot happen after a successful LoadX509KeyPair
	}
	log.Info("tls certificate reloaded", "not_after", leaf.NotAfter.UTC().Format("2006-01-02T15:04:05Z"), "serial", leaf.SerialNumber.Text(16), "client_ca", r.caFile != "")
	return nil
}
