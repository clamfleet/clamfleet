// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// server.go: the listener. Serve binds the configured address, optionally
// terminates TLS (and verifies client certificates, mTLS), and shuts down
// gracefully when its context ends.
//
// TLS rules: minimum TLS 1.2. When tls.client_ca is set the server uses
// RequireAndVerifyClientCert: a client without a valid certificate fails the
// handshake and never reaches a handler. That is a transport requirement only:
// the bearer token is still checked on every /v1 request, so a stolen client
// certificate alone gets nothing and a stolen token alone cannot even connect.
//
// The certificate is loaded once at start; a renewed certificate needs a
// restart (reload is a Milestone 6 packaging item).
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"
)

// Timeouts of the HTTP server. Generous for 1 MiB bodies from slow links,
// tight enough that a stalled client cannot hold a connection for long.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 16 << 10
	shutdownTimeout   = 10 * time.Second
)

// tlsConfig builds the TLS configuration, nil when TLS is off.
func tlsConfig(c Config) (*tls.Config, error) {
	if !c.TLSEnabled() {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("load tls.cert/tls.key: %w", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if c.TLS.ClientCA != "" {
		pemBytes, err := os.ReadFile(c.TLS.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("read tls.client_ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			// Fail at start: an empty pool would otherwise reject every agent
			// with a handshake error that looks like a network problem.
			return nil, fmt.Errorf("tls.client_ca %s contains no PEM certificate", c.TLS.ClientCA)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// Listen binds c.Listen. Separate from Serve so a caller (or test) that asked
// for port 0 can learn the real address before serving.
func Listen(c Config) (net.Listener, error) {
	return net.Listen("tcp", c.Listen)
}

// Serve listens per c and serves h until ctx is cancelled, then shuts down
// gracefully (10 s). It logs the actual listen address (useful with port 0).
// A clean shutdown returns nil.
func Serve(ctx context.Context, c Config, h http.Handler, log *slog.Logger) error {
	ln, err := Listen(c)
	if err != nil {
		return fmt.Errorf("listen %s: %w", c.Listen, err)
	}
	return ServeListener(ctx, ln, c, h, log)
}

// ServeListener is Serve on an existing listener. It closes the listener.
func ServeListener(ctx context.Context, ln net.Listener, c Config, h http.Handler, log *slog.Logger) error {
	tc, err := tlsConfig(c)
	if err != nil {
		ln.Close()
		return err
	}
	if tc != nil {
		ln = tls.NewListener(ln, tc)
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		// TLS handshake failures (for example a client without a certificate
		// under mTLS) are logged by net/http through this logger, at warn, with
		// the peer address.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	log.Info("listening", "addr", ln.Addr().String(), "tls", tc != nil, "mtls", c.TLS.ClientCA != "")

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err // the listener failed; Serve only returns ErrServerClosed after Shutdown
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("stopped")
	return nil
}
