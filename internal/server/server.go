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
// The certificate, key and client CA are re-read on SIGHUP (tlsreload.go): a
// renewed certificate needs no restart.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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

// Listen binds c.Listen. Separate from Serve so a caller (or test) that asked
// for port 0 can learn the real address before serving.
func Listen(c Config) (net.Listener, error) {
	return net.Listen("tcp", c.Listen)
}

// Serve listens per c and serves h until ctx is cancelled, then shuts down
// gracefully (10 s). It logs the actual listen address (useful with port 0).
// A clean shutdown returns nil.
func Serve(ctx context.Context, c Config, h http.Handler, log *slog.Logger) error {
	return ServeReload(ctx, c, h, log, nil)
}

// ServeReload is Serve that reloads the TLS files each time reload receives a value.
func ServeReload(ctx context.Context, c Config, h http.Handler, log *slog.Logger, reload <-chan struct{}) error {
	ln, err := Listen(c)
	if err != nil {
		return fmt.Errorf("listen %s: %w", c.Listen, err)
	}
	return ServeListenerReload(ctx, ln, c, h, log, reload)
}

// ServeListener is Serve on an existing listener. It closes the listener.
func ServeListener(ctx context.Context, ln net.Listener, c Config, h http.Handler, log *slog.Logger) error {
	return ServeListenerReload(ctx, ln, c, h, log, nil)
}

// ServeListenerReload is ServeReload on an existing listener. A receive on
// reload re-reads tls.cert, tls.key and tls.client_ca: all or nothing, the old
// state kept (and an error logged) when anything is wrong. With TLS off it logs
// that there is nothing to reload.
func ServeListenerReload(ctx context.Context, ln net.Listener, c Config, h http.Handler, log *slog.Logger, reload <-chan struct{}) error {
	rl, err := newTLSReloader(c)
	if err != nil {
		ln.Close()
		return err
	}
	if rl != nil {
		ln = tls.NewListener(ln, rl.config())
	}
	tc := rl != nil
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
	log.Info("listening", "addr", ln.Addr().String(), "tls", tc, "mtls", c.TLS.ClientCA != "")
	reloadDone := make(chan struct{})
	rctx, stopReload := context.WithCancel(ctx)
	defer stopReload()
	go func() {
		defer close(reloadDone)
		for {
			select {
			case <-rctx.Done():
				return
			case <-reload:
				if rl == nil {
					log.Info("reload requested, but TLS is off: nothing to reload")
					continue
				}
				if err := rl.reload(log); err != nil {
					log.Error("tls reload failed, keeping the previous certificate and client CA", "error", err.Error())
				}
			}
		}
	}()

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err // the listener failed; Serve only returns ErrServerClosed after Shutdown
	case <-ctx.Done():
	}
	stopReload()
	<-reloadDone
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
