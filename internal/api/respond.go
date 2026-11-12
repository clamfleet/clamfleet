// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package api implements the JSON ingest endpoints of the server (spec 7.2):
// POST /v1/report, POST /v1/event and GET /healthz.
//
// The handlers know nothing about routing or authentication: server.NewHandler
// is the single place that registers routes and puts the authentication
// middleware in front. The identity of the caller always comes from the
// credential (agentauth.FromContext), never from the payload.
//
// respond.go: the response envelope and the request log.
//
// Envelope (public interface, docs/api.md): every response is application/json.
// A success is a JSON object; clients must ignore keys they do not know, which
// is the hook for server-to-agent tasks later. An error is {"error":"<short message>"}.
// Error messages are fixed or describe the client's own input; they never carry
// internal detail (no SQL, paths or stack traces).
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		// Only fixed maps are encoded here; this cannot happen, but never send a half body.
		status, b = http.StatusInternalServerError, []byte(`{"error":"internal error"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// reqInfo is filled in by the handlers for the request log, which is written
// after the handler returns and otherwise could not know the authenticated host.
type reqInfo struct {
	mu   sync.Mutex
	host string
}

type infoKey struct{}

func setLogHost(ctx context.Context, name string) {
	if ri, ok := ctx.Value(infoKey{}).(*reqInfo); ok {
		ri.mu.Lock()
		ri.host = name
		ri.mu.Unlock()
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// clientIP is the TCP peer address without the port. X-Forwarded-For is
// deliberately not trusted: behind a reverse proxy the logged address is the
// proxy's, and honouring a client-supplied header would let anyone forge it.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RequestLog logs every request once, after it is served: 2xx at debug, 4xx at
// warn, 5xx at error. Fields: method, path, status, host (the authenticated
// host name, if any), duration and the client IP, always (decision 10: what an
// operator does with source addresses is their business; they are not hidden).
// It never logs the Authorization header, the query string or the body.
// now is the injected clock, so durations are testable.
func RequestLog(log *slog.Logger, now func() time.Time) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := now()
			ri := &reqInfo{}
			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), infoKey{}, ri)))
			status := sw.status
			if status == 0 {
				status = http.StatusOK
			}
			level := slog.LevelDebug
			switch {
			case status >= 500:
				level = slog.LevelError
			case status >= 400:
				level = slog.LevelWarn
			}
			ri.mu.Lock()
			host := ri.host
			ri.mu.Unlock()
			log.LogAttrs(r.Context(), level, "request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.String("host", host),
				slog.Duration("duration", now().Sub(start)),
				slog.String("client_ip", clientIP(r)),
			)
		})
	}
}
