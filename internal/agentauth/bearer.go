// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// bearer.go: the Authenticator interface (spec 7.1), the bearer-token
// implementation, and the HTTP middleware that enforces it.
//
// Authentication sits behind an interface so a second implementation can be
// added without touching the handlers: mTLS (a client certificate in
// r.TLS.PeerCertificates) arrives in Milestone 2 as a transport requirement
// (tls.client_ca) while the token stays mandatory, and a certificate-bound
// identity can later replace the token by implementing Authenticator.
//
// Failure model (security-relevant, do not change casually):
//   - Every cause of failure (no header, wrong scheme, malformed, unknown or
//     revoked token) is the same ErrUnauthenticated, and the middleware answers
//     all of them with the same 401 body and headers: no oracle.
//   - A lookup that fails for any other reason (database down) is
//     ErrUnavailable and answers 503, never 401: an agent must not read a
//     database hiccup as "my token was revoked".
//   - Authentication runs before the body is read, so an unauthenticated client
//     cannot make the server parse a megabyte.
package agentauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// Identity is the authenticated host. It comes from the credential, never from
// the payload.
type Identity struct {
	HostID   int64
	HostName string
}

var (
	// ErrUnauthenticated: the request carries no valid credential.
	ErrUnauthenticated = errors.New("unauthenticated")
	// ErrUnavailable: the credential could not be checked (store failure).
	ErrUnavailable = errors.New("authentication unavailable")
	// ErrUnknownToken is what a Lookup returns for a token hash that matches no
	// host (never registered, rotated away or revoked).
	ErrUnknownToken = errors.New("unknown token")
)

// Authenticator turns a request into the identity behind it. It returns an
// error that matches ErrUnauthenticated or ErrUnavailable (errors.Is).
type Authenticator interface {
	Authenticate(r *http.Request) (Identity, error)
}

// Lookup resolves a token hash to a host. It returns ErrUnknownToken when
// none matches; any other error means the store is unwell.
type Lookup func(ctx context.Context, tokenHash []byte) (Identity, error)

// Bearer authenticates "Authorization: Bearer cfa_..." against Lookup.
type Bearer struct {
	Lookup Lookup
}

// Authenticate implements Authenticator.
func (b Bearer) Authenticate(r *http.Request) (Identity, error) {
	token, err := bearerToken(r)
	if err != nil {
		return Identity{}, err
	}
	// Format check before any lookup: garbage, and tokens of other kinds
	// (a future "cfu_" user token), never reach the database.
	if Parse(token) != nil {
		return Identity{}, ErrUnauthenticated
	}
	id, err := b.Lookup(r.Context(), Hash(token))
	switch {
	case err == nil:
		return id, nil
	case errors.Is(err, ErrUnknownToken):
		return Identity{}, ErrUnauthenticated
	default:
		return Identity{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
}

// bearerToken extracts the token from the single Authorization header. The
// scheme is case-insensitive and extra spaces before the token are tolerated
// (RFC 7235: 1*SP); the token itself is checked strictly by Parse.
func bearerToken(r *http.Request) (string, error) {
	vals := r.Header.Values("Authorization")
	if len(vals) != 1 {
		return "", ErrUnauthenticated
	}
	scheme, rest, ok := strings.Cut(vals[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", ErrUnauthenticated
	}
	return strings.TrimLeft(rest, " "), nil
}

type ctxKey struct{}

// FromContext returns the identity the middleware stored. ok is false when the
// request did not pass through Middleware.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// Middleware wraps next so it only runs for an authenticated request, with the
// Identity in the context. 401 and 503 carry a fixed JSON body (the API
// envelope, spec 7.2 and docs/api.md). Side effect: logs a store failure at
// error level; the credential is never logged.
func Middleware(a Authenticator, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := a.Authenticate(r)
			switch {
			case err == nil:
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
			case errors.Is(err, ErrUnauthenticated):
				w.Header().Set("WWW-Authenticate", `Bearer realm="clamfleet"`)
				writeError(w, http.StatusUnauthorized, "unauthorized")
			default:
				log.Error("agent authentication unavailable", "error", err.Error())
				writeError(w, http.StatusServiceUnavailable, "service unavailable")
			}
		})
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}` + "\n"))
}
