// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// handler.go: NewHandler, the single place where routes are registered.
//
// Routes come from one table (Routes) so a test can list every route with its
// authentication class and prove that no /v1 route is reachable without a
// token. /v1/* is bearer-only: no cookies, hence no CSRF surface. UI routes
// (Milestone 3) will be another class with session cookies and CSRF
// protection, in the same table.
//
// A 404 or 405 for an unknown path or a wrong method comes from the standard
// mux (plain text with an Allow header), not from the JSON envelope.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/clamfleet/clamfleet/internal/agentauth"
	"github.com/clamfleet/clamfleet/internal/api"
	"github.com/clamfleet/clamfleet/internal/store"
)

// AuthClass says how a route is protected.
type AuthClass string

const (
	// AuthNone: public (health check).
	AuthNone AuthClass = "none"
	// AuthAgent: needs an agent bearer token (and a client certificate when mTLS is on).
	AuthAgent AuthClass = "agent"
)

// Route is one registered route.
type Route struct {
	Method string
	Path   string
	Auth   AuthClass
}

// Routes lists every route NewHandler registers.
func Routes() []Route {
	return []Route{
		{"POST", "/v1/report", AuthAgent},
		{"POST", "/v1/event", AuthAgent},
		{"GET", "/healthz", AuthNone},
	}
}

// Deps are what the handler needs.
type Deps struct {
	Store store.Store
	// Auth authenticates agents; nil means bearer tokens looked up in Store.
	Auth agentauth.Authenticator
	// Now is the injected clock for all server-side times.
	Now func() time.Time
	Log *slog.Logger
}

// NewHandler builds the complete HTTP handler.
func NewHandler(d Deps) http.Handler {
	auth := d.Auth
	if auth == nil {
		auth = agentauth.Bearer{Lookup: storeLookup(d.Store)}
	}
	h := api.New(api.Deps{Store: d.Store, Now: d.Now, Log: d.Log})
	agent := agentauth.Middleware(auth, d.Log)

	handlers := map[string]http.HandlerFunc{
		"POST /v1/report": h.Report,
		"POST /v1/event":  h.Event,
		"GET /healthz":    h.Health,
	}
	mux := http.NewServeMux()
	for _, rt := range Routes() {
		key := rt.Method + " " + rt.Path
		hd, ok := handlers[key]
		if !ok {
			panic("server: route without a handler: " + key)
		}
		// The auth class decides the wrapping, so the table and the behaviour
		// cannot drift apart.
		switch rt.Auth {
		case AuthAgent:
			mux.Handle(key, agent(hd))
		case AuthNone:
			mux.Handle(key, hd)
		default:
			panic("server: unknown auth class for " + key)
		}
	}
	return api.RequestLog(d.Log, d.Now)(mux)
}

// storeLookup adapts the store to agentauth.Lookup, translating "no such
// token" into the sentinel the authenticator understands; every other store
// error stays an error and becomes a 503, never a 401.
func storeLookup(s store.Store) agentauth.Lookup {
	return func(ctx context.Context, hash []byte) (agentauth.Identity, error) {
		ref, err := s.HostByTokenHash(ctx, hash)
		if errors.Is(err, store.ErrNotFound) {
			return agentauth.Identity{}, agentauth.ErrUnknownToken
		}
		if err != nil {
			return agentauth.Identity{}, err
		}
		return agentauth.Identity{HostID: ref.ID, HostName: ref.Name}, nil
	}
}
