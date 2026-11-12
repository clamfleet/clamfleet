// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// handler.go: NewHandler, the single place where routes are registered.
//
// Routes come from one table (Routes) so a test can list every route with its
// authentication class and prove that no route is reachable without the
// credential its class demands. /v1/* is bearer-only: no cookies, hence no CSRF
// surface. The console routes (user, admin, public classes) are cookie-session
// based, carry the security headers and CSRF protection, and live in the same
// table; the class decides the wrapping, so table and behaviour cannot drift.
//
// A 404 or 405 for an unknown path or a wrong method comes from the standard
// mux (plain text with an Allow header), not from the JSON envelope.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/clamfleet/clamfleet/internal/agentauth"
	"github.com/clamfleet/clamfleet/internal/api"
	"github.com/clamfleet/clamfleet/internal/secrets"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/version"
	"github.com/clamfleet/clamfleet/internal/web"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

// AuthClass says how a route is protected.
type AuthClass string

const (
	// AuthNone: public (health check).
	AuthNone AuthClass = "none"
	// AuthAgent: needs an agent bearer token (and a client certificate when mTLS is on).
	AuthAgent AuthClass = "agent"
	// AuthPublic: a console page that needs no session (login form, static
	// files). It still gets the security headers and the cross-origin check.
	AuthPublic AuthClass = "public"
	// AuthUser: a signed-in console user (viewer or admin), CSRF token on non-GET.
	AuthUser AuthClass = "user"
	// AuthAdmin: a signed-in console user with the admin role, CSRF token on non-GET.
	AuthAdmin AuthClass = "admin"
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
		{"GET", "/static/{file}", AuthPublic},
		{"GET", "/login", AuthPublic},
		{"POST", "/login", AuthPublic},
		// The second sign-in step. Public class: the caller has no session yet; the
		// handlers require a valid login challenge (cookie) and answer 303 to /login without one.
		{"GET", "/login/totp", AuthPublic},
		{"POST", "/login/totp", AuthPublic},
		{"POST", "/logout", AuthUser},
		// {$}, not "/": in Go's mux "GET /" matches EVERY GET path, so an unknown
		// URL would render the fleet instead of a 404.
		{"GET", "/{$}", AuthUser},
		{"GET", "/fleet/rows", AuthUser},
		{"GET", "/hosts/{name}", AuthUser},
		{"GET", "/admin/hosts", AuthAdmin},
		{"POST", "/admin/hosts", AuthAdmin},
		{"POST", "/admin/hosts/{name}/rotate-token", AuthAdmin},
		{"POST", "/admin/hosts/{name}/revoke-token", AuthAdmin},
		{"POST", "/admin/hosts/{name}/delete", AuthAdmin},
		{"GET", "/account", AuthUser},
		{"POST", "/account/password", AuthUser},
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
	// TrustedProxies are the reverse proxies whose X-Forwarded-For is believed
	// for the logged client IP (see api.ClientIP); parse with ParseTrustedProxies.
	TrustedProxies []netip.Prefix
	// AfterReport is called after each accepted report (see api.Deps); the
	// binary passes health.Evaluator.Host. Nil disables it.
	AfterReport func(ctx context.Context, hostID int64) error
	// Console holds the sign-in settings; the zero value means DefaultConfig().Auth.
	Console Auth
	// Hasher hashes console passwords; nil means a production argon2id Hasher.
	Hasher web.PasswordHasher
	// Version is shown in the page footer; "" means version.Version.
	Version string
	// Keys protects TOTP secrets at rest (internal/secrets); nil when the server
	// has no key file, which makes TOTP unavailable.
	Keys *secrets.Keyring
}

// NewHandlerFromConfig is NewHandler with the config-derived settings
// (trusted_proxies) applied to d, so the binary has one call that cannot
// forget one. The config must have passed Validate.
func NewHandlerFromConfig(c Config, d Deps) (http.Handler, error) {
	proxies, err := ParseTrustedProxies(c.TrustedProxies)
	if err != nil {
		return nil, err
	}
	d.TrustedProxies = proxies
	d.Console = c.Auth
	return NewHandler(d), nil
}

// NewHandler builds the complete HTTP handler.
func NewHandler(d Deps) http.Handler {
	auth := d.Auth
	if auth == nil {
		auth = agentauth.Bearer{Lookup: storeLookup(d.Store)}
	}
	if d.Console == (Auth{}) {
		d.Console = DefaultConfig().Auth
	}
	if d.Hasher == nil {
		d.Hasher = webauth.NewHasher()
	}
	if d.Version == "" {
		d.Version = version.Version
	}
	h := api.New(api.Deps{Store: d.Store, Now: d.Now, Log: d.Log, AfterReport: d.AfterReport})
	agent := agentauth.Middleware(auth, d.Log)

	sessions := &webauth.Manager{
		Store: d.Store, Now: d.Now, MaxAge: d.Console.SessionMaxAge, Idle: d.Console.SessionIdle,
		Secure: d.Console.CookieSecure, Log: d.Log,
	}
	console := web.New(web.Deps{
		Store: d.Store, Auth: sessions, Hasher: d.Hasher, Throttle: webauth.NewThrottle(d.Now), TOTPThrottle: webauth.NewThrottle(d.Now), Keys: d.Keys, Now: d.Now, Log: d.Log,
		ClientIP:     func(r *http.Request) string { return api.ClientIP(r, d.TrustedProxies) },
		LocalEnabled: d.Console.Local.Enabled, Version: d.Version,
	})

	handlers := map[string]http.HandlerFunc{
		"POST /v1/report": h.Report,
		"POST /v1/event":  h.Event,
		"GET /healthz":    h.Health,
	}
	for k, v := range console.Handlers() {
		handlers[k] = v
	}
	mux := http.NewServeMux()
	for _, rt := range Routes() {
		key := rt.Method + " " + rt.Path
		hd, ok := handlers[key]
		if !ok {
			panic("server: route without a handler: " + key)
		}
		// The auth class decides the wrapping, so the table and the behaviour
		// cannot drift apart. Order for console routes, outermost first: security
		// headers, cross-origin check, session (and role), CSRF token, handler.
		var wrapped http.Handler
		switch rt.Auth {
		case AuthAgent:
			wrapped = agent(hd)
		case AuthNone:
			wrapped = hd
		case AuthPublic:
			wrapped = web.SecurityHeaders(sessions.CrossOrigin(hd))
		case AuthUser:
			wrapped = web.SecurityHeaders(sessions.CrossOrigin(sessions.RequireUser(sessions.CSRF(hd))))
		case AuthAdmin:
			wrapped = web.SecurityHeaders(sessions.CrossOrigin(sessions.RequireAdmin(sessions.CSRF(hd))))
		default:
			panic("server: unknown auth class for " + key)
		}
		mux.Handle(key, wrapped)
	}
	for k := range handlers {
		found := false
		for _, rt := range Routes() {
			found = found || rt.Method+" "+rt.Path == k
		}
		if !found {
			panic("server: handler without a route in Routes(): " + k)
		}
	}
	return api.RequestLog(d.Log, d.Now, d.TrustedProxies)(mux)
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
