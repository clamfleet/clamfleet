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
	"reflect"
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
	// AuthMetrics: a monitoring scraper with the metrics bearer token (404 while
	// metrics are off). Not a console route: no session, no cookie, no CSRF.
	AuthMetrics AuthClass = "metrics"
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
		// Prometheus text format; off by default, bearer token from a file when on (M6).
		{"GET", "/metrics", AuthMetrics},
		{"GET", "/static/{file}", AuthPublic},
		{"GET", "/login", AuthPublic},
		{"POST", "/login", AuthPublic},
		// OpenID Connect (6b). Public class: no session exists yet. The start form is covered by the
		// cross-origin check; the callback is a GET that only proceeds with the state cookie.
		{"POST", "/login/oidc", AuthPublic},
		{"GET", "/login/oidc/callback", AuthPublic},
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
		// Detections (M5). Everyone signed in sees them (paths included, decision 12); only
		// admins acknowledge. "/events/ack" and "/events/{id}/ack" differ in segment count, so
		// they cannot shadow each other.
		{"GET", "/events", AuthUser},
		{"POST", "/events/{id}/ack", AuthAdmin},
		{"POST", "/events/ack", AuthAdmin},
		{"GET", "/admin/hosts", AuthAdmin},
		{"POST", "/admin/hosts", AuthAdmin},
		{"POST", "/admin/hosts/{name}/rotate-token", AuthAdmin},
		{"POST", "/admin/hosts/{name}/revoke-token", AuthAdmin},
		{"POST", "/admin/hosts/{name}/delete", AuthAdmin},
		{"GET", "/account", AuthUser},
		{"POST", "/account/password", AuthUser},
		// TOTP self-service. Every change asks the current password again (also the
		// forced first enrolment). RequireUser lets these through while a user must enrol.
		{"GET", "/account/totp", AuthUser},
		{"POST", "/account/totp/setup", AuthUser},
		{"POST", "/account/totp/confirm", AuthUser},
		{"POST", "/account/totp/recovery-codes", AuthUser},
		{"POST", "/account/totp/disable", AuthUser},
		// Alert targets (M4). Admin only, pages included: recipient addresses and
		// receiver hosts are configuration, and a test send makes the server connect
		// out. The literal /admin/alerts/new beats the {name} wildcard (Go 1.22 mux:
		// the more specific pattern wins) and "new" is a reserved target name.
		{"GET", "/admin/alerts", AuthAdmin},
		{"GET", "/admin/alerts/new", AuthAdmin},
		{"POST", "/admin/alerts", AuthAdmin},
		{"GET", "/admin/alerts/{name}", AuthAdmin},
		{"POST", "/admin/alerts/{name}", AuthAdmin},
		{"POST", "/admin/alerts/{name}/test", AuthAdmin},
		{"POST", "/admin/alerts/{name}/rotate-secret", AuthAdmin},
		{"POST", "/admin/alerts/{name}/delete", AuthAdmin},
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
	// AfterEvent is called after each accepted event (see api.Deps); the binary
	// passes a function that wakes the alert dispatcher when stored is true, so
	// a detection alerts within seconds instead of at the next 5 s tick. Nil disables it.
	AfterEvent func(ctx context.Context, stored bool)
	// Console holds the sign-in settings; the zero value means DefaultConfig().Auth.
	Console Auth
	// Hasher hashes console passwords; nil means a production argon2id Hasher.
	Hasher web.PasswordHasher
	// Version is shown in the page footer; "" means version.Version.
	Version string
	// Keys protects TOTP secrets at rest (internal/secrets); nil when the server
	// has no key file, which makes TOTP unavailable.
	Keys *secrets.Keyring
	// Alerts is what the alert pages need (server.BuildAlerts); nil means a strict
	// policy, no email and no test send.
	Alerts *Alerts
	// LDAP is the directory sign-in (BuildLDAP; NewHandlerFromConfig sets it from the
	// configuration); nil means LDAP is off.
	LDAP web.Directory
	// OIDC is the OpenID Connect sign-in (BuildOIDC; NewHandlerFromConfig sets it); nil means OIDC is off.
	OIDC web.OIDCProvider
	// MetricsToken is the bearer token of GET /metrics; nil means metrics are off
	// and the route answers 404. NewHandlerFromConfig reads it from metrics.token_file.
	MetricsToken []byte
	// FailedDeliveryWindow bounds the failed deliveries /metrics counts (alert_log_days); 0 means 90 days.
	FailedDeliveryWindow time.Duration
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
	if dir, err := BuildLDAP(c); err != nil {
		return nil, err
	} else if dir != nil {
		d.LDAP = dir
	}
	if oc, err := BuildOIDC(c, d.Now); err != nil {
		return nil, err
	} else if oc != nil {
		d.OIDC = oc
	}
	if d.MetricsToken, err = loadMetricsToken(c.Metrics); err != nil {
		return nil, err
	}
	d.FailedDeliveryWindow = days(c.Retention.AlertLogDays)
	return NewHandler(d), nil
}

// NewHandler builds the complete HTTP handler.
func NewHandler(d Deps) http.Handler {
	auth := d.Auth
	if auth == nil {
		auth = agentauth.Bearer{Lookup: storeLookup(d.Store)}
	}
	if reflect.DeepEqual(d.Console, Auth{}) { // Auth holds slices: not comparable with ==
		d.Console = DefaultConfig().Auth
	}
	if d.Hasher == nil {
		d.Hasher = webauth.NewHasher()
	}
	if d.Version == "" {
		d.Version = version.Version
	}
	failedWindow := d.FailedDeliveryWindow
	if failedWindow == 0 {
		failedWindow = days(DefaultAlertLogDays)
	}
	h := api.New(api.Deps{Store: d.Store, Now: d.Now, Log: d.Log, AfterReport: d.AfterReport, AfterEvent: d.AfterEvent})
	agent := agentauth.Middleware(auth, d.Log)

	sessions := &webauth.Manager{
		Store: d.Store, Now: d.Now, MaxAge: d.Console.SessionMaxAge, Idle: d.Console.SessionIdle,
		Secure: d.Console.CookieSecure, Log: d.Log, TOTPRequired: d.Console.Local.TOTPRequired,
		Sources: sourcesFor(d),
	}
	console := web.New(web.Deps{
		Store: d.Store, Auth: sessions, Hasher: d.Hasher, Throttle: webauth.NewThrottle(d.Now), TOTPThrottle: webauth.NewThrottle(d.Now), Keys: d.Keys, Now: d.Now, Log: d.Log,
		ClientIP: func(r *http.Request) string { return api.ClientIP(r, d.TrustedProxies) },
		LDAP:     d.LDAP, OIDC: d.OIDC, OIDCName: d.Console.OIDC.DisplayName,
		LocalEnabled: d.Console.Local.Enabled, TOTPRequired: d.Console.Local.TOTPRequired, Version: d.Version,
		Alerts: alertDeps(d.Alerts),
	})

	handlers := map[string]http.HandlerFunc{
		"POST /v1/report": h.Report,
		"POST /v1/event":  h.Event,
		"GET /healthz":    h.Health,
		"GET /metrics":    metricsHandler(d.Store, d.MetricsToken, d.Now, failedWindow, d.Version, d.TrustedProxies, d.Log),
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
		case AuthNone, AuthMetrics:
			// AuthMetrics checks its own bearer token inside the handler (and 404s when off).
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

// sourcesFor is the set of sources that may hold a session: enabled in the configuration AND
// actually wired. A provider that is switched on but was never built (a Deps without it) must
// not leave its users' sessions valid, so the check fails closed.
func sourcesFor(d Deps) map[string]bool {
	s := d.Console.EnabledSources()
	s[store.AuthLDAP] = s[store.AuthLDAP] && d.LDAP != nil
	s[store.AuthOIDC] = s[store.AuthOIDC] && d.OIDC != nil
	return s
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

// alertDeps converts the server's alert settings for the console.
func alertDeps(a *Alerts) web.AlertDeps {
	if a == nil {
		return web.AlertDeps{}
	}
	return web.AlertDeps{Dispatcher: a.Dispatcher, Policy: a.Policy, EmailEnabled: a.EmailEnabled, SMTPPlaintext: a.SMTPPlaintext, PublicURL: a.PublicURL}
}
