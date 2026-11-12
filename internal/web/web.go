// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package web is the server-rendered console: html/template pages, a little
// htmx for the live fleet table, and the handlers behind them.
//
// What this package does NOT do is decide who may call a handler. server.Routes()
// is the single table of routes with their auth class, and server.NewHandler
// wraps each handler in the matching middleware (internal/webauth). The
// handlers here may rely on a Principal in the context for user and admin
// routes, and still check the admin role where it matters for what they write.
//
// Untrusted text: agents control several displayed strings (tags, reported host
// name, versions, clamd and freshclam errors). Everything is output through
// html/template's contextual escaping; template.HTML is never used. The strict
// Content-Security-Policy (SecurityHeaders) is the second line, not the first.
//
// Dependencies: internal/store, internal/webauth, internal/health (the stored
// reason format), internal/proto (the report shape), the embedded templates
// and static files.
package web

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/clamfleet/clamfleet/internal/secrets"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// SourceURL is where the AGPL-3.0 section 13 offer of the source points: every
// page footer links to it, so network users are offered the source.
const SourceURL = "https://github.com/clamfleet/clamfleet"

// PasswordHasher is what the login and password-change handlers need
// (*webauth.Hasher). It is an interface so a test can count calls.
type PasswordHasher interface {
	Hash(ctx context.Context, password string) (string, error)
	Verify(ctx context.Context, password, phc string) (ok, needsRehash bool, err error)
	VerifyDummy(ctx context.Context, password string) error
}

// Deps are what the console needs.
type Deps struct {
	Store    store.Store
	Auth     *webauth.Manager
	Hasher   PasswordHasher
	Throttle *webauth.Throttle
	// TOTPThrottle is a second instance of the same backoff, keyed by user id, for
	// second-factor attempts. Its key is the user, not the challenge: each new
	// challenge costs a correct password and must not reset the count.
	TOTPThrottle *webauth.Throttle
	// Keys opens and seals TOTP secrets; nil when the server has no key file. TOTP
	// is then unavailable (recovery codes still work), and never skipped.
	Keys *secrets.Keyring
	Now  func() time.Time // injected clock: every time on a page comes from here
	Log  *slog.Logger
	// ClientIP returns the address to LOG for a request (api.ClientIP with the
	// configured trusted proxies). Logging and audit detail only, never a decision.
	ClientIP func(r *http.Request) string
	// LocalEnabled is auth.local.enabled: with false the login form refuses.
	LocalEnabled bool
	// Version is shown in the footer.
	Version string
}

// Web holds the handlers.
type Web struct {
	Deps
	pages map[string]*template.Template
}

// New parses the templates (a parse error is a programming error and panics at
// start, never at the first request) and returns the console. It also installs
// the error-page renderer on the session manager, so a 401/403 from the
// middleware looks like the rest of the console.
func New(d Deps) *Web {
	w := &Web{Deps: d, pages: map[string]*template.Template{}}
	funcs := template.FuncMap{
		"lower": strings.ToLower,
		// actions builds the data of the shared host_actions template.
		"actions": func(name string, hasToken bool, csrf string) hostAction { return hostAction{name, hasToken, csrf} },
	}
	for _, p := range []string{"login", "login_totp", "fleet", "host", "admin_hosts", "token_once", "account", "error"} {
		t := template.New(p).Funcs(funcs)
		files := []string{"templates/layout.html", "templates/" + p + ".html"}
		if p == "fleet" {
			files = append(files, "templates/fleet_rows.html")
		}
		if p == "host" || p == "admin_hosts" {
			files = append(files, "templates/host_actions.html")
		}
		w.pages[p] = template.Must(t.ParseFS(templateFS, files...))
	}
	if d.Auth != nil {
		d.Auth.Deny = w.deny
	}
	return w
}

// Handlers returns the handlers by "METHOD /path" key, as server.Routes() names them.
func (w *Web) Handlers() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET /static/{file}":                    w.static,
		"GET /login":                            w.loginPage,
		"POST /login":                           w.loginSubmit,
		"GET /login/totp":                       w.loginTOTPPage,
		"POST /login/totp":                      w.loginTOTPSubmit,
		"POST /logout":                          w.logout,
		"GET /{$}":                              w.fleet,
		"GET /fleet/rows":                       w.fleetRows,
		"GET /hosts/{name}":                     w.host,
		"GET /admin/hosts":                      w.adminHosts,
		"POST /admin/hosts":                     w.adminRegister,
		"POST /admin/hosts/{name}/rotate-token": w.adminRotate,
		"POST /admin/hosts/{name}/revoke-token": w.adminRevoke,
		"POST /admin/hosts/{name}/delete":       w.adminDelete,
		"GET /account":                          w.accountPage,
		"POST /account/password":                w.accountPassword,
	}
}

// base is the part of every page that does not depend on the page: the
// layout reads it.
type base struct {
	Title     string
	Nav       string // "fleet", "admin" or "account": the current menu item
	Principal *webauth.Principal
	CSRF      string
	Version   string
	SourceURL string
	Notice    string // a success message
	Error     string // an error message
}

// view is what a page template receives: the layout fields promoted from base
// and the page's own data in Body.
type view struct {
	base
	Body any
}

// newView fills the layout fields from the request (the signed-in user, if
// any) and the page title.
func (w *Web) newView(r *http.Request, title, nav string, body any) *view {
	v := &view{base: base{Title: title, Nav: nav, Version: w.Version, SourceURL: SourceURL}, Body: body}
	if p, ok := webauth.FromContext(r.Context()); ok {
		v.Principal, v.CSRF = &p, p.CSRFToken()
		v.Notice = recoveryNotice(r)
	}
	return v
}

// render executes page into a buffer first, so a template error yields a clean
// 500 instead of a half-written page under a 200.
func (w *Web) render(rw http.ResponseWriter, status int, page string, v *view) {
	var buf bytes.Buffer
	if err := w.pages[page].ExecuteTemplate(&buf, "layout", v); err != nil {
		w.Log.Error("render page", "page", page, "error", err.Error())
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(status)
	_, _ = rw.Write(buf.Bytes())
}

// renderPartial executes one named template without the layout (htmx fragments).
func (w *Web) renderPartial(rw http.ResponseWriter, page, name string, body any) {
	var buf bytes.Buffer
	if err := w.pages[page].ExecuteTemplate(&buf, name, body); err != nil {
		w.Log.Error("render fragment", "page", page, "error", err.Error())
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	_, _ = rw.Write(buf.Bytes())
}

// deny renders the 401/403 page the middleware asks for.
func (w *Web) deny(rw http.ResponseWriter, r *http.Request, status int) {
	w.errorPage(rw, r, status)
}

// errorPage renders a short error page. The text is fixed per status: nothing
// from the request is echoed.
func (w *Web) errorPage(rw http.ResponseWriter, r *http.Request, status int) {
	msg := map[int]string{
		http.StatusUnauthorized: "You are not signed in.",
		http.StatusForbidden:    "You do not have permission to do this.",
		http.StatusNotFound:     "There is nothing here.",
		http.StatusBadRequest:   "The request could not be understood.",
		http.StatusConflict:     "That conflicts with what exists already.",
	}[status]
	if msg == "" {
		status, msg = http.StatusInternalServerError, "Something went wrong on the server."
	}
	body := struct {
		Status     int
		StatusText string
		Message    string
	}{status, http.StatusText(status), msg}
	w.render(rw, status, "error", w.newView(r, fmt.Sprintf("%d %s", status, http.StatusText(status)), "", body))
}

// static serves the embedded files. The file name carries the version of the
// asset (htmx-2.0.11.min.js), so a one-day public cache is safe: an upgrade is
// a new URL.
func (w *Web) static(rw http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	// PathValue never contains a slash, but be explicit: only a plain file name of the embedded directory.
	if name == "" || name != path.Base(name) || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".md") {
		http.NotFound(rw, r)
		return
	}
	sub, _ := fs.Sub(staticFS, "static")
	f, err := sub.Open(name)
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	f.Close()
	rw.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeFileFS(rw, r, sub, name)
}

// SecurityHeaders sets the headers every UI response carries. The CSP allows
// only same-origin resources and no inline script or style (htmx is configured
// accordingly in the layout), forbids framing (clickjacking) and restricts
// form targets and the base URL. It is applied to UI routes only: /v1 answers
// JSON to programs and needs none of it.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		h := rw.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(rw, r)
	})
}
