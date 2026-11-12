// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// middleware.go: session authentication, the role check and the two CSRF
// layers, as wrappers a router applies per route class.
//
// CSRF defence has three layers, all on:
//  1. SameSite=Lax on the session cookie (NewCookie);
//  2. http.CrossOriginProtection (CrossOrigin): rejects non-safe requests the
//     browser marks cross-site (Sec-Fetch-Site, or Origin against Host). It is
//     the only layer that also covers the login form, where no session and
//     hence no token exists yet;
//  3. a per-session synchronizer token (CSRF) in a form field or the
//     X-CSRF-Token header, for every non-GET request with a session.
//
// Failure model: every cause of "no valid session" (no cookie, malformed,
// unknown, expired, idle, user disabled) is the same outcome, so nothing says
// which. A store failure is a 503, never a redirect to the login page.
package webauth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

const (
	// RoleViewer and RoleAdmin mirror store.RoleViewer and store.RoleAdmin.
	RoleViewer = store.RoleViewer
	RoleAdmin  = store.RoleAdmin

	// CSRFHeader is the header htmx requests carry; CSRFField the form field.
	CSRFHeader = "X-CSRF-Token"
	CSRFField  = "csrf_token"

	// MaxFormBytes bounds a UI request body (forms are tiny).
	MaxFormBytes = 64 << 10
)

// mustChangeAllowed are the only paths a user who must change their password
// may use: the change form itself, logout, and static assets (login page style).
var mustChangeAllowed = map[string]bool{"/account": true, "/account/password": true, "/logout": true}

// SessionStore is what Manager needs from the store.
type SessionStore interface {
	CreateSession(ctx context.Context, s store.Session) error
	SessionByTokenHash(ctx context.Context, hash []byte, now time.Time, idle time.Duration) (store.SessionPrincipal, error)
	TouchSession(ctx context.Context, id int64, now time.Time) error
	DeleteSession(ctx context.Context, hash []byte) error
}

// Manager issues sessions and protects routes.
type Manager struct {
	Store  SessionStore
	Now    func() time.Time // injected clock
	MaxAge time.Duration    // absolute session lifetime (auth.session_max_age)
	Idle   time.Duration    // idle timeout (auth.session_idle)
	Secure bool             // Secure + __Host- cookie (auth.cookie_secure)
	Log    *slog.Logger
	// Deny renders an error page for status 401 or 403 where the middleware
	// refuses a request that cannot be redirected. Nil: a plain-text error.
	Deny func(w http.ResponseWriter, r *http.Request, status int)
}

// TouchEvery is how often a session's last-seen time is written at most; the
// store enforces it too, but checking here keeps ordinary requests from
// opening a write transaction at all.
const TouchEvery = time.Minute

// Create stores a new session for userID and returns the cookie token. A
// fresh random token is generated on every call and never taken from the
// request, so a cookie planted before login (session fixation) is never reused.
//
// passwordHash is the hash of the credential the login verified (after a
// rehash: the new one). The store inserts the session only if the user still
// has exactly that hash and is not disabled, so a reset, a password change or a
// disable that committed while the login was hashing yields store.ErrCredentialChanged
// and no session. That check is by value, not by time: timestamps are whole
// seconds, and a clock comparison would let a login that started in the same
// second as a reset through.
//
// authVersion is the user's auth_version as read with the user, before hashing.
// It also catches a disable followed by an enable, which leaves the hash as it was.
func (m *Manager) Create(ctx context.Context, userID int64, passwordHash string, authVersion int64) (token string, err error) {
	token, s, err := m.PrepareSession()
	if err != nil {
		return "", err
	}
	s.UserID, s.PasswordHash, s.AuthVersion = userID, passwordHash, authVersion
	if err := m.Store.CreateSession(ctx, s); err != nil {
		return "", err
	}
	return token, nil
}

// PrepareSession returns a fresh cookie token and the session record for it
// (token hash, CSRF secret, created and expiry times), with no user yet. The
// second-factor login stores it itself, inside the transaction that consumes the
// login challenge (store.CompleteLogin), and takes the user from the challenge.
// The token is generated here and never taken from a request.
func (m *Manager) PrepareSession() (token string, s store.Session, err error) {
	token, hash, err := NewToken()
	if err != nil {
		return "", store.Session{}, err
	}
	csrf := make([]byte, secretBytes)
	if _, err := rand.Read(csrf); err != nil {
		return "", store.Session{}, fmt.Errorf("generate csrf token: %w", err)
	}
	now := m.Now()
	return token, store.Session{TokenHash: hash, CSRF: csrf, CreatedAt: now, ExpiresAt: now.Add(m.MaxAge)}, nil
}

// Destroy deletes the session behind the request's cookie, if any.
func (m *Manager) Destroy(ctx context.Context, r *http.Request) error {
	if tok := m.cookieToken(r); tok != "" {
		return m.Store.DeleteSession(ctx, HashToken(tok))
	}
	return nil
}

func (m *Manager) cookieToken(r *http.Request) string {
	c, err := r.Cookie(CookieName(m.Secure))
	if err != nil || ParseToken(c.Value) != nil {
		return ""
	}
	return c.Value
}

var errNoSession = errors.New("no valid session")

// Authenticate resolves the request's cookie to a Principal. errNoSession for
// every kind of invalid session; any other error means the store is unwell.
func (m *Manager) Authenticate(r *http.Request) (Principal, error) {
	tok := m.cookieToken(r)
	if tok == "" {
		return Principal{}, errNoSession
	}
	hash := HashToken(tok)
	now := m.Now()
	sp, err := m.Store.SessionByTokenHash(r.Context(), hash, now, m.Idle)
	if errors.Is(err, store.ErrNotFound) {
		return Principal{}, errNoSession
	}
	if err != nil {
		return Principal{}, err
	}
	// Activity, written at most once a minute (also guarded inside the store). A failed touch must
	// not fail the request: the session is valid, only its idle clock is stale.
	if now.Sub(sp.LastSeen) >= TouchEvery {
		if err := m.Store.TouchSession(r.Context(), sp.SessionID, now); err != nil {
			m.Log.Warn("cannot record session activity", "error", err.Error())
		}
	}
	return Principal{
		SessionID: sp.SessionID, UserID: sp.UserID, Email: sp.Email, Name: sp.Name, Role: sp.Role,
		MustChange: sp.MustChange, TokenHash: hash, csrf: sp.CSRF,
	}, nil
}

func (m *Manager) deny(w http.ResponseWriter, r *http.Request, status int) {
	w.Header().Set("Cache-Control", "no-store")
	if m.Deny != nil {
		m.Deny(w, r, status)
		return
	}
	http.Error(w, http.StatusText(status), status)
}

// RequireUser lets only a signed-in user through, with the Principal in the
// request context. Without a session: a GET is redirected to the login page
// (303, with the sanitised return path), an htmx request gets 401 plus
// HX-Redirect so the whole tab goes to the login page instead of swapping an
// error into a fragment, and any other method gets 401.
func (m *Manager) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := m.Authenticate(r)
		switch {
		case errors.Is(err, errNoSession):
			m.unauthenticated(w, r)
			return
		case err != nil:
			m.Log.Error("session lookup failed", "error", err.Error())
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		// Rule: a user whose password was issued by an admin or the CLI must change
		// it before doing anything else. Enforced here, on the server, for every
		// route, not by hiding links.
		if p.MustChange && !mustChangeAllowed[r.URL.Path] {
			if r.Method == http.MethodGet && r.Header.Get("HX-Request") == "" {
				w.Header().Set("Cache-Control", "no-store")
				http.Redirect(w, r, "/account", http.StatusSeeOther)
			} else {
				if r.Header.Get("HX-Request") != "" {
					w.Header().Set("HX-Redirect", "/account")
				}
				m.deny(w, r, http.StatusForbidden)
			}
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

func (m *Manager) unauthenticated(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.Header.Get("HX-Request") != "":
		w.Header().Set("HX-Redirect", "/login")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case r.Method == http.MethodGet:
		to := "/login"
		if next := SanitizeNext(r.URL.RequestURI()); next != "/" {
			to += "?next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, to, http.StatusSeeOther)
	default:
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

// RequireAdmin is RequireUser plus the admin role: a viewer gets 403 and the
// handler never runs. The role comes from the database on every request
// (the session join), not from the cookie.
func (m *Manager) RequireAdmin(next http.Handler) http.Handler {
	return m.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		if !p.IsAdmin() {
			m.deny(w, r, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// CSRF checks the synchronizer token on every non-GET request that reaches it
// (it must sit inside RequireUser, which supplies the Principal). The token
// is read from the X-CSRF-Token header (htmx) or the csrf_token form field.
// Missing or wrong: 403 and the handler never runs.
func (m *Manager) CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		p, ok := FromContext(r.Context())
		// Bound and parse the body once, here, so every handler behind this
		// wrapper reads r.PostForm without a second, unbounded parse.
		r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
		if err := r.ParseForm(); err != nil {
			m.deny(w, r, http.StatusForbidden)
			return
		}
		presented := r.Header.Get(CSRFHeader)
		if presented == "" {
			presented = r.PostForm.Get(CSRFField)
		}
		// !ok means the route was wired without RequireUser: fail closed.
		if !ok || !tokenMatches(p.csrf, presented) {
			m.deny(w, r, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CrossOrigin rejects non-safe cross-origin browser requests (see the package
// comment). It wraps every UI route, including the login form.
func (m *Manager) CrossOrigin(next http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.Log.Warn("cross-origin request refused", "method", r.Method, "path", r.URL.Path,
			"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"))
		m.deny(w, r, http.StatusForbidden)
	}))
	return cop.Handler(next)
}
