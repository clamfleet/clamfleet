// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// oidc.go: the console side of OpenID Connect sign-in (docs/plans/milestone-6.md 4.17, docs/auth.md).
//
//	POST /login/oidc          starts a sign-in: a state row, the state cookie, 303 to the provider.
//	GET  /login/oidc/callback finishes it: takes the state row (once), checks it, exchanges the code.
//
// Why the pieces are what they are:
//   - The state row is one-time (DELETE ... RETURNING) and found only through the hash of the
//     state cookie. A callback URL replayed, or opened in another browser, finds no row. The row
//     is gone whatever the callback does next, so a failed attempt cannot be retried with the
//     same URL.
//   - The state PARAMETER must also equal the stored one, in constant time: it ties the callback
//     to the request this browser made (login CSRF).
//   - The state cookie is SameSite=Lax, not Strict, and the callback is a GET: the provider sends
//     the browser back with a top-level navigation from another site, which Lax allows and Strict
//     does not. Only a real browser can prove this (e2e/web/tests/sso.spec.ts).
//   - The start route is a public-class POST: no session exists yet, so there is no CSRF token; the
//     cross-origin check (Sec-Fetch-Site / Origin) covers it.
//   - Nothing the provider sends (code, tokens) or makes (state, nonce, verifier) is logged. The
//     request log records the path only, never the query.
package web

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/clamfleet/clamfleet/internal/extauth"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

// OIDCProvider is the OpenID Connect sign-in (*extauth.OIDCClient); an interface so tests and the
// console do not depend on how it is built. nil means auth.oidc is off.
type OIDCProvider interface {
	Begin(ctx context.Context) (extauth.AuthRequest, error)
	Exchange(ctx context.Context, code, verifier, nonce string) (extauth.Identity, error)
}

const (
	expiredText     = "This sign-in has expired or was already used. Start again."
	unavailableText = "Single sign-on is not available right now. Try again in a few minutes."
	maxCodeBytes    = 2048
	maxProviderText = 200
)

// oidcAuditActor is the audit actor of an OIDC failure before any identity is known.
const oidcAuditActor = "oidc"

// oidcStart begins a sign-in.
func (w *Web) oidcStart(rw http.ResponseWriter, r *http.Request) {
	if w.OIDC == nil {
		w.statusPage(rw, r, http.StatusNotFound, notAvailableTxt, "error-sso-unavailable")
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, webauth.MaxFormBytes)
	if err := r.ParseForm(); err != nil {
		w.errorPage(rw, r, http.StatusBadRequest)
		return
	}
	next := webauth.SanitizeNext(r.PostForm.Get("next"))
	ip := w.ClientIP(r)
	req, err := w.OIDC.Begin(r.Context())
	if err != nil {
		w.Log.Error("oidc: cannot start a sign-in", "client_ip", ip, "error", err.Error())
		w.auditLoginFailed(r, oidcAuditActor, ip, "oidc: unavailable")
		w.statusPage(rw, r, http.StatusServiceUnavailable, unavailableText, "error-sso-unavailable")
		return
	}
	token, hash, err := webauth.NewOIDCToken()
	if err != nil {
		w.Log.Error("oidc: cannot make a state token", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	now := w.Now()
	err = w.Store.CreateOIDCState(r.Context(), store.OIDCState{
		TokenHash: hash, State: req.State, Nonce: req.Nonce, CodeVerifier: req.CodeVerifier, NextPath: next,
		CreatedAt: now, ExpiresAt: now.Add(webauth.OIDCStateLifetime),
	})
	switch {
	case errors.Is(err, store.ErrTooManyOIDCStates):
		w.Log.Warn("oidc: too many sign-ins in progress", "client_ip", ip)
		rw.Header().Set("Retry-After", "60")
		w.statusPage(rw, r, http.StatusServiceUnavailable, unavailableText, "error-sso-unavailable")
		return
	case err != nil:
		w.Log.Error("oidc: cannot store the sign-in state", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	http.SetCookie(rw, webauth.NewOIDCCookie(token, w.Auth.Secure))
	rw.Header().Set("Cache-Control", "no-store")
	http.Redirect(rw, r, req.URL, http.StatusSeeOther)
}

// oidcCallback finishes a sign-in.
func (w *Web) oidcCallback(rw http.ResponseWriter, r *http.Request) {
	if w.OIDC == nil {
		w.statusPage(rw, r, http.StatusNotFound, notAvailableTxt, "error-sso-unavailable")
		return
	}
	ip := w.ClientIP(r)
	// The cookie is spent by this request, success or not.
	http.SetCookie(rw, webauth.ClearOIDCCookie(w.Auth.Secure))
	expired := func(reason string) {
		w.Log.Warn("oidc: sign-in refused", "client_ip", ip, "reason", reason)
		w.auditLoginFailed(r, oidcAuditActor, ip, "oidc: "+reason)
		w.statusPage(rw, r, http.StatusBadRequest, expiredText, "error-sso-expired")
	}
	c, err := r.Cookie(webauth.OIDCCookieName(w.Auth.Secure))
	if err != nil || webauth.ParseOIDCToken(c.Value) != nil {
		expired("no state cookie")
		return
	}
	// Taken first and unconditionally: from here on the state is gone, whatever else is wrong.
	st, err := w.Store.TakeOIDCState(r.Context(), webauth.HashToken(c.Value), w.Now())
	if errors.Is(err, store.ErrNotFound) {
		expired("state used, expired or unknown")
		return
	}
	if err != nil {
		w.Log.Error("oidc: cannot read the sign-in state", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		expired("state parameter does not match")
		return
	}
	if e := q.Get("error"); e != "" {
		// The provider refused or the user cancelled. Its description is shown, escaped by the
		// template and cut to 200 bytes; the error code only when it is a plain token.
		w.Log.Warn("oidc: the provider returned an error", "client_ip", ip, "error_code", oauthCode(e))
		w.auditLoginFailed(r, oidcAuditActor, ip, "oidc: provider error "+oauthCode(e))
		msg := "The identity provider did not complete the sign-in"
		if d := cutText(q.Get("error_description"), maxProviderText); d != "" {
			msg += ": " + d
		}
		w.statusPage(rw, r, http.StatusForbidden, msg+".", "error-sso-provider")
		return
	}
	code := q.Get("code")
	if code == "" || len(code) > maxCodeBytes {
		expired("no code")
		return
	}
	id, err := w.OIDC.Exchange(r.Context(), code, st.CodeVerifier, st.Nonce)
	if err != nil {
		var refusal *extauth.Refusal
		switch {
		case errors.Is(err, extauth.ErrUnavailable):
			w.Log.Error("oidc: the provider is unavailable", "client_ip", ip, "error", err.Error())
			w.auditLoginFailed(r, oidcAuditActor, ip, "oidc: unavailable")
			w.statusPage(rw, r, http.StatusServiceUnavailable, unavailableText, "error-sso-unavailable")
		case errors.As(err, &refusal) && refusal.NoRole:
			w.Log.Warn("login refused: no role", "client_ip", ip, "source", store.AuthOIDC)
			w.auditLoginFailed(r, oidcAuditActor, ip, "no role")
			w.statusPage(rw, r, http.StatusForbidden, noRoleText, "error-no-role")
		case errors.As(err, &refusal):
			w.Log.Warn("oidc: sign-in refused", "client_ip", ip, "reason", refusal.Reason)
			w.auditLoginFailed(r, oidcAuditActor, ip, refusal.Reason)
			w.statusPage(rw, r, http.StatusForbidden, notAvailableTxt, "error-sso-unavailable")
		default:
			w.Log.Error("oidc: exchange failed", "error", err.Error())
			w.errorPage(rw, r, http.StatusInternalServerError)
		}
		return
	}
	outcome := webauth.Aborted // OIDC sign-ins have no per-identifier throttle: nothing here is a guessable secret
	w.completeExternal(rw, r, id.ExternalIdentity, "", st.NextPath, ip, &outcome)
}

// oauthCode keeps an OAuth error code only if it is a short lower-case token (RFC 6749 section 4.1.2.1).
func oauthCode(s string) string {
	if s == "" || len(s) > 40 {
		return "unknown"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r == '_') {
			return "unknown"
		}
	}
	return s
}

// cutText cuts provider-supplied text to n bytes on a rune boundary and drops control characters.
func cutText(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if r < ' ' || r == 0x7f {
			continue
		}
		if b.Len()+len(string(r)) > n {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
