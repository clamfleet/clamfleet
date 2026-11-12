// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// auth.go: login, logout and the signed-in user's own password change.
//
// Security-relevant choices, all deliberate:
//   - One generic failure text for every cause (unknown email, wrong password,
//     disabled account, no local password), and a real hash verification (or a
//     dummy one) on every attempt that reaches the hasher, so neither the text
//     nor the response time says whether an email exists.
//   - Every failure is audited (user.login.failed, with the client IP and the
//     real reason, for the operator) and logged at warn with the IP only: the
//     typed email lives in the audit row, not in the log stream.
//   - A fresh session token at every login; a cookie sent with the login
//     request is ignored and its session deleted (no session fixation).
//   - The per-email backoff (webauth.Throttle) refuses before hashing, so a
//     flood against one name costs no argon2 memory.
package web

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

// genericLoginError is the only text a failed sign-in shows.
const genericLoginError = "Invalid email or password."

// maxLoginPassword: anything longer cannot be a valid password (the policy
// maximum is 256 bytes); it is refused without hashing it.
const maxLoginPassword = webauth.MaxPasswordLen

type loginBody struct {
	Next          string
	NoUsers       bool
	LocalDisabled bool
}

func (w *Web) loginView(r *http.Request, next, errMsg string) *view {
	body := loginBody{Next: next, LocalDisabled: !w.LocalEnabled}
	// A hint, not a secret: on a fresh install the operator needs to know what to do.
	if n, err := w.Store.CountUsers(r.Context()); err == nil && n == 0 {
		body.NoUsers = true
	}
	v := w.newView(r, "Sign in", "", body)
	v.Error = errMsg
	return v
}

// loginPage shows the form; a user who is signed in already goes on.
func (w *Web) loginPage(rw http.ResponseWriter, r *http.Request) {
	next := webauth.SanitizeNext(r.URL.Query().Get("next"))
	if p, err := w.Auth.Authenticate(r); err == nil {
		target := next
		if p.MustChange {
			target = "/account"
		}
		rw.Header().Set("Cache-Control", "no-store")
		http.Redirect(rw, r, target, http.StatusSeeOther)
		return
	}
	w.render(rw, http.StatusOK, "login", w.loginView(r, next, ""))
}

// loginSubmit checks the credentials and starts a session.
func (w *Web) loginSubmit(rw http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(rw, r.Body, webauth.MaxFormBytes)
	if err := r.ParseForm(); err != nil {
		w.errorPage(rw, r, http.StatusBadRequest)
		return
	}
	next := webauth.SanitizeNext(r.PostForm.Get("next"))
	if !w.LocalEnabled {
		w.render(rw, http.StatusForbidden, "login", w.loginView(r, next, ""))
		return
	}
	email := store.TruncateForAudit(r.PostForm.Get("email"))
	password := r.PostForm.Get("password")
	ip := w.ClientIP(r)

	// Begin counts this attempt as a failure BEFORE any hashing, so a burst of
	// parallel requests for one email cannot all get past the check (see Throttle.Begin).
	wait, done := w.Throttle.Begin(email)
	if done == nil {
		w.Log.Warn("login refused: too many failures", "client_ip", ip, "retry_after", wait.Round(time.Second).String())
		rw.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		w.render(rw, http.StatusTooManyRequests, "login", w.loginView(r, next,
			"Too many failed attempts. Wait "+waitText(wait)+" and try again."))
		return
	}
	outcome := webauth.Aborted // until there is a verdict: a server fault is nobody's failed guess
	defer func() { done(outcome) }()

	// The session is dated from HERE, before the slow hash: if a password reset
	// commits while it runs, the session created afterwards is older than the
	// change and the session lookup refuses it (see SessionPrincipalByTokenHash).
	started := w.Now()
	user, reason, err := w.checkPassword(r, email, password)
	if err != nil {
		w.Log.Error("login: store or hasher failed", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	if reason != "" {
		outcome = webauth.Failed
		w.Log.Warn("login failed", "client_ip", ip, "reason", reason)
		// The audit row carries the typed email and the real reason; a failure to
		// write it is logged but never turns a failure into a success.
		if err := w.Store.RecordAudit(r.Context(), w.Now(), store.Audit{Kind: store.ActorUser, Actor: email},
			store.ActionUserLoginFailed, store.TargetUser, email, map[string]string{"ip": ip, "reason": reason}); err != nil {
			w.Log.Error("cannot audit failed login", "error", err.Error())
		}
		w.render(rw, http.StatusOK, "login", w.loginView(r, next, genericLoginError))
		return
	}

	outcome = webauth.Succeeded
	// Drop whatever session the browser came with, then issue a new one. The
	// presented token is never reused (see Manager.Create).
	if err := w.Auth.Destroy(r.Context(), r); err != nil {
		w.Log.Warn("cannot delete the previous session", "error", err.Error())
	}
	// Audit first, session second: if the audit row cannot be written the user is
	// not signed in, instead of being signed in without a record.
	audit := store.Audit{Kind: store.ActorUser, Actor: user.Email}
	if err := w.Store.RecordLogin(r.Context(), user.ID, w.Now(), audit, map[string]string{"ip": ip}); err != nil {
		w.Log.Error("login: cannot record", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	token, err := w.Auth.Create(r.Context(), user.ID, started)
	if err != nil {
		w.Log.Error("login: cannot create session", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	http.SetCookie(rw, webauth.NewCookie(token, w.Auth.Secure))
	rw.Header().Set("Cache-Control", "no-store")
	if user.MustChange {
		next = "/account"
	}
	http.Redirect(rw, r, next, http.StatusSeeOther)
}

// checkPassword verifies the credentials. It returns the user on success, or a
// non-empty reason (for the audit row only) on a plain failure; err is a real
// fault (store or hasher unavailable), which is a 500 and not a failed login.
// It also rehashes the password when the stored parameters are older.
func (w *Web) checkPassword(r *http.Request, email, password string) (user store.User, reason string, err error) {
	ctx := r.Context()
	u, err := w.Store.UserByEmail(ctx, email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		reason = "unknown user"
	case err != nil:
		return store.User{}, "", err
	case u.Disabled:
		reason = "user disabled"
	case u.AuthSource != store.AuthLocal || u.PasswordHash == "":
		reason = "no local password"
	}
	if len(password) > maxLoginPassword {
		password = "" // cannot match; still costs one hash below
		if reason == "" {
			reason = "bad password"
		}
	}
	if reason != "" {
		// Same cost as a real check: no timing oracle on the email.
		return store.User{}, reason, w.Hasher.VerifyDummy(ctx, password)
	}
	ok, needsRehash, err := w.Hasher.Verify(ctx, password, u.PasswordHash)
	if err != nil {
		return store.User{}, "", err
	}
	if !ok {
		return store.User{}, "bad password", nil
	}
	if needsRehash {
		// Best effort: the login succeeded; a failed upgrade is retried next time.
		if h, err := w.Hasher.Hash(ctx, password); err != nil {
			w.Log.Warn("cannot rehash password", "error", err.Error())
		} else if err := w.Store.RehashPassword(ctx, u.ID, u.PasswordHash, h, w.Now()); err != nil {
			w.Log.Warn("cannot store rehashed password", "error", err.Error())
		}
	}
	return u, "", nil
}

func waitText(d time.Duration) string {
	if d < time.Minute {
		return strconv.Itoa(int(d.Seconds())+1) + " seconds"
	}
	return strconv.Itoa(int(d.Minutes())+1) + " minutes"
}

// logout ends the session (user class, CSRF-checked by the wrapper).
func (w *Web) logout(rw http.ResponseWriter, r *http.Request) {
	p, _ := webauth.FromContext(r.Context())
	if err := w.Auth.Destroy(r.Context(), r); err != nil {
		w.Log.Error("logout: cannot delete session", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	if err := w.Store.RecordAudit(r.Context(), w.Now(), store.Audit{Kind: store.ActorUser, Actor: p.Email},
		store.ActionUserLogout, store.TargetUser, p.Email, map[string]string{"ip": w.ClientIP(r)}); err != nil {
		w.Log.Error("cannot audit logout", "error", err.Error())
	}
	http.SetCookie(rw, webauth.ClearCookie(w.Auth.Secure))
	rw.Header().Set("Cache-Control", "no-store")
	http.Redirect(rw, r, "/login", http.StatusSeeOther)
}

type accountBody struct{ MustChange bool }

func (w *Web) accountPage(rw http.ResponseWriter, r *http.Request) {
	p, _ := webauth.FromContext(r.Context())
	v := w.newView(r, "Account", "account", accountBody{MustChange: p.MustChange})
	if r.URL.Query().Get("changed") == "1" {
		v.Notice = "Password changed."
	}
	w.render(rw, http.StatusOK, "account", v)
}

// accountPassword changes the signed-in user's own password. It needs the
// current password (a hijacked session alone cannot take the account over),
// shares the login backoff (the current-password check is a guessing oracle
// otherwise), applies the policy, and ends every OTHER session of the user.
func (w *Web) accountPassword(rw http.ResponseWriter, r *http.Request) {
	p, _ := webauth.FromContext(r.Context())
	fail := func(status int, msg string) {
		v := w.newView(r, "Account", "account", accountBody{MustChange: p.MustChange})
		v.Error = msg
		w.render(rw, status, "account", v)
	}
	wait, done := w.Throttle.Begin(p.Email)
	if done == nil {
		rw.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		fail(http.StatusTooManyRequests, "Too many failed attempts. Wait "+waitText(wait)+" and try again.")
		return
	}
	outcome := webauth.Aborted
	defer func() { done(outcome) }()
	current, next, again := r.PostForm.Get("current_password"), r.PostForm.Get("new_password"), r.PostForm.Get("new_password2")
	u, err := w.Store.UserByEmail(r.Context(), p.Email)
	if err != nil {
		w.Log.Error("account: cannot read user", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	if u.PasswordHash == "" || len(current) > maxLoginPassword {
		_ = w.Hasher.VerifyDummy(r.Context(), "")
		outcome = webauth.Failed
		fail(http.StatusOK, "The current password is not correct.")
		return
	}
	ok, _, err := w.Hasher.Verify(r.Context(), current, u.PasswordHash)
	if err != nil {
		w.Log.Error("account: verify failed", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	if !ok {
		outcome = webauth.Failed
		w.Log.Warn("password change refused: wrong current password", "client_ip", w.ClientIP(r))
		fail(http.StatusOK, "The current password is not correct.")
		return
	}
	outcome = webauth.Succeeded
	switch {
	case next != again:
		fail(http.StatusOK, "The two new passwords do not match.")
		return
	case next == current:
		fail(http.StatusOK, "Choose a password different from the current one.")
		return
	}
	if err := webauth.CheckPolicy(next); err != nil {
		fail(http.StatusOK, policyText(err))
		return
	}
	hash, err := w.Hasher.Hash(r.Context(), next)
	if err != nil {
		w.Log.Error("account: hash failed", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	err = w.Store.SetPassword(r.Context(), u.ID, store.PasswordChange{Hash: hash, Self: true, KeepSession: p.TokenHash},
		w.Now(), store.Audit{Kind: store.ActorUser, Actor: p.Email})
	if err != nil {
		w.Log.Error("account: cannot store password", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	http.Redirect(rw, r, "/account?changed=1", http.StatusSeeOther)
}

// policyText turns a policy error into the sentence shown to the user (the
// error text is ours, never user input).
func policyText(err error) string {
	return "That password is not acceptable: " + trimPolicy(err.Error()) + "."
}

func trimPolicy(s string) string {
	const prefix = "password policy: "
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}
