// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// extlogin.go: external sign-in in the console: LDAP through the login form (this file),
// and the shared step that turns a verified external identity into a user and a session.
// OIDC has its own routes (oidc.go) and ends in the same completeExternal.
//
// Rules, all deliberate (docs/plans/milestone-6.md 4.15 to 4.19; docs/auth.md):
//   - A local account with exactly the typed email is tried first and LDAP is then never
//     asked (decision 18): a directory entry cannot shadow a local break-glass admin.
//   - The identity of an external user is the provider's stable id, never the email, and
//     an email that belongs to ANOTHER user refuses the sign-in (decision 19). Nothing is
//     linked automatically: that is the classic account takeover.
//   - Refusals and faults are told apart. A wrong password, an unknown name or a missing
//     role is the user's: the generic text (or "no role"), audited with the real reason,
//     counted by the throttle where it was a guess. A directory that is down is the
//     server's: a 503 page, audited, and no throttle count.
//   - No password, DN of a failed search, token or code in a log line. The audit row of a
//     failed sign-in carries the typed identifier (truncated, as for local sign-ins), the
//     IP and the reason; the DN appears only in the row of a SUCCESSFUL sign-in.
package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/clamfleet/clamfleet/internal/extauth"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

// Directory is the LDAP sign-in (*extauth.Directory); an interface so the console does not
// depend on how it is built, and nil means LDAP is off.
type Directory interface {
	Authenticate(ctx context.Context, username, password string) (extauth.Identity, error)
}

// isLocalAccount reports whether a LOCAL user has exactly this email (the identifier is an
// email address and the account's source is local).
func (w *Web) isLocalAccount(r *http.Request, identifier string) (bool, error) {
	if !w.LocalEnabled {
		return false, nil
	}
	if _, err := store.NormalizeEmail(identifier); err != nil {
		return false, nil
	}
	u, err := w.Store.UserByEmail(r.Context(), identifier)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	case err != nil:
		return false, err
	}
	return u.AuthSource == store.AuthLocal, nil
}

// ldapLogin signs in through the directory. It writes the response in every case.
func (w *Web) ldapLogin(rw http.ResponseWriter, r *http.Request, identifier, password, next, ip string, outcome *webauth.Outcome) {
	if len(password) > maxLoginPassword {
		// Cannot be a password (the policy maximum): refused without a network round trip.
		password = ""
	}
	id, err := w.LDAP.Authenticate(r.Context(), identifier, password)
	if err != nil {
		var refusal *extauth.Refusal
		switch {
		case errors.Is(err, extauth.ErrUnavailable):
			// The directory's fault: nobody guessed anything, so the attempt is taken back.
			*outcome = webauth.Aborted
			w.Log.Error("login: the directory is unavailable", "client_ip", ip, "error", err.Error())
			w.auditLoginFailed(r, identifier, ip, "ldap: unavailable")
			w.statusPage(rw, r, http.StatusServiceUnavailable, "The directory could not be reached. Try again in a few minutes.", "error-sso-unavailable")
		case errors.As(err, &refusal) && refusal.NoRole:
			// The password was right: not a wrong guess. Tell the user what to ask for.
			*outcome = webauth.Aborted
			w.Log.Warn("login refused: no role", "client_ip", ip, "source", store.AuthLDAP)
			w.auditLoginFailed(r, identifier, ip, "no role")
			w.statusPage(rw, r, http.StatusForbidden, noRoleText, "error-no-role")
		case errors.As(err, &refusal):
			*outcome = webauth.Failed
			w.Log.Warn("login failed", "client_ip", ip, "reason", refusal.Reason)
			w.auditLoginFailed(r, identifier, ip, refusal.Reason)
			w.render(rw, http.StatusOK, "login", w.loginView(r, next, genericLoginError))
		default:
			w.Log.Error("login: directory check failed", "error", err.Error())
			w.errorPage(rw, r, http.StatusInternalServerError)
		}
		return
	}
	w.completeExternal(rw, r, id.ExternalIdentity, id.DN, next, ip, outcome)
}

const (
	noRoleText      = "No role is assigned to your account. Ask an administrator to add you to a group that has access to ClamFleet."
	notAvailableTxt = "This sign-in method is not available for this account."
)

// auditLoginFailed records a failed external sign-in: the identifier as typed (truncated),
// the IP and the real reason. A failure to write it is logged, never turned into a success.
func (w *Web) auditLoginFailed(r *http.Request, identifier, ip, reason string) {
	identifier = store.TruncateForAudit(identifier)
	if err := w.Store.RecordAudit(r.Context(), w.Now(), store.Audit{Kind: store.ActorUser, Actor: identifier},
		store.ActionUserLoginFailed, store.TargetUser, identifier, map[string]string{"ip": ip, "reason": reason}); err != nil {
		w.Log.Error("cannot audit failed login", "error", err.Error())
	}
}

// completeExternal turns a verified identity into a user and a session, in ONE transaction
// (store.ExternalLogin), sets the cookie and redirects. It writes the response in every case
// and sets outcome for the throttle. dn is the LDAP DN ("" for OIDC), recorded on success only.
func (w *Web) completeExternal(rw http.ResponseWriter, r *http.Request, id store.ExternalIdentity, dn, next, ip string, outcome *webauth.Outcome) {
	// Drop whatever session the browser came with, then issue a new one: no session fixation.
	if err := w.Auth.Destroy(r.Context(), r); err != nil {
		w.Log.Warn("cannot delete the previous session", "error", err.Error())
	}
	token, sess, err := w.Auth.PrepareSession()
	if err != nil {
		w.Log.Error("login: cannot prepare a session", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	actor := webauth.Principal{Email: id.Email, AuthSource: id.Source, ExternalName: id.ExternalName}.Actor()
	detail := map[string]string{"source": id.Source, "ip": ip}
	if dn != "" {
		detail["dn"] = dn
	}
	_, err = w.Store.ExternalLogin(r.Context(), id, sess, w.Now(), store.Audit{Kind: store.ActorUser, Actor: actor}, detail)
	switch {
	case errors.Is(err, store.ErrEmailInUse):
		// The provider vouched for this person, but their email belongs to another account.
		// Nothing was linked or changed. An administrator resolves it (docs/auth.md).
		*outcome = webauth.Aborted
		w.Log.Warn("login refused: the email belongs to another account", "client_ip", ip, "source", id.Source)
		w.auditLoginFailed(r, actor, ip, "email in use")
		w.statusPage(rw, r, http.StatusForbidden, notAvailableTxt, "error-sso-unavailable")
		return
	case errors.Is(err, store.ErrUserDisabled):
		*outcome = webauth.Failed
		w.Log.Warn("login failed", "client_ip", ip, "reason", "user disabled")
		w.auditLoginFailed(r, actor, ip, "user disabled")
		w.render(rw, http.StatusOK, "login", w.loginView(r, next, genericLoginError))
		return
	case err != nil:
		w.Log.Error("login: cannot sign in the external user", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	*outcome = webauth.Succeeded
	http.SetCookie(rw, webauth.NewCookie(token, w.Auth.Secure))
	rw.Header().Set("Cache-Control", "no-store")
	http.Redirect(rw, r, next, http.StatusSeeOther)
}

// statusPage renders the error page with a specific fixed text and test id (never request text).
func (w *Web) statusPage(rw http.ResponseWriter, r *http.Request, status int, msg, testID string) {
	body := struct {
		Status     int
		StatusText string
		Message    string
		TestID     string
	}{status, http.StatusText(status), msg, testID}
	w.render(rw, status, "error", w.newView(r, "Sign-in", "", body))
}
