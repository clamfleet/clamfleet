// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// totp.go: the signed-in user's own TOTP settings under /account/totp
// (docs/plans/milestone-3b.md 4.6).
//
// Every change asks for the CURRENT PASSWORD again, including the first
// enrolment under auth.local.totp_required: a stolen session cookie alone must
// not be able to plant the attacker's authenticator. The password check shares
// the login backoff (keyed by email), exactly like the password change.
//
// An enrolment in progress is stored SEALED on the session it was started in
// (user_sessions.totp_pending), never in the browser, and only that session can
// confirm it. Confirming needs a valid code from the new authenticator; only
// then does EnableTOTP write the secret (re-sealed for its permanent purpose),
// new recovery codes, and end the user's other sessions.
//
// Pages that show a secret or recovery codes are never cached, and a reload of
// the confirm page re-posts into "no setup in progress", so the codes are shown once.
//
// Never logged or audited: the secret, the otpauth URI, a submitted code, a recovery code.
package web

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/clamfleet/clamfleet/internal/secrets"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

// pendingTTL is how long a started enrolment may wait for its confirming code.
const pendingTTL = 15 * time.Minute

const msgWrongPassword = "The current password is not correct."

type totpPageBody struct {
	Local     bool // TOTP applies to local accounts only
	Available bool // the server has a key file
	Enabled   bool
	Required  bool
	CodesLeft int
	CSRF      string
}

type setupBody struct {
	Secret string // grouped by four, for typing
	URI    string
	CSRF   string
}

type recoveryBody struct {
	Codes []string
	CSRF  string
}

// totpState builds the status block of the TOTP pages for p.
func (w *Web) totpState(r *http.Request, p webauth.Principal) (totpPageBody, error) {
	b := totpPageBody{
		Local: p.AuthSource == store.AuthLocal, Available: w.Keys != nil, Enabled: p.TOTPEnabled,
		Required: w.TOTPRequired, CSRF: p.CSRFToken(),
	}
	if p.TOTPEnabled {
		n, err := w.Store.RecoveryCodesLeft(r.Context(), p.UserID)
		if err != nil {
			return b, err
		}
		b.CodesLeft = n
	}
	return b, nil
}

// showTOTP renders the status page with an optional message.
func (w *Web) showTOTP(rw http.ResponseWriter, r *http.Request, status int, notice, errMsg string) {
	p, _ := webauth.FromContext(r.Context())
	b, err := w.totpState(r, p)
	if err != nil {
		w.Log.Error("totp: cannot read the recovery code count", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	v := w.newView(r, "Two-factor sign-in", "account", b)
	if notice != "" {
		v.Notice = notice
	}
	v.Error = errMsg
	w.render(rw, status, "account_totp", v)
}

func (w *Web) totpPage(rw http.ResponseWriter, r *http.Request) {
	notice := ""
	if r.URL.Query().Get("disabled") == "1" {
		notice = "Two-factor sign-in is turned off."
	}
	w.showTOTP(rw, r, http.StatusOK, notice, "")
}

// localOnly refuses TOTP changes for users that are not local (their second
// factor belongs to the identity provider). It returns false after answering.
func (w *Web) localOnly(rw http.ResponseWriter, r *http.Request, p webauth.Principal) bool {
	if p.AuthSource != store.AuthLocal {
		w.errorPage(rw, r, http.StatusForbidden)
		return false
	}
	return true
}

// reauthenticate checks the posted current password for a TOTP change. It
// shares the password backoff (Throttle, keyed by email) and, like the password
// change, counts the attempt before hashing. It returns false after having
// answered (429, wrong password, or a fault); true means the password is right.
func (w *Web) reauthenticate(rw http.ResponseWriter, r *http.Request, p webauth.Principal, again func(status int, msg string)) bool {
	wait, done := w.Throttle.Begin(p.Email)
	if done == nil {
		rw.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		again(http.StatusTooManyRequests, "Too many failed attempts. Wait "+waitText(wait)+" and try again.")
		return false
	}
	outcome := webauth.Aborted
	defer func() { done(outcome) }()
	password := r.PostForm.Get("current_password")
	u, err := w.Store.UserByEmail(r.Context(), p.Email)
	if err != nil {
		w.Log.Error("totp: cannot read user", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return false
	}
	if u.PasswordHash == "" || len(password) > maxLoginPassword {
		_ = w.Hasher.VerifyDummy(r.Context(), "")
		outcome = webauth.Failed
		again(http.StatusOK, msgWrongPassword)
		return false
	}
	ok, _, err := w.Hasher.Verify(r.Context(), password, u.PasswordHash)
	if err != nil {
		w.Log.Error("totp: password check failed", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return false
	}
	if !ok {
		outcome = webauth.Failed
		w.Log.Warn("totp change refused: wrong current password", "client_ip", w.ClientIP(r))
		again(http.StatusOK, msgWrongPassword)
		return false
	}
	outcome = webauth.Succeeded
	return true
}

// totpSetup starts an enrolment (or a replacement of the authenticator).
func (w *Web) totpSetup(rw http.ResponseWriter, r *http.Request) {
	p, _ := webauth.FromContext(r.Context())
	if !w.localOnly(rw, r, p) {
		return
	}
	if w.Keys == nil {
		w.showTOTP(rw, r, http.StatusServiceUnavailable, "", "Two-factor sign-in is not available on this server: it has no secret key file.")
		return
	}
	if !w.reauthenticate(rw, r, p, func(status int, msg string) { w.showTOTP(rw, r, status, "", msg) }) {
		return
	}
	secret, err := webauth.GenerateTOTPSecret()
	if err != nil {
		w.Log.Error("totp: cannot generate a secret", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	// Sealed for THIS user and THIS session: another session cannot open it.
	sealed, err := w.Keys.Seal(secrets.PurposeTOTPPending, secret, uint64(p.UserID), uint64(p.SessionID))
	if err == nil {
		err = w.Store.SetPendingTOTP(r.Context(), p.SessionID, sealed, w.Now())
	}
	if err != nil {
		w.Log.Error("totp: cannot store the pending secret", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	w.renderSetup(rw, r, p, secret, http.StatusOK, "")
}

func (w *Web) renderSetup(rw http.ResponseWriter, r *http.Request, p webauth.Principal, secret []byte, status int, errMsg string) {
	v := w.newView(r, "Set up two-factor sign-in", "account", setupBody{
		Secret: webauth.FormatTOTPSecret(secret), URI: webauth.TOTPKeyURI(p.Email, secret), CSRF: p.CSRFToken(),
	})
	v.Error = errMsg
	w.render(rw, status, "totp_setup", v)
}

// totpConfirm finishes an enrolment with a code from the new authenticator.
func (w *Web) totpConfirm(rw http.ResponseWriter, r *http.Request) {
	p, _ := webauth.FromContext(r.Context())
	if !w.localOnly(rw, r, p) {
		return
	}
	if w.Keys == nil {
		w.showTOTP(rw, r, http.StatusServiceUnavailable, "", "Two-factor sign-in is not available on this server: it has no secret key file.")
		return
	}
	noSetup := func() { w.showTOTP(rw, r, http.StatusOK, "", "No setup in progress. Start again.") }
	// Only THIS session's pending secret is considered: another session of the
	// same user cannot confirm (or read) it.
	sealed, at, err := w.Store.PendingTOTP(r.Context(), p.SessionID)
	if errors.Is(err, store.ErrNotFound) || err == nil && w.Now().Sub(at) > pendingTTL {
		noSetup()
		return
	}
	if err != nil {
		w.Log.Error("totp: cannot read the pending secret", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	secret, err := w.Keys.Open(secrets.PurposeTOTPPending, sealed, uint64(p.UserID), uint64(p.SessionID))
	if err != nil {
		// A pending secret sealed with a key that is gone (rotation mid-enrolment): start again.
		w.Log.Warn("totp: the pending secret cannot be opened", "error", err.Error())
		noSetup()
		return
	}
	// A confirming code is checked against the new secret only: there is no last
	// step yet. No throttle: the user is signed in, and guessing one's own pending
	// secret gains nothing; the pending secret expires.
	step, ok := webauth.MatchTOTP(secret, r.PostForm.Get("code"), w.Now(), webauth.NoStep)
	if !ok {
		w.renderSetup(rw, r, p, secret, http.StatusOK, "That code is not valid. Check the time on your phone and try again.")
		return
	}
	st, err := w.Store.UserTOTP(r.Context(), p.UserID)
	if err != nil {
		w.Log.Error("totp: cannot read the user", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	codes, err := webauth.GenerateRecoveryCodes(webauth.RecoveryCodeCount)
	if err != nil {
		w.Log.Error("totp: cannot generate recovery codes", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	permanent, err := w.Keys.Seal(secrets.PurposeTOTP, secret, uint64(p.UserID))
	if err != nil {
		w.Log.Error("totp: cannot seal the secret", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	err = w.Store.EnableTOTP(r.Context(), store.EnableTOTP{
		UserID: p.UserID, ExpectedVersion: st.AuthVersion, Sealed: permanent, Step: step,
		RecoveryHashes: hashRecoveryCodes(codes), SessionID: p.SessionID, KeepSession: p.TokenHash,
	}, w.Now(), store.Audit{Kind: store.ActorUser, Actor: p.Email})
	if errors.Is(err, store.ErrCredentialChanged) {
		w.showTOTP(rw, r, http.StatusConflict, "", "Your account changed while you were setting this up. Nothing was saved. Start again.")
		return
	}
	if err != nil {
		w.Log.Error("totp: cannot enable", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	w.renderRecoveryCodes(rw, r, p, codes)
}

func hashRecoveryCodes(codes []string) [][]byte {
	out := make([][]byte, 0, len(codes))
	for _, c := range codes {
		n, _ := webauth.NormalizeRecoveryCode(c) // generated by us: always valid
		out = append(out, webauth.HashRecoveryCode(n))
	}
	return out
}

func (w *Web) renderRecoveryCodes(rw http.ResponseWriter, r *http.Request, p webauth.Principal, codes []string) {
	w.render(rw, http.StatusOK, "recovery_codes", w.newView(r, "Recovery codes", "account", recoveryBody{Codes: codes, CSRF: p.CSRFToken()}))
}

// totpRecoveryCodes replaces all recovery codes with new ones, shown once.
func (w *Web) totpRecoveryCodes(rw http.ResponseWriter, r *http.Request) {
	p, _ := webauth.FromContext(r.Context())
	if !w.localOnly(rw, r, p) {
		return
	}
	if !w.reauthenticate(rw, r, p, func(status int, msg string) { w.showTOTP(rw, r, status, "", msg) }) {
		return
	}
	codes, err := webauth.GenerateRecoveryCodes(webauth.RecoveryCodeCount)
	if err != nil {
		w.Log.Error("totp: cannot generate recovery codes", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	err = w.Store.ReplaceRecoveryCodes(r.Context(), p.UserID, hashRecoveryCodes(codes), w.Now(), store.Audit{Kind: store.ActorUser, Actor: p.Email})
	if errors.Is(err, store.ErrCredentialChanged) {
		w.showTOTP(rw, r, http.StatusConflict, "", "Two-factor sign-in is not turned on, so there are no recovery codes to renew.")
		return
	}
	if err != nil {
		w.Log.Error("totp: cannot replace recovery codes", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	w.renderRecoveryCodes(rw, r, p, codes)
}

// totpDisable turns the user's own TOTP off. Rule: refused while the server
// requires it (auth.local.totp_required), and checked BEFORE the password so a
// required server never even tests the password for this.
func (w *Web) totpDisable(rw http.ResponseWriter, r *http.Request) {
	p, _ := webauth.FromContext(r.Context())
	if !w.localOnly(rw, r, p) {
		return
	}
	if w.TOTPRequired {
		w.showTOTP(rw, r, http.StatusConflict, "", "This server requires two-factor sign-in: it cannot be turned off.")
		return
	}
	if !w.reauthenticate(rw, r, p, func(status int, msg string) { w.showTOTP(rw, r, status, "", msg) }) {
		return
	}
	err := w.Store.DisableTOTP(r.Context(), p.UserID, p.TokenHash, store.ActionTOTPDisable, w.Now(), store.Audit{Kind: store.ActorUser, Actor: p.Email})
	if err != nil {
		w.Log.Error("totp: cannot turn off", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	http.Redirect(rw, r, "/account/totp?disabled=1", http.StatusSeeOther)
}
