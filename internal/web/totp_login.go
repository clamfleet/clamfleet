// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// totp_login.go: the second sign-in step.
//
// A correct password for a user with TOTP creates a login challenge (a row of
// its own, a cookie of its own), not a session. POST /login/totp turns the
// challenge into a session in ONE store transaction (store.CompleteLogin) that
// consumes the challenge, checks the account is exactly as the password step saw
// it, consumes the time step or the recovery code by compare-and-swap and inserts
// the session. This file only decides what the verdict looks like; every
// single-use rule is enforced by the store.
//
// The lessons of the M3 review are applied from the start: the attempt is counted
// BEFORE anything is verified (Throttle.Begin), a fault is an Aborted attempt and
// never somebody's wrong guess, and nothing is decided on timestamps.
//
// Never logged or audited: a submitted code (right or wrong), the secret, a recovery code.
package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/clamfleet/clamfleet/internal/secrets"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

const (
	msgBadCode    = "That code is not valid. Check the time on your phone and try again."
	msgUsedCode   = "That code was already used. Wait for the next one."
	msgLocked     = "Too many wrong codes. Ask an administrator."
	msgNoKey      = "Two-factor sign-in with a code is unavailable on this server. Use a recovery code, or ask an administrator."
	maxCodeLength = 64 // longer than any code, shorter than any abuse
)

// totpKey is the key of the second-factor throttle.
func totpKey(userID int64) string { return "totp:" + strconv.FormatInt(userID, 10) }

// startChallenge is the password step's end for a user with TOTP: it stores a
// login challenge bound to what the password step saw, sets the challenge
// cookie and sends the browser to the code form. No session is created and any
// session cookie the browser came with is dropped (the caller already deleted
// the session row), so the pending login is never a session.
func (w *Web) startChallenge(rw http.ResponseWriter, r *http.Request, user store.User, next, email, ip string, outcome *webauth.Outcome) {
	token, hash, err := webauth.NewChallengeToken()
	if err != nil {
		w.Log.Error("login: cannot create a challenge token", "error", err.Error())
		*outcome = webauth.Aborted
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	now := w.Now()
	err = w.Store.CreateLoginChallenge(r.Context(), store.LoginChallenge{
		TokenHash: hash, UserID: user.ID, AuthVersion: user.AuthVersion, PasswordHash: user.PasswordHash,
		Next: next, CreatedAt: now, ExpiresAt: now.Add(webauth.ChallengeTTL),
	}, now)
	if errors.Is(err, store.ErrCredentialChanged) {
		w.auditCredentialChanged(r, email, ip)
		*outcome = webauth.Aborted
		w.render(rw, http.StatusOK, "login", w.loginView(r, next, genericLoginError))
		return
	}
	if err != nil {
		w.Log.Error("login: cannot create a challenge", "error", err.Error())
		*outcome = webauth.Aborted
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	// Info, not audit: the audit row is written with the final result.
	w.Log.Info("password ok, second factor pending", "client_ip", ip)
	http.SetCookie(rw, webauth.ClearCookie(w.Auth.Secure)) // a stale session cookie must not linger
	http.SetCookie(rw, webauth.NewChallengeCookie(token, w.Auth.Secure))
	rw.Header().Set("Cache-Control", "no-store")
	http.Redirect(rw, r, "/login/totp", http.StatusSeeOther)
}

// challengeFor resolves the request's challenge cookie to a live challenge.
// ok is false for none, malformed, unknown or expired; err is a store fault.
func (w *Web) challengeFor(r *http.Request) (ch store.LoginChallenge, ok bool, err error) {
	tok := webauth.ChallengeTokenFromRequest(r, w.Auth.Secure)
	if tok == "" {
		return store.LoginChallenge{}, false, nil
	}
	ch, err = w.Store.LoginChallenge(r.Context(), webauth.HashToken(tok), w.Now())
	if errors.Is(err, store.ErrNotFound) {
		return store.LoginChallenge{}, false, nil
	}
	return ch, err == nil, err
}

func (w *Web) loginTOTPPage(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")
	if _, err := w.Auth.Authenticate(r); err == nil {
		http.Redirect(rw, r, "/", http.StatusSeeOther)
		return
	}
	_, ok, err := w.challengeFor(r)
	if err != nil {
		w.Log.Error("login: cannot read the challenge", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Redirect(rw, r, "/login", http.StatusSeeOther)
		return
	}
	w.render(rw, http.StatusOK, "login_totp", w.newView(r, "Two-factor sign-in", "", struct{}{}))
}

// loginTOTPSubmit verifies the code and completes the login.
func (w *Web) loginTOTPSubmit(rw http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(rw, r.Body, webauth.MaxFormBytes)
	if err := r.ParseForm(); err != nil {
		w.errorPage(rw, r, http.StatusBadRequest)
		return
	}
	ip := w.ClientIP(r)
	expired := func() {
		http.SetCookie(rw, webauth.ClearChallengeCookie(w.Auth.Secure))
		rw.Header().Set("Cache-Control", "no-store")
		http.Redirect(rw, r, "/login?expired=1", http.StatusSeeOther)
	}
	form := func(status int, msg string) {
		v := w.newView(r, "Two-factor sign-in", "", struct{}{})
		v.Error = msg
		w.render(rw, status, "login_totp", v)
	}
	ch, ok, err := w.challengeFor(r)
	if err != nil {
		w.Log.Error("login: cannot read the challenge", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	if !ok {
		expired()
		return
	}

	// Begin counts this attempt as a failure BEFORE anything is verified, so a
	// burst of parallel guesses cannot all be checked (see Throttle.Begin). The
	// key is the user: a new challenge (a new correct password) does not reset it.
	wait, done := w.TOTPThrottle.Begin(totpKey(ch.UserID))
	if done == nil {
		w.Log.Warn("second factor refused: too many failures", "client_ip", ip, "retry_after", wait.String())
		rw.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		form(http.StatusTooManyRequests, "Too many wrong codes. Wait "+waitText(wait)+" and try again.")
		return
	}
	outcome := webauth.Aborted // until there is a verdict: a server fault is nobody's wrong guess
	defer func() { done(outcome) }()

	st, err := w.Store.UserTOTP(r.Context(), ch.UserID)
	if err != nil {
		w.Log.Error("login: cannot read the second-factor state", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	actor := store.Audit{Kind: store.ActorUser, Actor: st.Email}
	// fail is a wrong guess: it is counted in the store (persistent lock), audited
	// with its reason, and keeps the throttle's provisional failure.
	fail := func(reason, msg string) {
		outcome = webauth.Failed
		w.Log.Warn("second factor failed", "client_ip", ip, "reason", reason)
		if _, err := w.Store.RecordSecondFactorFailure(r.Context(), ch.UserID, store.SecondFactorLockLimit, w.Now(), actor,
			map[string]string{"ip": ip, "reason": reason}); err != nil {
			w.Log.Error("cannot record the second-factor failure", "error", err.Error())
		}
		form(http.StatusOK, msg)
	}

	if st.Disabled || !st.Enabled || st.AuthVersion != ch.AuthVersion {
		// The account changed since the password step: this challenge is dead.
		w.auditCredentialChanged(r, st.Email, ip)
		expired()
		return
	}
	if st.Failures >= store.SecondFactorLockLimit {
		// Locked: rate-bounded like any attempt (Failed), and audited, but not counted again.
		outcome = webauth.Failed
		w.Log.Warn("second factor refused: locked", "client_ip", ip)
		if err := w.Store.RecordAudit(r.Context(), w.Now(), actor, store.ActionUserLoginFailed, store.TargetUser, st.Email,
			map[string]string{"ip": ip, "reason": "second factor locked"}); err != nil {
			w.Log.Error("cannot audit failed login", "error", err.Error())
		}
		form(http.StatusOK, msgLocked)
		return
	}

	code := r.PostForm.Get("code")
	complete := store.CompleteLogin{ChallengeHash: webauth.HashToken(webauth.ChallengeTokenFromRequest(r, w.Auth.Secure)), Limit: store.SecondFactorLockLimit}
	mfa := ""
	if len(code) > maxCodeLength {
		fail("bad code", msgBadCode)
		return
	}
	if _, isTOTP := webauth.NormalizeTOTPCode(code); isTOTP {
		mfa = "totp"
		if w.Keys == nil {
			// Never fall back to "password only": no key, no code login.
			w.Log.Warn("second factor unavailable: the server has no secret key file", "client_ip", ip)
			form(http.StatusServiceUnavailable, msgNoKey)
			return
		}
		secret, err := w.Keys.Open(secrets.PurposeTOTP, st.Sealed, uint64(ch.UserID))
		if err != nil {
			// The error never holds bytes of the key or the secret.
			w.Log.Error("login: cannot open the TOTP secret", "error", err.Error())
			w.errorPage(rw, r, http.StatusInternalServerError)
			return
		}
		last := webauth.NoStep
		if st.LastStep != nil {
			last = *st.LastStep
		}
		step, matched := webauth.MatchTOTP(secret, code, w.Now(), last)
		if !matched {
			// Without the replay guard, does it match? Then it is the right code for a
			// step that was already used. The store decides what that means, atomically:
			// ErrReplay while the challenge is live (a replay), ErrNotFound if a parallel
			// request with the same code has just completed it (a lost race, not a guess).
			// Deciding here, on state read a moment earlier, would count the loser of
			// a race as a wrong guess.
			var again bool
			if step, again = webauth.MatchTOTP(secret, code, w.Now(), webauth.NoStep); !again {
				fail("bad code", msgBadCode)
				return
			}
		}
		complete.Step = &step
	} else {
		mfa = "recovery_code"
		norm, err := webauth.NormalizeRecoveryCode(code)
		if err != nil {
			fail("bad recovery code", msgBadCode)
			return
		}
		complete.RecoveryHash = webauth.HashRecoveryCode(norm)
	}

	token, sess, err := w.Auth.PrepareSession()
	if err != nil {
		w.Log.Error("login: cannot prepare a session", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	complete.Session = sess
	err = w.Store.CompleteLogin(r.Context(), complete, w.Now(), map[string]string{"ip": ip, "mfa": mfa})
	switch {
	case errors.Is(err, store.ErrReplay):
		fail("code already used", msgUsedCode)
		return
	case errors.Is(err, store.ErrBadRecovery):
		fail("bad recovery code", msgBadCode)
		return
	case errors.Is(err, store.ErrSecondFactorLocked):
		outcome = webauth.Failed
		form(http.StatusOK, msgLocked)
		return
	case errors.Is(err, store.ErrNotFound):
		// Used by a parallel request, or expired: not a wrong guess.
		expired()
		return
	case errors.Is(err, store.ErrCredentialChanged):
		w.auditCredentialChanged(r, st.Email, ip)
		expired()
		return
	case err != nil:
		w.Log.Error("login: cannot complete", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	outcome = webauth.Succeeded

	// Any session the browser came with is dropped (fixation, as at the password step).
	if err := w.Auth.Destroy(r.Context(), r); err != nil {
		w.Log.Warn("cannot delete the previous session", "error", err.Error())
	}
	next := ch.Next
	if u, err := w.Store.UserByEmail(r.Context(), st.Email); err == nil && u.MustChange {
		next = "/account"
	}
	if mfa == "recovery_code" {
		if left, err := w.Store.RecoveryCodesLeft(r.Context(), ch.UserID); err == nil {
			next = withRecoveryLeft(next, left)
		}
	}
	http.SetCookie(rw, webauth.ClearChallengeCookie(w.Auth.Secure))
	http.SetCookie(rw, webauth.NewCookie(token, w.Auth.Secure))
	rw.Header().Set("Cache-Control", "no-store")
	http.Redirect(rw, r, next, http.StatusSeeOther)
}

// withRecoveryLeft appends ?recovery_left=N to a local path. The page then shows
// how many recovery codes remain (recoveryNotice); the value is a number the
// notice re-parses, never echoed as text.
func withRecoveryLeft(next string, left int) string {
	u, err := url.Parse(next)
	if err != nil {
		return next
	}
	q := u.Query()
	q.Set("recovery_left", strconv.Itoa(left))
	u.RawQuery = q.Encode()
	return u.String()
}

// recoveryNotice is the banner after a recovery-code sign-in, from the
// recovery_left query parameter. Only an integer 0..10 is honoured.
func recoveryNotice(r *http.Request) string {
	n, err := strconv.Atoi(r.URL.Query().Get("recovery_left"))
	if err != nil || n < 0 || n > webauth.RecoveryCodeCount {
		return ""
	}
	if n == 1 {
		return "You signed in with a recovery code: 1 recovery code left."
	}
	return "You signed in with a recovery code: " + strconv.Itoa(n) + " recovery codes left."
}
