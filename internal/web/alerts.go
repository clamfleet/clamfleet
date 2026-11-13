// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// alerts.go: alert target administration in the console (docs/plans/milestone-4.md
// 4.10, 4.11 and 5). Admin class only: recipient addresses and receiver hosts
// are configuration, not fleet state, and a test send makes the server open
// connections, so a viewer sees no menu item and the route table answers 403.
//
// What this file guards:
//   - A webhook URL is a credential (chat tools carry their token in the path).
//     It is sealed with the secret key, shown nowhere after saving (the list
//     shows scheme and host only), never written to the log or the audit row and
//     never echoed back into a page, not even on a validation error.
//   - The signing key is shown exactly once, on a no-store page; rotating it
//     replaces it at once.
//   - Every URL is validated as at create on every change of the URL, and a
//     refused one leaves the stored one untouched.
//   - The test send goes through the same sender and policy as real alerts, is
//     rate limited per target, and never shows a response body.
//   - Every write goes through the store, which writes the audit row with the
//     acting user in the same transaction.
package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/clamfleet/clamfleet/internal/alert"
	"github.com/clamfleet/clamfleet/internal/secrets"
	"github.com/clamfleet/clamfleet/internal/store"
)

// AlertDeps is what the alert pages need besides the store.
type AlertDeps struct {
	// Dispatcher sends the test messages; nil makes the test send answer 503.
	Dispatcher *alert.Dispatcher
	// Policy validates webhook URLs (the same policy the sender enforces).
	Policy alert.Policy
	// EmailEnabled is true when smtp.host is set.
	EmailEnabled bool
	// SMTPPlaintext is true for smtp.tls: none: email targets are then "unencrypted".
	SMTPPlaintext bool
	// PublicURL is public_url ("" shows a banner: links in alerts are missing).
	PublicURL string
}

const (
	// unroutedWindow is how far back the "matched no target" banner looks.
	unroutedWindow = 7 * 24 * time.Hour
)

type alertRow struct {
	Name, Type      string
	Destination     string
	Unencrypted     bool
	MinSeverity     string
	Tags            []string
	Kinds           string
	Enabled         bool
	LastStatus      string
	LastAgo         string
	LastAbs         string
	LastCode        string
	Unreadable      bool // the sealed secret cannot be opened with the loaded keys
	LastResultClass string
}

type logRowView struct {
	When, WhenAbs, Target, Recipient, Host, Kind string
	Attempt                                      string
	Status, Code, Error, Duration                string
}

type alertsBody struct {
	Targets        []alertRow
	Log            []logRowView
	EmailOff       bool
	NoPublicURL    bool
	Unrouted       int64
	UnroutedPlural bool
}

type targetFormView struct {
	Create      bool
	Name, Type  string
	URLDisplay  string // edit: the stored URL's display form
	Plaintext   bool   // the stored target is http://
	To          string
	MinSeverity string
	Tags        string
	State       bool
	Detections  bool
	// Burst is the detection burst limit as text (the form field).
	Burst      string
	Enabled    bool
	Pending    int
	Unreadable bool
	EmailOff   bool
	SMTPPlain  bool
	Log        []logRowView
}

type secretBody struct {
	Target  string
	Key     string
	Rotated bool // true: a new key replaced the old one (rotate or re-entered URL)
}

type testResultView struct {
	Target string
	OK     bool
	Lines  []string
}

func logView(now time.Time, es []store.AlertLogEntry) []logRowView {
	out := make([]logRowView, 0, len(es))
	for _, e := range es {
		v := logRowView{When: ago(now, e.TS), WhenAbs: abs(e.TS), Target: e.TargetName, Recipient: e.Recipient, Host: e.Host, Kind: e.Kind,
			Status: e.Status, Code: e.Code, Error: e.Error}
		if e.Attempt > 0 {
			v.Attempt = strconv.Itoa(e.Attempt)
		}
		if e.DurationMS > 0 {
			v.Duration = strconv.FormatInt(e.DurationMS, 10) + " ms"
		}
		out = append(out, v)
	}
	return out
}

// secretReadable reports whether a webhook target's sealed secret opens with the
// loaded keys (no key file: never).
func (w *Web) secretReadable(t store.AlertTarget) bool {
	if t.Type != store.TargetTypeWebhook {
		return true
	}
	if w.Keys == nil || len(t.Sealed) == 0 {
		return false
	}
	_, err := w.Keys.Open(secrets.PurposeAlertTarget, t.Sealed, uint64(t.ID))
	return err == nil
}

func destination(t store.AlertTarget) (text string, plaintext bool) {
	switch t.Type {
	case store.TargetTypeWebhook:
		var c alert.WebhookConfig
		_ = json.Unmarshal(t.Config, &c)
		return c.URLDisplay, c.Plaintext
	default:
		to, _ := alert.Recipients(t.Config)
		switch len(to) {
		case 0:
			return "(no recipients)", false
		case 1:
			return to[0], false
		default:
			return fmt.Sprintf("%s and %d more", to[0], len(to)-1), false
		}
	}
}

func kindsText(t store.AlertTarget) string {
	switch {
	case t.SendStateChanges && t.SendDetections:
		return "state changes, detections"
	case t.SendStateChanges:
		return "state changes"
	case t.SendDetections:
		return "detections"
	}
	return "none"
}

// alertNotice turns the fixed notice kinds of a redirect into text. The target
// name must be a valid name and the number is clamped, so nothing arbitrary
// from the URL is ever shown.
func alertNotice(r *http.Request) string {
	q := r.URL.Query()
	n, err := store.NormalizeAlertTargetName(q.Get("target"))
	if err != nil {
		return ""
	}
	switch q.Get("notice") {
	case "created":
		return "Alert target " + n + " created."
	case "saved":
		c, _ := strconv.Atoi(q.Get("cancelled"))
		msg := "Alert target " + n + " saved."
		switch {
		case c == 1:
			msg += " 1 pending alert cancelled."
		case c > 1 && c < 1000000:
			msg += " " + strconv.Itoa(c) + " pending alerts cancelled."
		}
		return msg
	case "deleted":
		return "Alert target " + n + " deleted."
	case "test-ok":
		return "Test message to " + n + " delivered."
	case "test-failed":
		return "The test message to " + n + " failed: see Recent deliveries."
	}
	return ""
}

func (w *Web) alertsPage(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	targets, err := w.Store.ListAlertTargets(ctx)
	if err != nil {
		w.Log.Error("alerts: cannot list targets", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	logs, err := w.Store.AlertLog(ctx, store.AlertLogFilter{Limit: 50})
	if err != nil {
		w.Log.Error("alerts: cannot read the log", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	now := w.Now()
	unrouted, err := w.Store.UnroutedDetections(ctx, now.Add(-unroutedWindow))
	if err != nil {
		w.Log.Error("alerts: cannot count unrouted detections", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	b := alertsBody{EmailOff: !w.Alerts.EmailEnabled, NoPublicURL: w.Alerts.PublicURL == "", Unrouted: unrouted, UnroutedPlural: unrouted != 1, Log: logView(now, logs)}
	for _, t := range targets {
		dest, plain := destination(t.AlertTarget)
		if t.Type == store.TargetTypeEmail && w.Alerts.SMTPPlaintext {
			plain = true
		}
		row := alertRow{Name: t.Name, Type: t.Type, Destination: dest, Unencrypted: plain, MinSeverity: t.MinSeverity, Tags: t.TagFilter,
			Kinds: kindsText(t.AlertTarget), Enabled: t.Enabled, LastStatus: t.LastStatus, LastCode: t.LastCode, Unreadable: !w.secretReadable(t.AlertTarget)}
		row.LastAgo, row.LastAbs = optTime(now, t.LastAt)
		switch t.LastStatus {
		case "sent", "test_sent":
			row.LastResultClass = "ok"
		case "":
		default:
			row.LastResultClass = "fail"
		}
		b.Targets = append(b.Targets, row)
	}
	v := w.newView(r, "Alerts", "alerts", b)
	if n := alertNotice(r); n != "" {
		v.Notice = n
	}
	w.render(rw, http.StatusOK, "admin_alerts", v)
}

// ---------------------------------------------------------------- form handling

type targetInput struct {
	name, typ, url, to, minSev, tags string
	burst                            string
	state, detections, enabled       bool
}

// maxDetectionBurst bounds the burst field: beyond it "every detection alone"
// (0) is the honest setting.
const maxDetectionBurst = 1000

// parseBurst reads the detection burst field. set is false for an empty field
// (an older form or a script that does not know it): the caller keeps the
// stored value, or the default for a new target.
func parseBurst(s string) (n int, set bool, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false, nil
	}
	n, err = strconv.Atoi(s)
	if err != nil || n < 0 || n > maxDetectionBurst {
		return 0, true, fmt.Errorf("the detection burst must be a whole number from 0 to %d (0 sends every detection on its own)", maxDetectionBurst)
	}
	return n, true, nil
}

func readTargetForm(r *http.Request) targetInput {
	f := r.PostForm
	return targetInput{
		name: strings.TrimSpace(f.Get("name")), typ: f.Get("type"), url: strings.TrimSpace(f.Get("url")), to: f.Get("to"),
		minSev: f.Get("min_severity"), tags: f.Get("tags"), burst: f.Get("detection_burst"),
		state: f.Get("state_changes") != "", detections: f.Get("detections") != "", enabled: f.Get("enabled") != "",
	}
}

func (f targetInput) view(create bool, typ string) targetFormView {
	return targetFormView{Create: create, Name: f.name, Type: typ, To: f.to, MinSeverity: f.minSev, Tags: f.tags,
		State: f.state, Detections: f.detections, Burst: f.burst, Enabled: f.enabled}
}

// formFail re-renders the form with an error. The URL field is never echoed.
func (w *Web) formFail(rw http.ResponseWriter, r *http.Request, status int, v targetFormView, msg string) {
	v.EmailOff, v.SMTPPlain = !w.Alerts.EmailEnabled, w.Alerts.SMTPPlaintext
	title := "New alert target"
	if !v.Create {
		title = "Alert target " + v.Name
	}
	vw := w.newView(r, title, "alerts", v)
	vw.Error = msg
	w.render(rw, status, "alert_target", vw)
}

func (w *Web) newTargetPage(rw http.ResponseWriter, r *http.Request) {
	typ := r.URL.Query().Get("type")
	if typ != store.TargetTypeEmail && typ != store.TargetTypeWebhook {
		w.errorPage(rw, r, http.StatusBadRequest)
		return
	}
	v := targetFormView{Create: true, Type: typ, MinSeverity: "WARN", State: true, Detections: true, Burst: strconv.Itoa(store.DefaultDetectionBurst), Enabled: true,
		EmailOff: !w.Alerts.EmailEnabled, SMTPPlain: w.Alerts.SMTPPlaintext}
	w.render(rw, http.StatusOK, "alert_target", w.newView(r, "New alert target", "alerts", v))
}

const noKeyMsg = "Webhook targets need the secret key file, which this server does not have. An administrator creates it once with `clamfleet-server key generate` (as root, then chgrp clamfleet-server and chmod 0640) and restarts the server."

// createTarget handles POST /admin/alerts.
func (w *Web) createTarget(rw http.ResponseWriter, r *http.Request) {
	in := readTargetForm(r)
	v := in.view(true, in.typ)
	if in.typ != store.TargetTypeEmail && in.typ != store.TargetTypeWebhook {
		w.errorPage(rw, r, http.StatusBadRequest)
		return
	}
	name, err := store.NormalizeAlertTargetName(in.name)
	if err != nil {
		w.formFail(rw, r, http.StatusBadRequest, v, err.Error())
		return
	}
	v.Name = name
	if !alert.ValidMinSeverity(in.minSev) {
		w.formFail(rw, r, http.StatusBadRequest, v, "Choose a minimum severity.")
		return
	}
	tags, err := alert.ParseTags(in.tags)
	if err != nil {
		w.formFail(rw, r, http.StatusBadRequest, v, err.Error())
		return
	}

	burst, set, err := parseBurst(in.burst)
	if err != nil {
		w.formFail(rw, r, http.StatusBadRequest, v, err.Error())
		return
	}
	if !set {
		burst = store.DefaultDetectionBurst
	}
	nt := store.NewAlertTarget{Name: name, Type: in.typ, MinSeverity: in.minSev, TagFilter: tags,
		SendStateChanges: in.state, SendDetections: in.detections, DetectionBurst: burst, Enabled: in.enabled}
	var seal func(id int64) ([]byte, error)
	var signing string
	switch in.typ {
	case store.TargetTypeEmail:
		if !w.Alerts.EmailEnabled {
			w.formFail(rw, r, http.StatusBadRequest, v, "Email is not configured: an administrator sets smtp.host (and smtp.from) in the server configuration first.")
			return
		}
		to, err := alert.ParseRecipients(in.to)
		if err != nil {
			w.formFail(rw, r, http.StatusBadRequest, v, err.Error())
			return
		}
		nt.Config = mustJSON(alert.EmailConfig{To: to})
	case store.TargetTypeWebhook:
		vu, err := alert.ValidateWebhookURL(in.url, w.Alerts.Policy)
		if err != nil {
			w.formFail(rw, r, http.StatusBadRequest, v, "The URL was refused: "+err.Error()+".")
			return
		}
		if w.Keys == nil {
			w.formFail(rw, r, http.StatusServiceUnavailable, v, noKeyMsg)
			return
		}
		if signing, err = alert.NewSigningKey(); err != nil {
			w.Log.Error("alert target: cannot generate a signing key", "error", err.Error())
			w.errorPage(rw, r, http.StatusInternalServerError)
			return
		}
		nt.Config = mustJSON(alert.WebhookConfig{URLDisplay: vu.Display, Plaintext: vu.Plaintext})
		seal = w.sealer(alert.WebhookSecret{URL: in.url, SigningKey: signing})
	}
	p, audit := w.actor(r)
	if _, err := w.Store.CreateAlertTarget(r.Context(), nt, seal, w.Now(), audit); err != nil {
		if errors.Is(err, store.ErrTargetExists) {
			w.formFail(rw, r, http.StatusConflict, v, "An alert target with that name already exists.")
			return
		}
		w.Log.Error("alert target: cannot create", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	w.Log.Info("alert target created", "target", name, "type", in.typ, "actor", p.Email)
	if in.typ == store.TargetTypeWebhook {
		w.showSecret(rw, r, name, signing, false)
		return
	}
	http.Redirect(rw, r, "/admin/alerts?"+url.Values{"notice": {"created"}, "target": {name}}.Encode(), http.StatusSeeOther)
}

// sealer returns the store callback that seals sec with the target's id as AAD.
func (w *Web) sealer(sec alert.WebhookSecret) func(id int64) ([]byte, error) {
	return func(id int64) ([]byte, error) {
		plain, err := sec.Marshal()
		if err != nil {
			return nil, err
		}
		return w.Keys.Seal(secrets.PurposeAlertTarget, plain, uint64(id))
	}
}

func (w *Web) showSecret(rw http.ResponseWriter, r *http.Request, target, key string, rotated bool) {
	// Never cached: the key is shown exactly once (render sets no-store; Pragma covers old proxies).
	rw.Header().Set("Pragma", "no-cache")
	w.render(rw, http.StatusOK, "secret_once", w.newView(r, "Signing key for "+target, "alerts", secretBody{Target: target, Key: key, Rotated: rotated}))
}

// editPage handles GET /admin/alerts/{name}.
func (w *Web) editTargetPage(rw http.ResponseWriter, r *http.Request) {
	t, ok := w.loadTarget(rw, r)
	if !ok {
		return
	}
	w.renderEdit(rw, r, t, http.StatusOK, "")
}

func (w *Web) loadTarget(rw http.ResponseWriter, r *http.Request) (store.AlertTarget, bool) {
	t, err := w.Store.AlertTarget(r.Context(), r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		w.errorPage(rw, r, http.StatusNotFound)
		return t, false
	}
	if err != nil {
		w.Log.Error("alert target: cannot read", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return t, false
	}
	return t, true
}

func (w *Web) renderEdit(rw http.ResponseWriter, r *http.Request, t store.AlertTarget, status int, errMsg string) {
	logs, err := w.Store.AlertLog(r.Context(), store.AlertLogFilter{TargetName: t.Name, Limit: 100})
	if err != nil {
		w.Log.Error("alert target: cannot read the log", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	pending, _ := w.Store.CountPendingAlerts(r.Context(), t.Name)
	dest, plain := destination(t)
	v := targetFormView{Name: t.Name, Type: t.Type, URLDisplay: dest, Plaintext: plain, MinSeverity: t.MinSeverity, Tags: strings.Join(t.TagFilter, ", "),
		State: t.SendStateChanges, Detections: t.SendDetections, Burst: strconv.Itoa(t.DetectionBurst), Enabled: t.Enabled, Pending: pending, Unreadable: !w.secretReadable(t),
		EmailOff: !w.Alerts.EmailEnabled, SMTPPlain: w.Alerts.SMTPPlaintext, Log: logView(w.Now(), logs)}
	if t.Type == store.TargetTypeEmail {
		to, _ := alert.Recipients(t.Config)
		v.To = strings.Join(to, "\n")
	}
	vw := w.newView(r, "Alert target "+t.Name, "alerts", v)
	vw.Error = errMsg
	if n := alertNotice(r); n != "" && errMsg == "" {
		vw.Notice = n
	}
	w.render(rw, status, "alert_target", vw)
}

// updateTarget handles POST /admin/alerts/{name}.
func (w *Web) updateTarget(rw http.ResponseWriter, r *http.Request) {
	old, ok := w.loadTarget(rw, r)
	if !ok {
		return
	}
	in := readTargetForm(r)
	fail := func(status int, msg string) { w.renderEdit(rw, r, old, status, msg) }
	if !alert.ValidMinSeverity(in.minSev) {
		fail(http.StatusBadRequest, "Choose a minimum severity.")
		return
	}
	tags, err := alert.ParseTags(in.tags)
	if err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	u := store.AlertTargetUpdate{Config: old.Config, MinSeverity: in.minSev, TagFilter: tags,
		SendStateChanges: in.state, SendDetections: in.detections, Enabled: in.enabled, Expect: &store.TargetSnapshot{Config: old.Config, Sealed: old.Sealed}}
	if n, set, err := parseBurst(in.burst); err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	} else if set {
		u.DetectionBurst = &n
	}
	var seal func(id int64) ([]byte, error)
	newKey := "" // set when a new signing key replaces the old one
	switch old.Type {
	case store.TargetTypeEmail:
		to, err := alert.ParseRecipients(in.to)
		if err != nil {
			fail(http.StatusBadRequest, err.Error())
			return
		}
		u.Config = mustJSON(alert.EmailConfig{To: to})
	case store.TargetTypeWebhook:
		// A blank URL keeps the stored one. A new URL is validated exactly as at
		// create, and a refused one leaves the stored URL (and key) unchanged.
		if in.url != "" {
			vu, err := alert.ValidateWebhookURL(in.url, w.Alerts.Policy)
			if err != nil {
				fail(http.StatusBadRequest, "The URL was refused: "+err.Error()+". The stored URL was not changed.")
				return
			}
			if w.Keys == nil {
				fail(http.StatusServiceUnavailable, noKeyMsg)
				return
			}
			key := ""
			if plain, err := w.Keys.Open(secrets.PurposeAlertTarget, old.Sealed, uint64(old.ID)); err == nil {
				if sec, err := alert.ParseWebhookSecret(plain); err == nil {
					key = sec.SigningKey // the receiver keeps verifying with the key it has
				}
			}
			if key == "" { // the old secret cannot be opened: the old key is lost, a new one is issued
				if key, err = alert.NewSigningKey(); err != nil {
					w.errorPage(rw, r, http.StatusInternalServerError)
					return
				}
				newKey = key
			}
			u.Config = mustJSON(alert.WebhookConfig{URLDisplay: vu.Display, Plaintext: vu.Plaintext})
			seal = w.sealer(alert.WebhookSecret{URL: in.url, SigningKey: key})
		}
	}
	p, audit := w.actor(r)
	c, err := w.Store.UpdateAlertTarget(r.Context(), old.Name, u, seal, w.Now(), audit)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			w.errorPage(rw, r, http.StatusNotFound)
			return
		}
		if errors.Is(err, store.ErrChangedMeanwhile) {
			w.changedMeanwhile(rw, r, old.Name)
			return
		}
		w.Log.Error("alert target: cannot update", "target", old.Name, "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	w.Log.Info("alert target updated", "target", old.Name, "cancelled", c.Deliveries, "actor", p.Email)
	if newKey != "" {
		w.showSecret(rw, r, old.Name, newKey, true)
		return
	}
	http.Redirect(rw, r, "/admin/alerts/"+old.Name+"?"+url.Values{"notice": {"saved"}, "target": {old.Name}, "cancelled": {strconv.Itoa(c.Deliveries)}}.Encode(), http.StatusSeeOther)
}

// rotateSecret handles POST /admin/alerts/{name}/rotate-secret: a new signing
// key, shown once; the old one stops verifying at once (no overlap in M4).
func (w *Web) rotateSecret(rw http.ResponseWriter, r *http.Request) {
	t, ok := w.loadTarget(rw, r)
	if !ok {
		return
	}
	if t.Type != store.TargetTypeWebhook {
		w.errorPage(rw, r, http.StatusBadRequest)
		return
	}
	if w.Keys == nil {
		w.renderEdit(rw, r, t, http.StatusServiceUnavailable, noKeyMsg)
		return
	}
	plain, err := w.Keys.Open(secrets.PurposeAlertTarget, t.Sealed, uint64(t.ID))
	var sec alert.WebhookSecret
	if err == nil {
		sec, err = alert.ParseWebhookSecret(plain)
	}
	if err != nil {
		w.renderEdit(rw, r, t, http.StatusConflict, "The stored secret cannot be opened with the loaded key, so its URL is not known: enter the URL again below, which also issues a new signing key.")
		return
	}
	key, err := alert.NewSigningKey()
	if err != nil {
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	sec.SigningKey = key
	p, audit := w.actor(r)
	if err := w.Store.RotateAlertSecret(r.Context(), t.Name, snapshotOf(t), w.sealer(sec), w.Now(), audit); err != nil {
		if errors.Is(err, store.ErrChangedMeanwhile) {
			w.changedMeanwhile(rw, r, t.Name)
			return
		}
		w.Log.Error("alert target: cannot rotate", "target", t.Name, "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	w.Log.Info("alert target signing key rotated", "target", t.Name, "actor", p.Email)
	w.showSecret(rw, r, t.Name, key, true)
}

// deleteTarget handles POST /admin/alerts/{name}/delete. Rule: the typed name
// must equal the target's name; a wrong or missing one deletes nothing.
func (w *Web) deleteTarget(rw http.ResponseWriter, r *http.Request) {
	t, ok := w.loadTarget(rw, r)
	if !ok {
		return
	}
	if strings.ToLower(strings.TrimSpace(r.PostForm.Get("confirm"))) != t.Name {
		w.renderEdit(rw, r, t, http.StatusBadRequest, "Nothing was deleted: the confirmation did not match the target name "+t.Name+".")
		return
	}
	p, audit := w.actor(r)
	if err := w.Store.DeleteAlertTarget(r.Context(), t.Name, w.Now(), audit); err != nil {
		w.Log.Error("alert target: cannot delete", "target", t.Name, "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	w.Log.Info("alert target deleted", "target", t.Name, "actor", p.Email)
	http.Redirect(rw, r, "/admin/alerts?"+url.Values{"notice": {"deleted"}, "target": {t.Name}}.Encode(), http.StatusSeeOther)
}

// ---------------------------------------------------------------- test send

// testText renders one record as a line for the page: our own words, never a
// response body or the URL.
func testText(rec store.TestSendRecord) string {
	who := ""
	if rec.Recipient != "" {
		who = " to " + rec.Recipient
	}
	r := rec.Result
	if r.Status == store.AlertLogSent {
		return fmt.Sprintf("Delivered%s: %s in %d ms", who, r.Code, r.Duration.Milliseconds())
	}
	switch r.Code {
	case "blocked", "plaintext":
		return "Blocked" + who + ": " + r.Error
	case "tls":
		return "Failed" + who + ": " + r.Error
	case "timeout":
		return "Timeout" + who + ": " + r.Error
	}
	if r.Code == "" {
		return "Failed" + who + ": " + r.Error
	}
	return r.Code + who + ": " + r.Error
}

// testSend handles POST /admin/alerts/{name}/test: synchronous, through the same
// sender and policy as real alerts (kind "test"), logged and audited. An htmx
// request gets a fragment; a plain form post is redirected with a notice.
func (w *Web) testSend(rw http.ResponseWriter, r *http.Request) {
	t, ok := w.loadTarget(rw, r)
	if !ok {
		return
	}
	htmx := r.Header.Get("HX-Request") == "true"
	if w.Alerts.Dispatcher == nil {
		w.testResult(rw, r, htmx, http.StatusServiceUnavailable, t.Name, false, "Test sending is not available on this server.")
		return
	}
	recs, err := w.Alerts.Dispatcher.TestSend(r.Context(), t)
	if errors.Is(err, alert.ErrTestRateLimited) {
		w.testResult(rw, r, htmx, http.StatusTooManyRequests, t.Name, false, "A test was just sent to this target: wait 10 seconds before the next one.")
		return
	}
	if err != nil {
		w.Log.Error("alert target: test send failed to run", "target", t.Name, "error", err.Error())
		w.testResult(rw, r, htmx, http.StatusInternalServerError, t.Name, false, "The test could not be run.")
		return
	}
	p, audit := w.actor(r)
	if err := w.Store.RecordTestSend(r.Context(), t.Name, recs, w.Now(), audit); err != nil {
		w.Log.Error("alert target: cannot record the test send", "target", t.Name, "error", err.Error())
	}
	allOK := true
	var lines []string
	for _, rec := range recs {
		if rec.Result.Status != store.AlertLogSent {
			allOK = false
		}
		lines = append(lines, testText(rec))
	}
	w.Log.Info("alert target tested", "target", t.Name, "ok", allOK, "actor", p.Email)
	w.testResult(rw, r, htmx, http.StatusOK, t.Name, allOK, lines...)
}

func (w *Web) testResult(rw http.ResponseWriter, r *http.Request, htmx bool, status int, target string, ok bool, lines ...string) {
	if !htmx {
		kind := "test-failed"
		if ok {
			kind = "test-ok"
		}
		http.Redirect(rw, r, "/admin/alerts?"+url.Values{"notice": {kind}, "target": {target}}.Encode(), http.StatusSeeOther)
		return
	}
	w.renderPartialStatus(rw, status, "alert_test_result", "alert_test_result", testResultView{Target: target, OK: ok, Lines: lines})
}

// mustJSON encodes plain strings and slices of them: it cannot fail.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func snapshotOf(t store.AlertTarget) store.TargetSnapshot {
	return store.TargetSnapshot{Config: t.Config, Sealed: t.Sealed}
}

// changedMeanwhile answers 409 when another admin edited or rotated the target
// between this request's read and its write: nothing was written, and the page
// is re-read so the admin sees the current state before trying again.
func (w *Web) changedMeanwhile(rw http.ResponseWriter, r *http.Request, name string) {
	t, err := w.Store.AlertTarget(r.Context(), name)
	if err != nil {
		w.errorPage(rw, r, http.StatusConflict)
		return
	}
	w.renderEdit(rw, r, t, http.StatusConflict, "This target was changed by someone else while you were editing it, so nothing was saved. Check the settings below and try again.")
}
