// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// events.go: the detections page and acknowledgement (milestone 5).
//
// GET /events is open to every signed-in user: paths are shown to all of them
// (M5 decision 12), escaped by displayPath, never put in a URL, a log line or an
// audit row. Acknowledging is admin only: the two POST routes are registered with
// the admin class in server.Routes(), and the store writes the audit row in the
// same transaction as the change.
//
// Acknowledgement records who and when and removes the event from the open
// counts. It does NOT cancel alerts and does not change health. "Acknowledge
// all" acts on exactly the open events matching the filters with id <= upto,
// the set the admin was shown, so a detection that arrived after the page was
// rendered is never hidden by it.
//
// Dependencies: internal/store (EventStore), pathfmt.go, the layout.

package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

const eventsPageSize = 50

// receivedLate: the Received column is shown only when an event arrived this
// much after it was detected (it was spooled).
const receivedLate = time.Minute

// eventRowView is one table row: on the page, in the host card and as the htmx
// answer to an acknowledgement.
type eventRowView struct {
	ID          int64
	Host        string
	Detected    string // "3m ago"
	DetectedAbs string
	LateText    string // "received 3h later, spooled", "" when on time
	Signature   []seg
	Path        []seg
	Stream      bool // clamd gave "stream": there is no file path
	Truncated   bool
	Occurrences int64
	Source      string
	Acked       bool
	AckBy       string
	AckAt       string
	IsAdmin     bool
	// Return is where a non-htmx acknowledgement goes back to (validated again by the handler).
	Return string
	CSRF   string
}

func (w *Web) eventRow(now time.Time, e store.EventRow, admin bool, ret, csrf string) eventRowView {
	v := eventRowView{
		ID: e.ID, Host: e.Host, Detected: ago(now, e.TS), DetectedAbs: abs(e.TS),
		Signature: displaySignature(e.Signature), Path: displayPath(e.Path), Stream: e.Path == "stream",
		Truncated: pathTruncated(e.Path), Occurrences: e.Occurrences, Source: e.Source,
		Acked: e.Acked(), AckBy: e.AckBy, IsAdmin: admin, Return: ret, CSRF: csrf,
	}
	if d := e.ReceivedAt.Sub(e.TS); d >= receivedLate {
		v.LateText = "received " + age(d) + " later, spooled"
	}
	if e.AckAt != nil {
		v.AckAt = abs(*e.AckAt)
	}
	return v
}

type bulkView struct {
	Expected int64
	UpTo     int64
	Host     string
	Sig      string
	CSRF     string
}

type eventsBody struct {
	Rows       []eventRowView
	Count      int64 // matching the filters
	Hosts      []string
	HostFilter string
	SigFilter  string
	AckFilter  string
	AckOptions []string
	Older      string // URL, "" when there is no older page
	Newest     string // URL, "" on the newest page
	Empty      bool   // no events at all (before filtering)
	IsAdmin    bool
	Bulk       *bulkView
}

// eventFilter reads the filters from a request's query (or form). The signature
// is capped; host is used only as a registered-name filter.
func eventFilter(q url.Values) store.EventFilter {
	f := store.EventFilter{Host: q.Get("host"), Signature: q.Get("sig"), Ack: q.Get("ack")}
	if len(f.Signature) > 256 {
		f.Signature = f.Signature[:256]
	}
	switch f.Ack {
	case store.AckAcked, store.AckAll:
	default:
		f.Ack = store.AckOpen
	}
	return f
}

// eventsQuery encodes the filters (not the cursor) back into a query string.
func eventsQuery(f store.EventFilter) url.Values {
	q := url.Values{}
	if f.Host != "" {
		q.Set("host", f.Host)
	}
	if f.Signature != "" {
		q.Set("sig", f.Signature)
	}
	if f.Ack != store.AckOpen {
		q.Set("ack", f.Ack)
	}
	return q
}

// eventsPage renders GET /events.
func (w *Web) eventsPage(rw http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := eventFilter(q)
	f.Limit = eventsPageSize + 1 // one more than shown tells whether an older page exists
	if b, err := strconv.ParseInt(q.Get("before"), 10, 64); err == nil && b > 0 {
		f.Before = b
	}
	p, _ := webauth.FromContext(r.Context())
	rows, err := w.Store.ListEvents(r.Context(), f)
	var count, total int64
	var hosts []store.HostSummary
	if err == nil {
		cf := f
		cf.Before = 0
		count, err = w.Store.CountEvents(r.Context(), cf)
	}
	if err == nil {
		total, err = w.Store.CountEvents(r.Context(), store.EventFilter{Ack: store.AckAll})
	}
	if err == nil {
		hosts, err = w.Store.ListHosts(r.Context())
	}
	if err != nil {
		w.Log.Error("events: cannot read", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	now := w.Now()
	admin := p.IsAdmin()
	ret := r.URL.Path
	if r.URL.RawQuery != "" {
		ret += "?" + r.URL.RawQuery
	}
	b := eventsBody{
		Count: count, HostFilter: f.Host, SigFilter: f.Signature, AckFilter: f.Ack,
		AckOptions: []string{store.AckOpen, store.AckAcked, store.AckAll}, Empty: total == 0, IsAdmin: admin,
	}
	for _, h := range hosts {
		b.Hosts = append(b.Hosts, h.Name)
	}
	more := len(rows) > eventsPageSize
	if more {
		rows = rows[:eventsPageSize]
	}
	for _, e := range rows {
		b.Rows = append(b.Rows, w.eventRow(now, e, admin, ret, p.CSRFToken()))
	}
	base := eventsQuery(f)
	if more && len(rows) > 0 {
		o := cloneValues(base)
		o.Set("before", strconv.FormatInt(rows[len(rows)-1].ID, 10))
		b.Older = "/events?" + o.Encode()
	}
	if f.Before > 0 {
		b.Newest = "/events" + queryPrefix(base)
	}
	if admin && f.Ack == store.AckOpen && count > 0 {
		bf := f
		bf.Before, bf.Limit = 0, 0
		upto, err := w.Store.MaxEventID(r.Context(), bf)
		if err == nil {
			bf.UpTo = upto
			var expected int64
			if expected, err = w.Store.CountEvents(r.Context(), bf); err == nil {
				b.Bulk = &bulkView{Expected: expected, UpTo: upto, Host: f.Host, Sig: f.Signature, CSRF: p.CSRFToken()}
			}
		}
		if err != nil {
			w.Log.Error("events: cannot compute the bulk boundary", "error", err.Error())
		}
	}
	v := w.newView(r, "Detections", "events", b)
	// A notice after a bulk acknowledgement: two integers, never text from the URL.
	if m, err := strconv.ParseInt(q.Get("acked"), 10, 64); err == nil && m >= 0 {
		if n, err := strconv.ParseInt(q.Get("of"), 10, 64); err == nil && n >= m {
			v.Notice = fmt.Sprintf("%d detections acknowledged.", m)
			if m == 1 {
				v.Notice = "1 detection acknowledged."
			}
			if n > m {
				v.Notice += fmt.Sprintf(" %d of the %d shown had already been acknowledged by someone else.", n-m, n)
			}
		}
	}
	w.render(rw, http.StatusOK, "events", v)
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func queryPrefix(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}

var hostNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,252}$`)

// safeReturn validates the "return" form value of a non-htmx acknowledgement.
// It must be this site's events page (with a query) or a host page, so the
// redirect can never leave the site: anything else (an absolute URL, "//host",
// a backslash trick, a control character) goes to /events.
func safeReturn(ret string) string {
	const fallback = "/events"
	if ret == "" || len(ret) > 2048 || strings.ContainsAny(ret, "\\\r\n\t ") {
		return fallback
	}
	for _, c := range ret {
		if c < 0x20 || c == 0x7f {
			return fallback
		}
	}
	switch {
	case ret == "/events" || strings.HasPrefix(ret, "/events?"):
		if u, err := url.Parse(ret); err == nil && u.Host == "" && u.Scheme == "" && u.Path == "/events" {
			return ret
		}
	case strings.HasPrefix(ret, "/hosts/"):
		name := strings.TrimPrefix(ret, "/hosts/")
		if i := strings.IndexByte(name, '?'); i >= 0 {
			name = name[:i]
		}
		if hostNameRE.MatchString(name) {
			return ret
		}
	}
	return fallback
}

// ackEvent handles POST /events/{id}/ack (admin class).
func (w *Web) ackEvent(rw http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		w.errorPage(rw, r, http.StatusNotFound)
		return
	}
	p, audit := w.actor(r)
	row, acked, err := w.Store.AckEvent(r.Context(), id, w.Now(), audit)
	if errors.Is(err, store.ErrNotFound) {
		w.errorPage(rw, r, http.StatusNotFound)
		return
	}
	if err != nil {
		w.Log.Error("events: cannot acknowledge", "event_id", id, "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	if acked {
		w.Log.Info("event acknowledged", "event_id", id, "host", row.Host, "actor", p.Actor())
	}
	ret := safeReturn(r.PostForm.Get("return"))
	if r.Header.Get("HX-Request") == "true" {
		w.renderPartial(rw, "events", "event_row", w.eventRow(w.Now(), row, true, ret, p.CSRFToken()))
		return
	}
	http.Redirect(rw, r, ret, http.StatusSeeOther)
}

// ackEvents handles POST /events/ack, "acknowledge all matching, as of this id"
// (admin class). upto is required: it is the newest event the admin was shown.
func (w *Web) ackEvents(rw http.ResponseWriter, r *http.Request) {
	upto, err := strconv.ParseInt(r.PostForm.Get("upto"), 10, 64)
	if err != nil || upto <= 0 {
		w.errorPage(rw, r, http.StatusBadRequest)
		return
	}
	expected, err := strconv.ParseInt(r.PostForm.Get("expected"), 10, 64)
	if err != nil || expected < 0 {
		w.errorPage(rw, r, http.StatusBadRequest)
		return
	}
	f := store.EventFilter{Host: r.PostForm.Get("host"), Signature: r.PostForm.Get("sig")}
	if len(f.Signature) > 256 {
		f.Signature = f.Signature[:256]
	}
	p, audit := w.actor(r)
	n, err := w.Store.AckEvents(r.Context(), f, upto, expected, w.Now(), audit)
	if err != nil {
		w.Log.Error("events: cannot acknowledge in bulk", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	w.Log.Info("events acknowledged in bulk", "count", n, "upto", upto, "actor", p.Actor())
	q := eventsQuery(store.EventFilter{Host: f.Host, Signature: f.Signature, Ack: store.AckOpen})
	q.Set("acked", strconv.FormatInt(n, 10))
	q.Set("of", strconv.FormatInt(max(expected, n), 10))
	http.Redirect(rw, r, "/events?"+q.Encode(), http.StatusSeeOther)
}
