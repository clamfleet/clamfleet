// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// host.go: the host detail page.
//
// Everything in the stored report is agent-supplied text (versions, error
// messages, unit states) and reaches the page through html/template escaping
// only. The URL shape /hosts/{name} is the one the spec 11 webhook "url" will use.
package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

type sigView struct {
	Name, Version, Built, Age string
	Sigs                      int64
}

type scanView struct {
	Finished, FinishedAgo     string
	Exit                      int
	Scanned, Infected, Errors int64
}

type reportView struct {
	ReceivedFrom string // the host name the agent reported (may differ from the registered name)
	ReportTime   string
	ClamdUp      bool
	ClamdVersion string
	ClamdQueue   string
	ClamdError   string
	Sigs         []sigView
	FreshclamOK  string
	FreshclamErr string
	FreshclamMsg string
	Source       string
	Services     []struct{ Name, State string }
	Scan         *scanView
	// VirusEvent says whether clamd.conf runs our event command: "set up",
	// "another command", "not set" or "unknown" (older agent, or unreadable clamd.conf).
	VirusEvent string
}

type historyView struct {
	When, WhenAbs string
	From, To      string
	Reasons       []reasonView
}

type auditView struct{ When, Actor, ActorKind, Action, Detail string }

type hostBody struct {
	Name         string
	State        string
	Reasons      []reasonView
	Since        string
	SinceAbs     string
	FirstSeen    string
	LastSeenAgo  string
	LastSeenAbs  string
	ReportedName string
	AgentVersion string
	Tags         []string
	HasToken     bool
	ReportCount  int64
	Report       *reportView
	History      []historyView
	// OpenEvents and Recent are the Detections card: the open count and the 10
	// newest events, any state.
	OpenEvents int64
	Recent     []eventRowView
	// Admin-only: left empty for a viewer by the handler, not only hidden in the template.
	IsAdmin      bool
	TokenCreated string
	Audit        []auditView
}

func optTime(now time.Time, t *time.Time) (agoText, absText string) {
	if t == nil {
		return "", ""
	}
	return ago(now, *t), abs(*t)
}

func buildReport(now time.Time, raw json.RawMessage) *reportView {
	if len(raw) == 0 {
		return nil
	}
	var r proto.Report
	if json.Unmarshal(raw, &r) != nil {
		return nil
	}
	v := &reportView{ReceivedFrom: r.Host, ReportTime: abs(r.TS), ClamdUp: r.Clamd.Up, VirusEvent: "unknown"}
	if ve := r.Clamd.VirusEvent; ve != nil {
		switch *ve {
		case proto.VirusEventClamfleet:
			v.VirusEvent = "set up (clamfleet-agent event)"
		case proto.VirusEventOther:
			v.VirusEvent = "another command (a wrapper must call clamfleet-agent event)"
		case proto.VirusEventNone:
			v.VirusEvent = "not set: detections on this host are not reported"
		}
	}
	if r.Clamd.Version != nil {
		v.ClamdVersion = *r.Clamd.Version
	}
	if r.Clamd.Queue != nil {
		v.ClamdQueue = strconv.Itoa(*r.Clamd.Queue)
	}
	if r.Clamd.Error != nil {
		v.ClamdError = *r.Clamd.Error
	}
	for _, s := range []struct {
		name string
		db   *proto.SigDB
	}{{"daily", r.Sigs.Daily}, {"main", r.Sigs.Main}, {"bytecode", r.Sigs.Bytecode}} {
		if s.db != nil {
			v.Sigs = append(v.Sigs, sigView{s.name, strconv.Itoa(s.db.Version), abs(s.db.Built), age(now.Sub(s.db.Built)), s.db.Sigs})
		}
	}
	if r.Freshclam.LastOK != nil {
		v.FreshclamOK = abs(*r.Freshclam.LastOK)
	}
	if r.Freshclam.LastError != nil {
		v.FreshclamErr = abs(*r.Freshclam.LastError)
	}
	if r.Freshclam.LastErrorMsg != nil {
		v.FreshclamMsg = *r.Freshclam.LastErrorMsg
	}
	if r.Freshclam.Source != nil {
		v.Source = *r.Freshclam.Source
	}
	v.Services = []struct{ Name, State string }{{"clamd", r.Services.Clamd}, {"freshclam", r.Services.Freshclam}, {"clamonacc", r.Services.Clamonacc}}
	if s := r.LastScan; s != nil {
		v.Scan = &scanView{abs(s.Finished), ago(now, s.Finished), s.Exit, s.Scanned, s.Infected, s.Errors}
	}
	return v
}

// host renders the detail page of one host.
func (w *Web) host(rw http.ResponseWriter, r *http.Request) {
	d, err := w.Store.HostByName(r.Context(), r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		w.errorPage(rw, r, http.StatusNotFound)
		return
	}
	if err != nil {
		w.Log.Error("host: cannot read", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	p, _ := webauth.FromContext(r.Context())
	now := w.Now()
	b := hostBody{
		Name: d.Name, State: stateText(d.State), Reasons: decodeReasons(d.StateReason),
		Tags: d.Tags, HasToken: d.HasToken, ReportCount: d.ReportCount, ReportedName: d.ReportedName,
		AgentVersion: d.AgentVersion, Report: buildReport(now, d.LastReport), IsAdmin: p.IsAdmin(),
	}
	b.OpenEvents = d.OpenEvents
	ret := "/hosts/" + d.Name
	for _, e := range d.RecentEvents {
		b.Recent = append(b.Recent, w.eventRow(now, e, b.IsAdmin, ret, p.CSRFToken()))
	}
	b.Since, b.SinceAbs = optTime(now, d.StateSince)
	_, b.FirstSeen = optTime(now, d.FirstSeen)
	b.LastSeenAgo, b.LastSeenAbs = optTime(now, d.LastSeen)
	for _, c := range d.StateChanges {
		h := historyView{When: ago(now, c.TS), WhenAbs: abs(c.TS), From: "none", To: c.To, Reasons: decodeReasons(c.Reason)}
		if c.From != nil {
			h.From = *c.From
		}
		b.History = append(b.History, h)
	}
	if b.IsAdmin {
		_, b.TokenCreated = optTime(now, d.TokenCreatedAt)
		for _, a := range d.Audit {
			b.Audit = append(b.Audit, auditView{abs(a.TS), a.Actor, a.ActorKind, a.Action, a.Detail})
		}
	}
	w.render(rw, http.StatusOK, "host", w.newView(r, d.Name, "fleet", b))
}
