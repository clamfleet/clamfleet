// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// fleet.go: the fleet overview and its htmx fragment.
//
// The page is a plain GET form (tag and state filters) around a live region.
// The live region polls /fleet/rows every 15 s with the same filters and swaps
// its contents; polls count as session activity, so an open tab stays signed in
// until the absolute session limit, and a poll after the session ended gets
// 401 + HX-Redirect and the whole tab goes to the login page.
//
// Revoked hosts are not shown here (their state is frozen); the hosts admin
// page lists every host.
package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"

	"github.com/clamfleet/clamfleet/internal/health"
	"github.com/clamfleet/clamfleet/internal/store"
)

// pendingState is the pseudo state of a host that was never evaluated.
const pendingState = "pending"

// states in display order, worst first.
var stateOrder = []string{"STALE", "CRIT", "WARN", pendingState, "OK"}

var stateRank = map[string]int{"STALE": 0, "CRIT": 1, "WARN": 2, pendingState: 3, "OK": 4}

type reasonView struct{ Rule, Severity, Msg string }

type fleetRowView struct {
	Name         string
	Tags         []string
	State        string // OK, WARN, CRIT, STALE or pending
	Reasons      []reasonView
	LastSeenAgo  string // "" when never
	LastSeenAbs  string
	Clamd        string
	DailyVersion string
	DailyAge     string
	// OpenEvents is the host's unacknowledged detections.
	OpenEvents int64
}

type countView struct {
	State string
	N     int
}

type fleetBody struct {
	Rows        []fleetRowView
	Counts      []countView
	Total       int // hosts with a token, before filtering
	Tags        []string
	TagFilter   string
	StateFilter string
	States      []string
	Filtered    bool
	// OpenTotal is the unacknowledged detections of all hosts with a token.
	OpenTotal int64
	// Query is the encoded filter, reused by the poll URL.
	Query string
}

// decodeReasons reads the stored JSON array. A row that cannot be decoded
// yields no reasons (the state badge still shows); the text of each reason may
// hold agent-supplied words and reaches the page only through template escaping.
func decodeReasons(raw json.RawMessage) []reasonView {
	var rs []health.Reason
	if len(raw) == 0 || json.Unmarshal(raw, &rs) != nil {
		return nil
	}
	out := make([]reasonView, 0, len(rs))
	for _, r := range rs {
		out = append(out, reasonView{r.Rule, r.Severity, r.Msg})
	}
	return out
}

func stateText(s *string) string {
	if s == nil {
		return pendingState
	}
	return *s
}

// buildFleet assembles the page data from the store rows and the filters.
func (w *Web) buildFleet(rows []store.FleetRow, tag, state string) fleetBody {
	now := w.Now()
	tagSet := map[string]bool{}
	counts := map[string]int{}
	var views []fleetRowView
	var openTotal int64
	for _, r := range rows {
		st := stateText(r.State)
		counts[st]++
		openTotal += r.OpenEvents
		for _, t := range r.Tags {
			tagSet[t] = true
		}
		if state != "" && st != state {
			continue
		}
		if tag != "" && !contains(r.Tags, tag) {
			continue
		}
		v := fleetRowView{Name: r.Name, Tags: r.Tags, State: st, Reasons: decodeReasons(r.StateReason), Clamd: r.ClamdVersion, OpenEvents: r.OpenEvents}
		if r.LastSeen != nil {
			v.LastSeenAgo, v.LastSeenAbs = ago(now, *r.LastSeen), abs(*r.LastSeen)
		}
		if r.DailyVersion != nil {
			v.DailyVersion = strconv.Itoa(*r.DailyVersion)
		}
		if r.DailyBuilt != nil {
			v.DailyAge = age(now.Sub(*r.DailyBuilt))
		}
		views = append(views, v)
	}
	// Worst first, then by name: what needs attention is at the top.
	sort.SliceStable(views, func(i, j int) bool {
		if ri, rj := stateRank[views[i].State], stateRank[views[j].State]; ri != rj {
			return ri < rj
		}
		return views[i].Name < views[j].Name
	})
	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	cv := make([]countView, 0, len(stateOrder))
	for _, s := range stateOrder {
		cv = append(cv, countView{s, counts[s]})
	}
	q := url.Values{}
	if tag != "" {
		q.Set("tag", tag)
	}
	if state != "" {
		q.Set("state", state)
	}
	return fleetBody{
		Rows: views, Counts: cv, Total: len(rows), Tags: tags, TagFilter: tag, StateFilter: state,
		States: stateOrder, Filtered: tag != "" || state != "", Query: q.Encode(), OpenTotal: openTotal,
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// filters reads the tag and state filters; an unknown state is ignored.
func filters(r *http.Request) (tag, state string) {
	q := r.URL.Query()
	tag = q.Get("tag")
	if len(tag) > 64 {
		tag = tag[:64]
	}
	state = q.Get("state")
	if _, ok := stateRank[state]; !ok {
		state = ""
	}
	return tag, state
}

func (w *Web) fleetBodyFor(r *http.Request) (fleetBody, error) {
	rows, err := w.Store.ListFleet(r.Context())
	if err != nil {
		return fleetBody{}, err
	}
	tag, state := filters(r)
	return w.buildFleet(rows, tag, state), nil
}

// fleet renders the overview page.
func (w *Web) fleet(rw http.ResponseWriter, r *http.Request) {
	body, err := w.fleetBodyFor(r)
	if err != nil {
		w.Log.Error("fleet: cannot list hosts", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	w.render(rw, http.StatusOK, "fleet", w.newView(r, "Fleet", "fleet", body))
}

// fleetRows renders only the live region (htmx poll).
func (w *Web) fleetRows(rw http.ResponseWriter, r *http.Request) {
	body, err := w.fleetBodyFor(r)
	if err != nil {
		w.Log.Error("fleet rows: cannot list hosts", "error", err.Error())
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.renderPartial(rw, "fleet", "fleet_rows", body)
}
