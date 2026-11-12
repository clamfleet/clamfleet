// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// admin.go: host administration in the console (admin class): register a
// host, rotate or revoke its token, delete it with all its data.
//
// Every route here is registered with the admin class in server.Routes(), so
// the session, the role and the CSRF token are checked before a handler runs.
// The handlers still take the actor from the Principal and write every change
// through the store, which writes its audit row (actor_kind=user, the email)
// in the same transaction.
//
// A token is shown exactly once, on a page that is never cached; it is not in
// the log, the audit row or any later page.
package web

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/clamfleet/clamfleet/internal/agentauth"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

type adminHostView struct {
	Name        string
	HasToken    bool
	State       string
	LastSeenAgo string
	LastSeenAbs string
	Tags        []string
}

type adminBody struct {
	Hosts []adminHostView
	// Name keeps what was typed in the register form after an error.
	Name string
}

type tokenBody struct {
	Host    string
	Token   string
	Created bool // registered now (true) or rotated (false)
}

// hostAction is the data of the shared host_actions template.
type hostAction struct {
	Name     string
	HasToken bool
	CSRF     string
}

func (w *Web) actor(r *http.Request) (webauth.Principal, store.Audit) {
	p, _ := webauth.FromContext(r.Context())
	return p, store.Audit{Kind: store.ActorUser, Actor: p.Email}
}

// adminView builds the hosts admin page; every host is listed, revoked ones included.
func (w *Web) adminView(r *http.Request, name string) (*view, error) {
	hosts, err := w.Store.ListHosts(r.Context())
	if err != nil {
		return nil, err
	}
	now := w.Now()
	b := adminBody{Name: name}
	for _, h := range hosts {
		v := adminHostView{Name: h.Name, HasToken: h.HasToken, State: stateText(h.State), Tags: h.Tags}
		v.LastSeenAgo, v.LastSeenAbs = optTime(now, h.LastSeen)
		b.Hosts = append(b.Hosts, v)
	}
	v := w.newView(r, "Hosts", "admin", b)
	// A notice after a redirect: only fixed kinds, and the name must be a valid
	// host name, so nothing arbitrary from the URL is ever shown.
	q := r.URL.Query()
	if n, err := store.NormalizeHostName(q.Get("host")); err == nil {
		switch q.Get("notice") {
		case "revoked":
			v.Notice = "Token of " + n + " revoked. The host's history is kept."
		case "deleted":
			v.Notice = "Host " + n + " and all its data deleted."
		}
	}
	return v, nil
}

func (w *Web) adminHosts(rw http.ResponseWriter, r *http.Request) {
	v, err := w.adminView(r, "")
	if err != nil {
		w.Log.Error("admin hosts: cannot list", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	w.render(rw, http.StatusOK, "admin_hosts", v)
}

// adminFail re-renders the hosts page with an error and the typed name.
func (w *Web) adminFail(rw http.ResponseWriter, r *http.Request, status int, name, msg string) {
	v, err := w.adminView(r, name)
	if err != nil {
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	v.Error = msg
	w.render(rw, status, "admin_hosts", v)
}

func (w *Web) showToken(rw http.ResponseWriter, r *http.Request, host, token string, created bool) {
	title := "Token for " + host
	// Never cached, never indexed: the token is shown exactly once. render sets
	// Cache-Control: no-store on every console page; Pragma covers old proxies.
	rw.Header().Set("Pragma", "no-cache")
	w.render(rw, http.StatusOK, "token_once", w.newView(r, title, "admin", tokenBody{Host: host, Token: token, Created: created}))
}

// adminRegister registers a host and shows its token once.
func (w *Web) adminRegister(rw http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostForm.Get("name"))
	norm, err := store.NormalizeHostName(name)
	if err != nil {
		w.adminFail(rw, r, http.StatusBadRequest, name, "Invalid host name: use 1-253 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit.")
		return
	}
	token, hash, err := agentauth.Generate()
	if err != nil {
		w.Log.Error("register host: cannot generate token", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	p, audit := w.actor(r)
	if _, err := w.Store.CreateHost(r.Context(), norm, hash, w.Now(), audit); err != nil {
		if errors.Is(err, store.ErrHostExists) {
			w.adminFail(rw, r, http.StatusConflict, name, "A host with that name already exists.")
			return
		}
		w.Log.Error("register host: cannot store", "error", err.Error())
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	w.Log.Info("host registered", "host", norm, "actor", p.Email)
	w.showToken(rw, r, norm, token, true)
}

// adminRotate issues a new token (the old one stops working at once). It also
// re-enables a host whose token was revoked.
func (w *Web) adminRotate(rw http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.PathValue("name"))
	token, hash, err := agentauth.Generate()
	if err != nil {
		w.errorPage(rw, r, http.StatusInternalServerError)
		return
	}
	p, audit := w.actor(r)
	if err := w.Store.SetToken(r.Context(), name, hash, w.Now(), audit); err != nil {
		w.hostError(rw, r, "rotate token", err)
		return
	}
	w.Log.Info("token rotated", "host", name, "actor", p.Email)
	w.showToken(rw, r, name, token, false)
}

func (w *Web) adminRevoke(rw http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.PathValue("name"))
	p, audit := w.actor(r)
	if err := w.Store.SetToken(r.Context(), name, nil, w.Now(), audit); err != nil {
		w.hostError(rw, r, "revoke token", err)
		return
	}
	w.Log.Info("token revoked", "host", name, "actor", p.Email)
	http.Redirect(rw, r, "/admin/hosts?"+url.Values{"notice": {"revoked"}, "host": {name}}.Encode(), http.StatusSeeOther)
}

// adminDelete removes a host and everything stored about it. Rule: the typed
// confirmation must equal the host name; a wrong or missing one deletes nothing.
func (w *Web) adminDelete(rw http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.PathValue("name"))
	if strings.ToLower(strings.TrimSpace(r.PostForm.Get("confirm"))) != name {
		w.adminFail(rw, r, http.StatusBadRequest, "", "Nothing was deleted: the confirmation did not match the host name "+name+".")
		return
	}
	p, audit := w.actor(r)
	if err := w.Store.DeleteHost(r.Context(), name, w.Now(), audit); err != nil {
		w.hostError(rw, r, "delete host", err)
		return
	}
	w.Log.Info("host deleted with all its data", "host", name, "actor", p.Email)
	http.Redirect(rw, r, "/admin/hosts?"+url.Values{"notice": {"deleted"}, "host": {name}}.Encode(), http.StatusSeeOther)
}

func (w *Web) hostError(rw http.ResponseWriter, r *http.Request, what string, err error) {
	if errors.Is(err, store.ErrNotFound) {
		w.errorPage(rw, r, http.StatusNotFound)
		return
	}
	w.Log.Error("admin: cannot "+what, "error", err.Error())
	w.errorPage(rw, r, http.StatusInternalServerError)
}
