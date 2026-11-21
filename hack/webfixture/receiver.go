// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// receiver.go: the webhook receiver of the browser fixture. A browser test that
// creates an alert target needs a URL the server can really deliver to, and a
// way to read what arrived, so the fixture runs one on 127.0.0.1.
//
//	any other path           record the request, answer the scripted status (default 204)
//	GET    /__requests       JSON array of what was recorded, oldest first
//	DELETE /__requests       forget what was recorded
//	POST   /__status?code=N  answer N (100-599) from now on, "" or 0 resets to 204
//
// Each recorded request is {"ts","method","path","header":{...},"body":"..."}:
// the headers include webhook-id, webhook-timestamp and webhook-signature, so a
// test can verify the signature itself with the key the console showed.
//
// Loopback only (it listens on 127.0.0.1 and the server under test has
// alert.webhook.allow_loopback on in the fixture config).
package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type recordedRequest struct {
	TS     time.Time           `json:"ts"`
	Method string              `json:"method"`
	Path   string              `json:"path"`
	Header map[string][]string `json:"header"`
	Body   string              `json:"body"`
}

type receiver struct {
	ln     net.Listener
	srv    *http.Server
	mu     sync.Mutex
	reqs   []recordedRequest
	status int
}

// startReceiver listens on 127.0.0.1 on a free port.
func startReceiver() (*receiver, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &receiver{ln: ln, status: http.StatusNoContent}
	r.srv = &http.Server{Handler: r, ReadHeaderTimeout: 10 * time.Second}
	go r.srv.Serve(ln)
	return r, nil
}

func (r *receiver) URL() string { return "http://" + r.ln.Addr().String() }
func (r *receiver) Close()      { r.srv.Close() }

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch {
	case req.URL.Path == "/__requests" && req.Method == http.MethodGet:
		r.mu.Lock()
		out := append([]recordedRequest{}, r.reqs...)
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	case req.URL.Path == "/__requests" && req.Method == http.MethodDelete:
		r.mu.Lock()
		r.reqs = nil
		r.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case req.URL.Path == "/__status" && req.Method == http.MethodPost:
		code, _ := strconv.Atoi(req.URL.Query().Get("code"))
		if code != 0 && (code < 100 || code > 599) {
			http.Error(w, "code must be 100-599", http.StatusBadRequest)
			return
		}
		if code == 0 {
			code = http.StatusNoContent
		}
		r.mu.Lock()
		r.status = code
		r.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		r.mu.Lock()
		r.reqs = append(r.reqs, recordedRequest{TS: time.Now().UTC(), Method: req.Method, Path: req.URL.Path, Header: req.Header.Clone(), Body: string(body)})
		code := r.status
		r.mu.Unlock()
		w.WriteHeader(code)
	}
}
