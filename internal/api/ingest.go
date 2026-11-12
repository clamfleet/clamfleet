// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// ingest.go: POST /v1/report and POST /v1/event.
//
// Order inside a handler (it matters, see docs/api.md):
//  1. Authentication has already run (middleware), before any body is read, so
//     an unauthenticated client cannot make the server parse a megabyte.
//  2. http.MaxBytesReader: an oversized body is 413.
//  3. Decode without DisallowUnknownFields (spec 7.2: servers ignore unknown
//     fields so a newer agent keeps working), then require EOF: trailing data
//     is a 400.
//  4. Validate. 5. Write to the store.
//
// Dependencies: internal/store, internal/proto, internal/agentauth.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/clamfleet/clamfleet/internal/agentauth"
	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
)

// Request body caps (decision in docs/api.md).
const (
	MaxReportBytes = 1 << 20
	MaxEventBytes  = 64 << 10
)

// Validation limits.
const (
	maxTags       = 32
	maxTagBytes   = 64
	maxHostBytes  = 253
	maxVersionLen = 64
	maxPathBytes  = 4096
	maxSigBytes   = 256
	maxSourceLen  = 32
	// skewWarn: how far into the future an agent timestamp may be before the
	// server logs it. The report is still accepted: rejecting for skew would
	// blind the fleet view exactly when a host's clock is wrong.
	skewWarn = 5 * time.Minute
)

// Deps are the handlers' dependencies.
type Deps struct {
	Store store.Store
	// Now is the injected clock for every server-side timestamp.
	Now func() time.Time
	Log *slog.Logger
	// AfterReport, when set, is called after a report was accepted and stored
	// (a duplicate too: it still proves the agent is alive), so the host's
	// health state follows the report at once. Its error is logged and never
	// changes the 202: the report is safe, and the evaluation loop catches up.
	AfterReport func(ctx context.Context, hostID int64) error
}

// afterReportTimeout bounds the evaluation that follows a report.
const afterReportTimeout = 5 * time.Second

// Handlers holds the ingest handlers.
type Handlers struct {
	d Deps

	mu     sync.Mutex
	skewed map[int64]bool // hosts whose last report was future-skewed, to log once per change
}

// New returns the handlers for d.
func New(d Deps) *Handlers {
	return &Handlers{d: d, skewed: map[int64]bool{}}
}

// decodeBody reads one JSON document of at most limit bytes into v and writes
// the error response itself when it fails (returns false then).
func decodeBody(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	err := dec.Decode(v)
	if err == nil {
		// A second value, or garbage after the first, is a malformed request.
		if _, err2 := dec.Token(); !errors.Is(err2, io.EOF) {
			err = errors.New("unexpected data after the JSON document")
			if isTooLarge(err2) {
				err = err2
			}
		}
	}
	switch {
	case err == nil:
		return true
	case isTooLarge(err):
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %d bytes", limit))
	default:
		writeError(w, http.StatusBadRequest, "invalid JSON: "+describeDecodeError(err))
	}
	return false
}

// describeDecodeError keeps Go type names out of the response (they are internal
// detail and mean nothing to an agent operator).
func describeDecodeError(err error) string {
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		if ute.Field == "" {
			return "the document must be a JSON object"
		}
		return fmt.Sprintf("field %q: cannot use a JSON %s", ute.Field, ute.Value)
	}
	return err.Error()
}

func isTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

// normalizeTags validates and de-duplicates (order kept) the tag list.
func normalizeTags(tags []string) ([]string, error) {
	out := make([]string, 0, len(tags))
	seen := map[string]bool{}
	if len(tags) > maxTags {
		return nil, fmt.Errorf("tags: at most %d allowed, got %d", maxTags, len(tags))
	}
	for _, t := range tags {
		if len(t) < 1 || len(t) > maxTagBytes || hasControl(t) {
			return nil, fmt.Errorf("tags: each tag must be 1-%d bytes without control characters", maxTagBytes)
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}

func validateReport(r *proto.Report) error {
	if r.Schema != proto.SchemaVersion {
		return fmt.Errorf("unsupported schema %d: this server accepts schema %d", r.Schema, proto.SchemaVersion)
	}
	if r.TS.IsZero() {
		return errors.New("ts is required")
	}
	if len(r.Host) > maxHostBytes || hasControl(r.Host) {
		return fmt.Errorf("host: at most %d bytes without control characters", maxHostBytes)
	}
	if len(r.AgentVersion) > maxVersionLen || hasControl(r.AgentVersion) {
		return fmt.Errorf("agent_version: at most %d bytes without control characters", maxVersionLen)
	}
	tags, err := normalizeTags(r.Tags)
	if err != nil {
		return err
	}
	r.Tags = tags
	return nil
}

func validateEvent(e *proto.Event) error {
	switch {
	case e.Schema != proto.SchemaVersion:
		return fmt.Errorf("unsupported schema %d: this server accepts schema %d", e.Schema, proto.SchemaVersion)
	case e.TS.IsZero():
		return errors.New("ts is required")
	case len(e.Path) < 1 || len(e.Path) > maxPathBytes || strings.ContainsRune(e.Path, 0):
		return fmt.Errorf("path: 1-%d bytes, no NUL", maxPathBytes)
	case len(e.Signature) < 1 || len(e.Signature) > maxSigBytes || hasControl(e.Signature):
		return fmt.Errorf("signature: 1-%d bytes without control characters", maxSigBytes)
	case len(e.Source) < 1 || len(e.Source) > maxSourceLen || hasControl(e.Source):
		return fmt.Errorf("source: 1-%d bytes without control characters", maxSourceLen)
	}
	return nil
}

// identity returns the authenticated host. Reaching a handler without one is a
// wiring bug (the route is not behind the middleware): fail closed with 401
// instead of serving anonymously.
func (h *Handlers) identity(w http.ResponseWriter, r *http.Request) (agentauth.Identity, bool) {
	id, ok := agentauth.FromContext(r.Context())
	if !ok {
		h.d.Log.Error("ingest handler reached without authentication: route is not behind the auth middleware", "path", r.URL.Path)
		w.Header().Set("WWW-Authenticate", `Bearer realm="clamfleet"`)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return agentauth.Identity{}, false
	}
	setLogHost(r.Context(), id.HostName)
	return id, true
}

// storeFailed answers a store error: 401 if the host vanished between
// authentication and the write (its token is gone), else 503. Never 500 with
// detail: the operator reads the log, the agent just retries.
func (h *Handlers) storeFailed(w http.ResponseWriter, ctx context.Context, op string, err error) {
	if errors.Is(err, store.ErrNotFound) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="clamfleet"`)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	h.d.Log.ErrorContext(ctx, "store failed", "op", op, "error", err.Error())
	writeError(w, http.StatusServiceUnavailable, "service unavailable")
}

// Report handles POST /v1/report.
func (h *Handlers) Report(w http.ResponseWriter, r *http.Request) {
	id, ok := h.identity(w, r)
	if !ok {
		return
	}
	var rep proto.Report
	if !decodeBody(w, r, MaxReportBytes, &rep) {
		return
	}
	if err := validateReport(&rep); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := h.d.Now()
	res, err := h.d.Store.RecordReport(r.Context(), store.ReportRecord{HostID: id.HostID, Report: rep, ReceivedAt: now})
	if err != nil {
		h.storeFailed(w, r.Context(), "record report", err)
		return
	}
	if h.d.AfterReport != nil {
		// Detached from the request context: the report is already stored, and an
		// agent that hangs up must not leave its host's state one loop behind.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), afterReportTimeout)
		if err := h.d.AfterReport(ctx, id.HostID); err != nil {
			h.d.Log.Error("health evaluation after a report failed", "host", id.HostName, "error", err.Error())
		}
		cancel()
	}
	h.warnOnMismatch(id, rep.Host, res.PreviousReportedName)
	h.warnOnSkew(id, rep.TS, now)
	writeJSON(w, http.StatusAccepted, struct{}{})
}

// warnOnMismatch: the payload host is display data only (the identity is the
// token's host). A differing name is worth one line, not one every five
// minutes, so it is logged only when it also differs from the previous
// report's name.
func (h *Handlers) warnOnMismatch(id agentauth.Identity, payloadHost, previous string) {
	if strings.EqualFold(payloadHost, id.HostName) || payloadHost == previous {
		return
	}
	h.d.Log.Warn("report host name differs from the registered host; stored under the registered host",
		"registered", id.HostName, "reported", payloadHost)
}

// warnOnSkew logs a future-skewed agent clock once per change (entering the
// skewed state), not on every report.
func (h *Handlers) warnOnSkew(id agentauth.Identity, ts, now time.Time) {
	skewed := ts.Sub(now) > skewWarn
	h.mu.Lock()
	was := h.skewed[id.HostID]
	h.skewed[id.HostID] = skewed
	h.mu.Unlock()
	if skewed && !was {
		h.d.Log.Warn("agent clock is ahead of the server clock", "host", id.HostName, "ahead", ts.Sub(now).Round(time.Second).String())
	}
}

// Event handles POST /v1/event. A duplicate (same host, ts, path and
// signature) is a success: the agent may retry after a lost response.
func (h *Handlers) Event(w http.ResponseWriter, r *http.Request) {
	id, ok := h.identity(w, r)
	if !ok {
		return
	}
	var ev proto.Event
	if !decodeBody(w, r, MaxEventBytes, &ev) {
		return
	}
	if err := validateEvent(&ev); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.d.Store.RecordEvent(r.Context(), store.EventRecord{HostID: id.HostID, Event: ev, ReceivedAt: h.d.Now()}); err != nil {
		h.storeFailed(w, r.Context(), "record event", err)
		return
	}
	writeJSON(w, http.StatusAccepted, struct{}{})
}

// Health handles GET /healthz: unauthenticated, answers whether the database
// is reachable. It reveals nothing else.
func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.d.Store.Ping(ctx); err != nil {
		h.d.Log.ErrorContext(ctx, "health check failed", "error", err.Error())
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
