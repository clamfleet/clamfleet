// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// metrics.go: GET /metrics in the Prometheus text exposition format 0.0.4
// (decisions 6 and 7).
//
// Why our own encoder and not prometheus/client_golang: our metrics are a dozen
// gauges computed per scrape, the text format is simple, and the library brings
// protobuf, Prometheus's model and procfs packages plus Go and process metrics
// that node_exporter and systemd already provide (dependency rule: a small
// custom implementation beats a heavy package where the problem is not hard).
//
// Access: off by default (404). When on, a bearer token read from a file is
// required, because the page lists every host name and its health. The token is
// compared as SHA-256 hashes in constant time. The route sets no cookie, so it
// has no CSRF surface, and a console session alone gets 401.
//
// Never exported: a detection path, a signature name or a host tag (personal
// data or free text); only host names, states and counts.
package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/clamfleet/clamfleet/internal/api"
	"github.com/clamfleet/clamfleet/internal/secrets"
	"github.com/clamfleet/clamfleet/internal/store"
)

// Metrics configures GET /metrics.
type Metrics struct {
	// Enabled switches the route on. Off by default: with it off the route is a 404.
	Enabled bool `yaml:"enabled"`
	// TokenFile holds the bearer token (at least 32 bytes after trimming), read
	// once at start under the key-file permission rule (root:clamfleet-server 0640).
	// Required when enabled; never YAML or environment (M4 decision 11).
	// Prometheus sends it with authorization.credentials_file.
	TokenFile string `yaml:"token_file"`
}

// minMetricsToken is the shortest accepted token: 32 bytes is 256 bits of a
// random token, and refuses a guessable word.
const minMetricsToken = 32

// Validate checks the metrics keys without I/O.
func (m Metrics) Validate() error {
	if !m.Enabled {
		return nil
	}
	if m.TokenFile == "" {
		return fmt.Errorf("metrics.token_file is required when metrics.enabled is true: /metrics lists every host and needs a bearer token")
	}
	if !strings.HasPrefix(m.TokenFile, "/") {
		return fmt.Errorf("metrics.token_file must be an absolute path, got %q", m.TokenFile)
	}
	return nil
}

// loadMetricsToken reads the token file, or returns nil when metrics are off.
func loadMetricsToken(m Metrics) ([]byte, error) {
	if !m.Enabled {
		return nil, nil
	}
	tok, err := secrets.ReadProtectedFile(m.TokenFile, "metrics.token_file")
	if err != nil {
		return nil, err
	}
	if len(tok) < minMetricsToken {
		return nil, fmt.Errorf("metrics.token_file %s holds a token of %d bytes: at least %d are required (for example `openssl rand -base64 48`)", m.TokenFile, len(tok), minMetricsToken)
	}
	return []byte(tok), nil
}

// metricsHandler answers GET /metrics. token nil means disabled (404).
func metricsHandler(st store.MetricsStore, token []byte, now func() time.Time, failedWindow time.Duration, version string, trusted []netip.Prefix, log *slog.Logger) http.HandlerFunc {
	var want [sha256.Size]byte
	if token != nil {
		want = sha256.Sum256(token)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if token == nil {
			http.NotFound(w, r)
			return
		}
		// Only "Bearer <token>" is accepted, and the token is compared exactly: a
		// trailing space or another scheme is a 401. Hashing first makes the compare
		// constant-time whatever the lengths are.
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(got))
		if !ok || subtle.ConstantTimeCompare(sum[:], want[:]) != 1 {
			// The client IP only: never the header, which may hold a near-miss of the token.
			log.Warn("metrics request refused", "client", api.ClientIP(r, trusted))
			w.Header().Set("WWW-Authenticate", `Bearer realm="clamfleet-metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		t := now()
		snap, err := st.MetricsSnapshot(r.Context(), t.Add(-failedWindow))
		if err != nil {
			log.Error("metrics snapshot failed", "error", err.Error())
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(EncodeMetrics(snap, t, version))
	}
}

// metricStates are the series of clamfleet_hosts, always all present so an alert
// on "CRIT > 0" never meets a missing series. "pending" is a host never evaluated.
var metricStates = []string{"OK", "WARN", "CRIT", "STALE", "pending"}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// EncodeMetrics renders the snapshot in the text exposition format. Series are
// sorted, so the output is deterministic. A value that is unknown has no series
// (a host never seen has no last-seen series).
func EncodeMetrics(s store.MetricsSnapshot, now time.Time, version string) []byte {
	var b bytes.Buffer
	family := func(name, typ, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	series := func(name string, value string, labels ...string) {
		b.WriteString(name)
		if len(labels) > 0 {
			b.WriteByte('{')
			for i := 0; i < len(labels); i += 2 {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, `%s="%s"`, labels[i], labelEscaper.Replace(labels[i+1]))
			}
			b.WriteByte('}')
		}
		b.WriteByte(' ')
		b.WriteString(value)
		b.WriteByte('\n')
	}
	itoa := func(n int64) string { return strconv.FormatInt(n, 10) }
	hosts := append([]store.MetricsHost(nil), s.Hosts...)
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	stateOf := func(h store.MetricsHost) string {
		if h.State == nil {
			return "pending"
		}
		return *h.State
	}

	counts := map[string]int64{}
	for _, h := range hosts {
		counts[stateOf(h)]++
	}
	family("clamfleet_hosts", "gauge", `Registered hosts by health state ("pending": never evaluated; revoked hosts excluded).`)
	known := map[string]bool{}
	for _, st := range metricStates {
		known[st] = true
		series("clamfleet_hosts", itoa(counts[st]), "state", st)
	}
	var extra []string
	for st := range counts {
		if !known[st] {
			extra = append(extra, st)
		}
	}
	sort.Strings(extra)
	for _, st := range extra {
		series("clamfleet_hosts", itoa(counts[st]), "state", st)
	}

	family("clamfleet_host_state", "gauge", "One series per host, 1 for the host's current health state.")
	for _, h := range hosts {
		series("clamfleet_host_state", "1", "host", h.Name, "state", stateOf(h))
	}
	family("clamfleet_host_last_seen_timestamp_seconds", "gauge", "Unix time of the host's last accepted report (absent when never seen).")
	for _, h := range hosts {
		if h.LastSeen != nil {
			series("clamfleet_host_last_seen_timestamp_seconds", itoa(h.LastSeen.Unix()), "host", h.Name)
		}
	}
	family("clamfleet_host_signature_age_seconds", "gauge", "Server clock minus the build time of the host's signature database (daily, main, bytecode).")
	for _, h := range hosts {
		for _, db := range []string{"bytecode", "daily", "main"} {
			if built, ok := h.SigBuilt[db]; ok {
				series("clamfleet_host_signature_age_seconds", itoa(now.Unix()-built.Unix()), "host", h.Name, "db", db)
			}
		}
	}
	family("clamfleet_events_open", "gauge", "Detections not yet acknowledged.")
	series("clamfleet_events_open", itoa(s.OpenEvents))
	family("clamfleet_alert_deliveries", "gauge", "Alert deliveries: pending and retrying now, failed within retention.alert_log_days.")
	series("clamfleet_alert_deliveries", itoa(s.DeliveriesFailed), "status", "failed")
	series("clamfleet_alert_deliveries", itoa(s.DeliveriesPending), "status", "pending")
	series("clamfleet_alert_deliveries", itoa(s.DeliveriesRetrying), "status", "retrying")
	family("clamfleet_build_info", "gauge", "The server version, always 1.")
	series("clamfleet_build_info", "1", "version", version)
	return b.Bytes()
}
