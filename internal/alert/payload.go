// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package alert turns state changes and detections into alerts and delivers
// them to email and webhook targets (Milestone 4).
//
// payload.go: the alert payload, schema 1. These structs are a PUBLIC
// INTERFACE: receivers are written against them (docs/alerts.md is the
// reference and testdata/*.golden.json pins the exact bytes). Do not rename a
// key or change a type without bumping Schema and a schema decision.
//
// Conventions (same as internal/proto):
//   - No omitempty. A key that applies to a kind is always present; a value
//     that is unknown is an explicit JSON null (pointer fields), never a
//     missing key and never a misleading zero. The three kinds are three
//     structs, so a key that does not apply to a kind is simply not there.
//   - Timestamps are UTC, whole seconds.
//   - Receivers must ignore unknown fields and unknown kinds; adding a field or
//     a kind keeps Schema 1.
//
// Text fields reason, path and signature are controlled by the monitored host:
// they are data, never markup (the email renderer escapes them, receivers are
// told to).
//
// Dependencies: the standard library only.
package alert

import (
	"encoding/json"
	"sort"
	"time"
)

// SchemaVersion is the value of the "schema" key in every alert payload.
const SchemaVersion = 1

// Kinds of an alert payload.
const (
	KindStateChange = "state_change"
	KindDetection   = "detection"
	KindTest        = "test"
)

// StateChangePayload is the alert for a host's state change.
type StateChangePayload struct {
	Schema int    `json:"schema"`
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Host   string `json:"host"`
	// Tags are the host's tags at planning time, sorted.
	Tags []string `json:"tags"`
	TS   string   `json:"ts"`
	// URL is public_url + "/hosts/" + host, null while public_url is unset.
	URL *string `json:"url"`
	// From is the state THIS TARGET was last told about the host (so every
	// alert's from is the previous alert's to), or the transition's own from
	// for the first alert to this target about this host (null on the host's
	// first evaluation).
	From *string `json:"from"`
	To   string  `json:"to"`
	// Reason holds the human texts and ReasonCodes the stable rule codes of
	// the reasons behind To.
	Reason      []string `json:"reason"`
	ReasonCodes []string `json:"reason_codes"`
	// Resolved is true when To is below the target's minimum severity: the
	// problem this target was told about is over, as far as it is concerned.
	Resolved bool `json:"resolved"`
	// Changes is how many state changes this alert covers (more than 1 when a
	// cooldown coalesced several).
	Changes int `json:"changes"`
}

// DetectionPayload is the alert for one detection. TS is the agent's event
// time and ReceivedAt the server's.
type DetectionPayload struct {
	Schema     int      `json:"schema"`
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Target     string   `json:"target"`
	Host       string   `json:"host"`
	Tags       []string `json:"tags"`
	TS         string   `json:"ts"`
	URL        *string  `json:"url"`
	Path       string   `json:"path"`
	Signature  string   `json:"signature"`
	Source     string   `json:"source"`
	ReceivedAt string   `json:"received_at"`
}

// TestPayload is what a test-send delivers. URL is the public_url root, or null.
type TestPayload struct {
	Schema int     `json:"schema"`
	ID     string  `json:"id"`
	Kind   string  `json:"kind"`
	Target string  `json:"target"`
	TS     string  `json:"ts"`
	URL    *string `json:"url"`
}

// Envelope reads the keys every kind shares, for code that only routes a
// stored payload (the sender needs the id; the email renderer the kind).
type Envelope struct {
	Schema int    `json:"schema"`
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
}

// FormatTime is the wire form of a time: UTC, whole seconds, RFC 3339.
func FormatTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}

// HostURL is the link to a host's page, nil when publicURL is empty. The host
// name is admin-assigned and validated ([a-z0-9._-]), so it needs no escaping.
func HostURL(publicURL, host string) *string {
	if publicURL == "" {
		return nil
	}
	u := publicURL + "/hosts/" + host
	return &u
}

// RootURL is public_url itself, nil when unset (test payload).
func RootURL(publicURL string) *string {
	if publicURL == "" {
		return nil
	}
	return &publicURL
}

// SortedTags returns a sorted copy of tags, never nil (it encodes as []).
func SortedTags(tags []string) []string {
	out := append([]string{}, tags...)
	sort.Strings(out)
	return out
}

// storedReason is one element of the reason JSON the health evaluator stores
// (health.Reason). It is declared here so this package stays free of the store
// and the evaluator.
type storedReason struct {
	Rule string `json:"rule"`
	Msg  string `json:"msg"`
}

// SplitReasons turns the stored reason JSON into the payload's two parallel
// arrays. Unreadable or empty input yields empty arrays, not an error: an
// alert about a state change must still go out when the reason text is
// damaged.
func SplitReasons(raw json.RawMessage) (texts, codes []string) {
	texts, codes = []string{}, []string{}
	var rs []storedReason
	if len(raw) == 0 || json.Unmarshal(raw, &rs) != nil {
		return texts, codes
	}
	for _, r := range rs {
		texts = append(texts, r.Msg)
		codes = append(codes, r.Rule)
	}
	return texts, codes
}

// Marshal encodes a payload. The result is what is stored in
// alert_deliveries.payload and sent byte for byte on every retry.
func Marshal(p any) ([]byte, error) { return json.Marshal(p) }
