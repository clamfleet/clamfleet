// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package proto

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"
)

// keyPaths lists every object key path in a JSON document, so two documents
// can be compared by shape. Array elements are folded into "[]".
func keyPaths(t *testing.T, raw []byte) []string {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				p := prefix + "." + k
				out = append(out, p)
				walk(p, c)
			}
		case []any:
			for _, c := range x {
				walk(prefix+"[]", c)
			}
		}
	}
	walk("", v)
	sort.Strings(out)
	return out
}

func strictDecode(t *testing.T, raw []byte, into any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Unknown keys in the spec example would mean the struct lacks a field.
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		t.Fatal(err)
	}
}

// additiveKeys are keys this implementation emits that the spec example lacks.
// Each one is a documented, schema-1-compatible addition (servers ignore
// unknown fields, spec 7.2); anything else missing from the spec is a bug.
var additiveKeys = []string{".freshclam.source"}

func roundTrip(t *testing.T, file string, into any, additive ...string) {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	strictDecode(t, raw, into)
	back, err := json.Marshal(into)
	if err != nil {
		t.Fatal(err)
	}
	// Same key set both ways: no spec key missing from the struct (decode
	// above), and no extra key invented by the struct (this comparison).
	got := keyPaths(t, back)
	for _, a := range additive {
		i := sort.SearchStrings(got, a)
		if i == len(got) || got[i] != a {
			t.Fatalf("additive key %s is not emitted; remove it from the allow-list", a)
		}
		got = append(got[:i], got[i+1:]...)
	}
	if want := keyPaths(t, raw); !reflect.DeepEqual(want, got) {
		t.Fatalf("key set differs from the spec example\nwant %v\n got %v", want, got)
	}
}

func TestReportMatchesSpec(t *testing.T) {
	var r Report
	roundTrip(t, "testdata/report_7_3.json", &r, additiveKeys...)
	if r.Clamd.Queue == nil || *r.Clamd.Queue != 0 || r.Sigs.Daily.Version != 27450 || r.LastScan.Scanned != 120345 {
		t.Fatalf("values not decoded: %+v", r)
	}
}

func TestEventMatchesSpec(t *testing.T) {
	var e Event
	roundTrip(t, "testdata/event_7_4.json", &e)
	if e.Signature != "Win.Test.EICAR_HDB-1" {
		t.Fatalf("got %+v", e)
	}
}

// A zero-value report must still carry every key: unknowns are null, tags is [].
func TestZeroReportKeepsEveryKey(t *testing.T) {
	zero := Report{Tags: []string{}}
	raw, err := json.Marshal(zero)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	if tags, ok := generic["tags"].([]any); !ok || len(tags) != 0 {
		t.Fatalf("tags = %#v, want []", generic["tags"])
	}
	if v, ok := generic["last_scan"]; !ok || v != nil {
		t.Fatalf("last_scan = %#v, want null", v)
	}
	clamd := generic["clamd"].(map[string]any)
	for _, k := range []string{"version", "queue", "error"} {
		if v, ok := clamd[k]; !ok || v != nil {
			t.Fatalf("clamd.%s = %#v (present=%v), want null", k, v, ok)
		}
	}
	sigs := generic["sigs"].(map[string]any)
	for _, k := range []string{"daily", "main", "bytecode"} {
		if v, ok := sigs[k]; !ok || v != nil {
			t.Fatalf("sigs.%s = %#v (present=%v), want null", k, v, ok)
		}
	}
	fc := generic["freshclam"].(map[string]any)
	for _, k := range []string{"last_ok", "last_error", "last_error_msg", "source"} {
		if v, ok := fc[k]; !ok || v != nil {
			t.Fatalf("freshclam.%s = %#v (present=%v), want null", k, v, ok)
		}
	}
}

func TestUTCTruncatesAndNormalises(t *testing.T) {
	berlin := time.FixedZone("CET", 3600)
	got := UTC(time.Date(2026, 11, 12, 11, 0, 5, 999_000_000, berlin))
	want := time.Date(2026, 11, 12, 10, 0, 5, 0, time.UTC)
	if !got.Equal(want) || got.Location() != time.UTC {
		t.Fatalf("got %v want %v", got, want)
	}
}
