// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package alert

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// t0 is far from today on purpose: nothing may read the real clock.
var t0 = time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC)

func sp(s string) *string { return &s }

func golden(t *testing.T, name string, v any) {
	t.Helper()
	got, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.TrimRight(want, "\n")) {
		t.Fatalf("%s differs.\n got: %s\nwant: %s", name, got, want)
	}
}

func stateChange() StateChangePayload {
	texts, codes := SplitReasons(json.RawMessage(`[{"rule":"clamd_down","severity":"CRIT","msg":"clamd not responding: connection refused"}]`))
	return StateChangePayload{
		Schema: SchemaVersion, ID: "6f1c0e8b2d4a4f7e9a3b5c7d9e1f2a3b", Kind: KindStateChange, Target: "ops-webhook",
		Host: "app01", Tags: SortedTags([]string{"web", "prod"}), TS: FormatTime(t0),
		URL: HostURL("https://clamfleet.example", "app01"), From: sp("OK"), To: "CRIT",
		Reason: texts, ReasonCodes: codes, Resolved: false, Changes: 1,
	}
}

// The golden files are the reference of the public payload: any change to a
// key, its order or its type fails here, which is the prompt to take a schema
// decision (CLAUDE.md).
func TestPayloadGolden(t *testing.T) {
	golden(t, "state_change.golden.json", stateChange())
	golden(t, "detection.golden.json", DetectionPayload{
		Schema: SchemaVersion, ID: "0a1b2c3d4e5f60718293a4b5c6d7e8f9", Kind: KindDetection, Target: "ops-webhook",
		Host: "app01", Tags: []string{"prod", "web"}, TS: FormatTime(t0),
		URL: HostURL("https://clamfleet.example", "app01"), Path: "/home/alice/eicar.com", Signature: "Win.Test.EICAR_HDB-1",
		Source: "clamonacc", ReceivedAt: FormatTime(t0.Add(3 * time.Second)),
	})
	golden(t, "detection_summary.golden.json", DetectionSummaryPayload{
		Schema: SchemaVersion, ID: "1a2b3c4d5e6f708192a3b4c5d6e7f809", Kind: KindDetectionSummary, Target: "ops-webhook",
		Host: "app01", Tags: []string{"prod", "web"}, TS: FormatTime(t0.Add(10 * time.Minute)),
		URL: EventsURL("https://clamfleet.example", "app01"), Count: 4321,
		FirstTS: FormatTime(t0.Add(-20 * time.Minute)), LastTS: FormatTime(t0.Add(10*time.Minute - 2*time.Second)),
		WindowStart: FormatTime(t0), WindowEnd: FormatTime(t0.Add(10 * time.Minute)), WindowSeconds: 600,
		Signatures: []SignatureCount{{"Win.Test.EICAR_HDB-1", 4300}, {"Php.Shell_x", 21}},
	})
	golden(t, "test.golden.json", TestPayload{
		Schema: SchemaVersion, ID: "ffeeddccbbaa99887766554433221100", Kind: KindTest, Target: "ops-webhook",
		TS: FormatTime(t0), URL: RootURL("https://clamfleet.example"),
	})
}

// Without public_url the link is an explicit null, and a first evaluation's
// from is null too: the keys stay present.
func TestPayloadNullsStayPresent(t *testing.T) {
	p := stateChange()
	p.URL, p.From = HostURL("", "app01"), nil
	b, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"url":null`, `"from":null`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
	tb, _ := Marshal(TestPayload{Schema: 1, ID: "x", Kind: KindTest, Target: "t", TS: FormatTime(t0), URL: RootURL("")})
	if !strings.Contains(string(tb), `"url":null`) {
		t.Errorf("test payload url: %s", tb)
	}
}

func TestSortedTagsAndEmpty(t *testing.T) {
	if got := SortedTags([]string{"web", "prod", "a"}); !reflect.DeepEqual(got, []string{"a", "prod", "web"}) {
		t.Fatalf("%v", got)
	}
	in := []string{"b", "a"}
	SortedTags(in)
	if in[0] != "b" {
		t.Fatal("SortedTags must not reorder its input")
	}
	b, _ := json.Marshal(SortedTags(nil))
	if string(b) != "[]" {
		t.Fatalf("no tags must encode as [], got %s", b)
	}
}

func TestSplitReasons(t *testing.T) {
	texts, codes := SplitReasons(json.RawMessage(`[{"rule":"a","severity":"WARN","msg":"x"},{"rule":"b","severity":"CRIT","msg":"y"}]`))
	if !reflect.DeepEqual(texts, []string{"x", "y"}) || !reflect.DeepEqual(codes, []string{"a", "b"}) {
		t.Fatalf("%v %v", texts, codes)
	}
	for _, bad := range []string{``, `null`, `{`, `[]`} {
		texts, codes := SplitReasons(json.RawMessage(bad))
		if texts == nil || codes == nil || len(texts) != 0 || len(codes) != 0 {
			t.Errorf("%q: want empty non-nil arrays, got %v %v", bad, texts, codes)
		}
	}
}

// A receiver written against schema 1 keeps working when a field is added:
// decoding a payload with an unknown field and an unknown kind must succeed.
func TestPayloadDecodeIgnoresUnknownFields(t *testing.T) {
	var e Envelope
	if err := json.Unmarshal([]byte(`{"schema":1,"id":"i","kind":"future_kind","target":"t","new_field":{"a":1}}`), &e); err != nil {
		t.Fatal(err)
	}
	if e.Kind != "future_kind" || e.ID != "i" {
		t.Fatalf("%+v", e)
	}
	var p StateChangePayload
	raw, _ := Marshal(stateChange())
	raw = bytes.Replace(raw, []byte(`"changes":1`), []byte(`"changes":1,"extra":true`), 1)
	if err := json.Unmarshal(raw, &p); err != nil || p.Host != "app01" {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestFormatTimeIsUTCWholeSeconds(t *testing.T) {
	loc := time.FixedZone("x", 3600)
	got := FormatTime(time.Date(2031, 3, 4, 13, 0, 0, 999, loc))
	if got != "2031-03-04T12:00:00Z" {
		t.Fatal(got)
	}
}

// A summary never carries a path: a mass detection can name thousands of files,
// and the events page has them.
func TestSummaryPayloadHasNoPathKey(t *testing.T) {
	b, err := Marshal(DetectionSummaryPayload{Schema: 1, ID: "i", Kind: KindDetectionSummary, Signatures: []SignatureCount{}})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"path", "paths", "source"} {
		if _, ok := m[k]; ok {
			t.Fatalf("summary has a %q key: %s", k, b)
		}
	}
	for _, k := range []string{"url", "signatures", "more_signatures", "count"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("summary lacks %q: %s", k, b)
		}
	}
}
