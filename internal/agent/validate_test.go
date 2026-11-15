// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

var vNow = time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC)

func vEvent(mut func(*proto.Event)) []byte {
	id := idA
	ev := proto.Event{Schema: 1, ID: &id, Host: "app01", TS: vNow.Add(-time.Minute), Path: "/srv/a", Signature: "Win.Test.EICAR_HDB-1", Source: "clamd"}
	if mut != nil {
		mut(&ev)
	}
	b, _ := json.Marshal(ev)
	return b
}

func TestValidateEvent(t *testing.T) {
	bad := "BAD"
	for _, c := range []struct {
		name string
		raw  []byte
		id   string
		want string // substring of the reason; "" = valid; "expired" = errExpired
	}{
		{"valid", vEvent(nil), idA, ""},
		{"not json", []byte("{"), idA, "not a JSON"},
		{"schema 2", vEvent(func(e *proto.Event) { e.Schema = 2 }), idA, "schema"},
		{"no id", vEvent(func(e *proto.Event) { e.ID = nil }), idA, "id is not"},
		{"id not hex", vEvent(func(e *proto.Event) { e.ID = &bad }), idA, "id is not"},
		{"id uppercase", vEvent(func(e *proto.Event) { u := strings.ToUpper(idA); e.ID = &u }), idA, "id is not"},
		{"id does not match name", vEvent(nil), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "match the file name"},
		{"empty host", vEvent(func(e *proto.Event) { e.Host = "" }), idA, "host"},
		{"host with newline", vEvent(func(e *proto.Event) { e.Host = "a\nb" }), idA, "host"},
		{"host of 254 bytes", vEvent(func(e *proto.Event) { e.Host = strings.Repeat("a", 254) }), idA, "host"},
		{"zero ts", vEvent(func(e *proto.Event) { e.TS = time.Time{} }), idA, "ts is zero"},
		{"ts before 2000", vEvent(func(e *proto.Event) { e.TS = time.Date(1999, 12, 31, 0, 0, 0, 0, time.UTC) }), idA, "ts is zero"},
		{"ts 11 minutes ahead", vEvent(func(e *proto.Event) { e.TS = vNow.Add(11 * time.Minute) }), idA, "future"},
		{"ts 9 minutes ahead", vEvent(func(e *proto.Event) { e.TS = vNow.Add(9 * time.Minute) }), idA, ""},
		{"ts older than max age", vEvent(func(e *proto.Event) { e.TS = vNow.Add(-366 * 24 * time.Hour) }), idA, "expired"},
		{"ts just inside max age", vEvent(func(e *proto.Event) { e.TS = vNow.Add(-364 * 24 * time.Hour) }), idA, ""},
		{"empty path", vEvent(func(e *proto.Event) { e.Path = "" }), idA, "path length"},
		{"path of 4096", vEvent(func(e *proto.Event) { e.Path = strings.Repeat("a", 4096) }), idA, ""},
		{"path of 4097", vEvent(func(e *proto.Event) { e.Path = strings.Repeat("a", 4097) }), idA, "path length"},
		{"path with NUL", vEvent(func(e *proto.Event) { e.Path = "/a\x00b" }), idA, "NUL"},
		{"path with invalid UTF-8", []byte(`{"schema":1,"id":"` + idA + `","host":"h","ts":"2031-03-04T11:59:00Z","path":"/a` + "\xff" + `","signature":"S","source":"clamd"}`), idA, ""}, // the decoder replaces the byte; the encoding is the agent's, see event.go
		{"empty signature", vEvent(func(e *proto.Event) { e.Signature = "" }), idA, "signature"},
		{"signature with DEL", vEvent(func(e *proto.Event) { e.Signature = "a\x7fb" }), idA, "signature"},
		{"signature with non-ASCII", vEvent(func(e *proto.Event) { e.Signature = "Wïn" }), idA, "signature"},
		{"signature of 257", vEvent(func(e *proto.Event) { e.Signature = strings.Repeat("a", 257) }), idA, "signature"},
		{"signature of 256", vEvent(func(e *proto.Event) { e.Signature = strings.Repeat("a", 256) }), idA, ""},
		{"source clamonacc", vEvent(func(e *proto.Event) { e.Source = "clamonacc" }), idA, "source"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ValidateEvent(c.raw, c.id, vNow, 365*24*time.Hour)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("rejected: %v", err)
			case c.want == "expired":
				if !errors.Is(err, errExpired) {
					t.Fatalf("err = %v, want errExpired", err)
				}
			case c.want != "":
				var ie *invalidError
				if !errors.As(err, &ie) || !strings.Contains(ie.Reason, c.want) {
					t.Fatalf("err = %v, want a reason containing %q", err, c.want)
				}
			}
		})
	}
}

// The reason never holds the path: it goes to the agent's log.
func TestValidateErrorsNeverContainThePath(t *testing.T) {
	const marker = "/srv/MARKER-PATH"
	for _, mut := range []func(*proto.Event){
		func(e *proto.Event) { e.Schema = 9 },
		func(e *proto.Event) { e.Signature = "" },
		func(e *proto.Event) { e.Path = marker + "\x00" },
		func(e *proto.Event) { e.Path = marker + strings.Repeat("a", 5000) },
		func(e *proto.Event) { e.TS = time.Time{} },
	} {
		mut := mut
		_, err := ValidateEvent(vEvent(func(e *proto.Event) { e.Path = marker; mut(e) }), idA, vNow, time.Hour)
		if err == nil || strings.Contains(err.Error(), "MARKER") {
			t.Fatalf("err = %v", err)
		}
	}
}

// Unknown fields never reach the server: the body is the marshalled struct.
func TestValidateEventDropsUnknownFieldsOnReencode(t *testing.T) {
	raw := []byte(`{"schema":1,"id":"` + idA + `","host":"h","ts":"2031-03-04T11:59:00Z","path":"/a","signature":"S","source":"clamd","admin":true,"extra":{"x":1}}`)
	ev, err := ValidateEvent(raw, idA, vNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(ev)
	if strings.Contains(string(out), "admin") || strings.Contains(string(out), "extra") {
		t.Fatalf("re-encoded body carries unknown fields: %s", out)
	}
}

func TestValidateReport(t *testing.T) {
	good := `{"schema":1,"host":"h","tags":[],"ts":"2031-03-04T11:59:00Z","replay":true}`
	r, err := ValidateReport([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if r.Replay {
		t.Fatal("replay from disk must be ignored: the agent decides at send time")
	}
	for name, raw := range map[string]string{
		"not json": "x", "schema 2": `{"schema":2,"ts":"2031-03-04T11:59:00Z"}`, "zero ts": `{"schema":1}`,
	} {
		if _, err := ValidateReport([]byte(raw)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
