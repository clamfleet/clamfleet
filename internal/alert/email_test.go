// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package alert

import (
	"encoding/json"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func render(t *testing.T, payload []byte) (EmailMessage, *mail.Message, string) {
	t.Helper()
	m, err := RenderEmail("clamfleet@test.example", "ops@x.example", 7, payload, t0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("not a parseable message: %v\n%s", err, raw)
	}
	b, err := io.ReadAll(quotedprintable.NewReader(parsed.Body))
	if err != nil {
		t.Fatal(err)
	}
	return m, parsed, string(b)
}

func TestEmailHeadersAndBody(t *testing.T) {
	p := stateChange()
	p.Changes = 3
	raw, _ := Marshal(p)
	m, parsed, body := render(t, raw)
	h := parsed.Header
	want := map[string]string{
		"From": "clamfleet@test.example", "To": "ops@x.example", "Subject": "[ClamFleet] app01: OK -> CRIT",
		"Message-Id": "<6f1c0e8b2d4a4f7e9a3b5c7d9e1f2a3b.7@test.example>", "Mime-Version": "1.0",
		"Content-Type": "text/plain; charset=utf-8", "Content-Transfer-Encoding": "quoted-printable",
		"Auto-Submitted": "auto-generated", "X-Clamfleet-Alert-Id": "6f1c0e8b2d4a4f7e9a3b5c7d9e1f2a3b",
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	// Date comes from the injected clock, not the real one.
	if d, err := h.Date(); err != nil || !d.Equal(t0) {
		t.Errorf("Date: %v %v, want %v", d, err, t0)
	}
	for _, s := range []string{"Host:      app01", "OK -> CRIT", "https://clamfleet.example/hosts/app01", "clamd not responding: connection refused", "[clamd_down]", "3 (coalesced"} {
		if !strings.Contains(body, s) {
			t.Errorf("body lacks %q:\n%s", s, body)
		}
	}
	// The Message-ID is stable across renders (and so across retries), and
	// differs per target.
	m2, _ := RenderEmail("clamfleet@test.example", "other@x.example", 7, raw, t0.Add(time.Hour))
	m3, _ := RenderEmail("clamfleet@test.example", "ops@x.example", 8, raw, t0)
	if m.MessageID != m2.MessageID || m.MessageID == m3.MessageID {
		t.Errorf("message ids: %s %s %s", m.MessageID, m2.MessageID, m3.MessageID)
	}
}

func TestEmailSubjects(t *testing.T) {
	p := stateChange()
	p.Resolved, p.To, p.From = true, "OK", sp("CRIT")
	raw, _ := Marshal(p)
	if m, _, _ := render(t, raw); m.Subject != "[ClamFleet] app01: CRIT -> OK resolved for this target" {
		t.Errorf("%q", m.Subject)
	}
	p.From = nil
	raw, _ = Marshal(p)
	if m, _, _ := render(t, raw); !strings.Contains(m.Subject, "none -> OK") {
		t.Errorf("%q", m.Subject)
	}
	d, _ := Marshal(DetectionPayload{Schema: 1, ID: "i", Kind: KindDetection, Target: "t", Host: "app01", Tags: []string{}, TS: FormatTime(t0), Path: "/p", Signature: "S", Source: "scan", ReceivedAt: FormatTime(t0)})
	if m, _, _ := render(t, d); m.Subject != "[ClamFleet] app01: detection" {
		t.Errorf("%q", m.Subject)
	}
	tp, _ := Marshal(TestPayload{Schema: 1, ID: "i", Kind: KindTest, Target: "t", TS: FormatTime(t0)})
	if m, _, body := render(t, tp); m.Subject != "[ClamFleet] test" || !strings.Contains(body, "test message") {
		t.Errorf("%q %q", m.Subject, body)
	}
	if _, err := RenderEmail("a@b", "c@d", 1, []byte(`{"kind":"future"}`), t0); err == nil {
		t.Error("an unknown kind must not render")
	}
	if _, err := RenderEmail("a@b", "c@d", 1, []byte(`nope`), t0); err == nil {
		t.Error("garbage must not render")
	}
}

func TestEmailNonASCIISubjectIsQEncoded(t *testing.T) {
	p := stateChange()
	p.Host = "h\u00f6st" // not a valid host name, but the encoder must still be safe
	raw, _ := Marshal(p)
	m, parsed, _ := render(t, raw)
	dec, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
	if err != nil || dec != m.Subject || strings.ContainsRune(parsed.Header.Get("Subject"), '\u00f6') {
		t.Fatalf("subject %q decoded %q (%v)", parsed.Header.Get("Subject"), dec, err)
	}
}

// Mutation 32: host-controlled text in a header, or no control-character
// escaping in the body. A detection path carrying CRLF, a Bcc header and a
// lone dot appears escaped in the body only.
func TestEmailInjectionThroughPathAndReason(t *testing.T) {
	evil := "/tmp/x\r\nBcc: x@evil.example\r\n.\r\nSubject: pwned\r\n"
	d, _ := Marshal(DetectionPayload{Schema: 1, ID: "i", Kind: KindDetection, Target: "t", Host: "app01", Tags: []string{}, TS: FormatTime(t0),
		Path: evil, Signature: "Sig\r\nBcc: y@evil.example", Source: "scan\nX-Evil: 1", ReceivedAt: FormatTime(t0)})
	_, parsed, body := render(t, d)
	for _, h := range []string{"Bcc", "X-Evil"} {
		if parsed.Header.Get(h) != "" {
			t.Errorf("header %s was injected", h)
		}
	}
	if parsed.Header.Get("Subject") != "[ClamFleet] app01: detection" {
		t.Errorf("subject %q", parsed.Header.Get("Subject"))
	}
	if !strings.Contains(body, `\x0d\x0aBcc: x@evil.example\x0d\x0a.\x0d\x0a`) {
		t.Errorf("the path is not shown escaped:\n%s", body)
	}
	if !strings.Contains(body, "Alert id") || !strings.Contains(body, "shown escaped") {
		t.Errorf("the body is incomplete:\n%s", body)
	}
	for _, l := range strings.Split(body, "\n") {
		if strings.TrimRight(l, "\r") == "." {
			t.Errorf("a lone dot line in the body:\n%s", body)
		}
	}
	// The same for state-change reasons (agent text).
	p := stateChange()
	p.Reason = []string{"bad\r\nBcc: z@evil.example"}
	raw, _ := Marshal(p)
	_, parsed, body = render(t, raw)
	if parsed.Header.Get("Bcc") != "" || !strings.Contains(body, `bad\x0d\x0aBcc: z@evil.example`) {
		t.Errorf("reason not escaped:\n%s", body)
	}
}

func TestEmailLongLinesAndInvalidUTF8Survive(t *testing.T) {
	long := strings.Repeat("a", 2000)
	d, _ := Marshal(DetectionPayload{Schema: 1, ID: "i", Kind: KindDetection, Target: "t", Host: "app01", Tags: []string{}, TS: FormatTime(t0),
		Path: "/" + long + "\xff\xfe/\u00e9", Signature: "S", Source: "scan", ReceivedAt: FormatTime(t0)})
	_, _, body := render(t, d)
	// json.Marshal already turned the invalid bytes into U+FFFD, so the payload
	// is always valid UTF-8; the long line and the accent must survive QP.
	if !strings.Contains(body, "/"+long) || !strings.Contains(body, "\ufffd\ufffd/é") {
		t.Errorf("a 2000 character line or the UTF-8 handling did not survive")
	}
}

func TestEscapeText(t *testing.T) {
	for in, want := range map[string]string{
		"plain":        "plain",
		"a\nb":         `a\x0ab`,
		"tab\there":    `tab\x09here`,
		"\x1b[31m":     `\x1b[31m`,
		"del\x7f":      `del\x7f`,
		"\u00e9\u4e2d": "\u00e9\u4e2d",
		"\xc3":         `\xc3`,
	} {
		if got := escapeText(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	_ = json.Valid
}
