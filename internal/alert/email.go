// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// email.go: rendering an alert payload as an email.
//
// Rules that carry the security of this file:
//   - Headers hold NO host-controlled text. The subject is built from the
//     admin-assigned host name (validated to [a-z0-9._-]), the state words and
//     fixed text; every header value is also stripped of control characters and
//     Q-encoded when non-ASCII, as a second line of defence.
//   - The body is plain text, quoted-printable. Text controlled by the monitored
//     host (reason, path, signature) has control characters and invalid UTF-8
//     replaced with \xNN, so no value can start a new header or a "." line
//     (a detection path may contain CR and LF: validateEvent only refuses NUL).
//     The SMTP DATA writer still dot-stuffs.
//   - Date comes from the injected clock; Message-ID is stable across retries
//     of one alert and target, so receivers can deduplicate a resend.
package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"strings"
	"time"
	"unicode/utf8"
)

// EmailMessage is a rendered message for one recipient.
type EmailMessage struct {
	From      string
	To        string
	Subject   string
	Date      time.Time
	MessageID string
	AlertID   string
	// Body is the plain-text body with LF line ends.
	Body string
}

// escapeText makes host-controlled text safe for a plain-text body: control
// characters (CR, LF, TAB, ESC, ...), DEL and invalid UTF-8 become \xNN.
func escapeText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 || r < 0x20 || r == 0x7f {
			fmt.Fprintf(&b, `\x%02x`, s[i])
			i++
			continue
		}
		b.WriteString(s[i : i+size])
		i += size
	}
	return b.String()
}

// headerSafe strips everything that could end a header line from a value.
func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
}

func qEncode(s string) string { return mime.QEncoding.Encode("utf-8", headerSafe(s)) }

func fromDomain(from string) string {
	if i := strings.LastIndex(from, "@"); i >= 0 {
		return headerSafe(from[i+1:])
	}
	return "localhost"
}

// RenderEmail renders the stored payload of a delivery for one recipient.
// targetID goes into the Message-ID. It returns an error for a payload it
// cannot read (a permanent failure: retrying cannot help).
func RenderEmail(from, to string, targetID int64, payload []byte, now time.Time) (EmailMessage, error) {
	var env Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return EmailMessage{}, fmt.Errorf("alert payload is not readable: %w", err)
	}
	m := EmailMessage{
		From: from, To: to, Date: now, AlertID: env.ID,
		MessageID: fmt.Sprintf("<%s.%d@%s>", headerSafe(env.ID), targetID, fromDomain(from)),
	}
	var b strings.Builder
	line := func(label, value string) { fmt.Fprintf(&b, "%-10s %s\n", label+":", value) }
	switch env.Kind {
	case KindStateChange:
		var p StateChangePayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return EmailMessage{}, fmt.Errorf("alert payload is not readable: %w", err)
		}
		fromState := "none"
		if p.From != nil {
			fromState = *p.From
		}
		m.Subject = fmt.Sprintf("[ClamFleet] %s: %s -> %s", p.Host, fromState, p.To)
		if p.Resolved {
			m.Subject += " resolved for this target"
		}
		b.WriteString("ClamFleet: a host changed state.\n\n")
		line("Host", p.Host)
		line("State", fromState+" -> "+p.To)
		if p.Resolved {
			b.WriteString("           (below this target's minimum severity: resolved for this target)\n")
		}
		if p.Changes > 1 {
			line("Changes", fmt.Sprintf("%d (coalesced during the cooldown)", p.Changes))
		}
		line("Tags", escapeText(strings.Join(p.Tags, ", ")))
		line("Time", p.TS)
		if p.URL != nil {
			line("Link", *p.URL)
		}
		line("Target", p.Target)
		line("Alert id", p.ID)
		if len(p.Reason) > 0 {
			b.WriteString("\nReasons (text from the monitored host, shown escaped):\n")
			for i, r := range p.Reason {
				code := ""
				if i < len(p.ReasonCodes) {
					code = " [" + escapeText(p.ReasonCodes[i]) + "]"
				}
				fmt.Fprintf(&b, "  - %s%s\n", escapeText(r), code)
			}
		}
	case KindDetection:
		var p DetectionPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return EmailMessage{}, fmt.Errorf("alert payload is not readable: %w", err)
		}
		m.Subject = fmt.Sprintf("[ClamFleet] %s: detection", p.Host)
		b.WriteString("ClamFleet: a detection was reported.\n\n")
		line("Host", p.Host)
		line("Path", escapeText(p.Path))
		line("Signature", escapeText(p.Signature))
		line("Source", escapeText(p.Source))
		line("Time", p.TS)
		line("Received", p.ReceivedAt)
		line("Tags", escapeText(strings.Join(p.Tags, ", ")))
		if p.URL != nil {
			line("Link", *p.URL)
		}
		line("Target", p.Target)
		line("Alert id", p.ID)
		b.WriteString("\nPath and signature are text from the monitored host, shown escaped.\n")
	case KindDetectionSummary:
		var p DetectionSummaryPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return EmailMessage{}, fmt.Errorf("alert payload is not readable: %w", err)
		}
		m.Subject = fmt.Sprintf("[ClamFleet] %s: %d detections", p.Host, p.Count)
		b.WriteString("ClamFleet: many detections were reported for one host; this is the summary of the ones\nthat were not sent one by one.\n\n")
		line("Host", p.Host)
		line("Detections", fmt.Sprintf("%d", p.Count))
		line("Window", p.WindowStart+" to "+p.WindowEnd)
		line("First", p.FirstTS+" (agent time)")
		line("Last", p.LastTS+" (agent time)")
		line("Tags", escapeText(strings.Join(p.Tags, ", ")))
		if p.URL != nil {
			line("Link", *p.URL)
		}
		line("Target", p.Target)
		line("Alert id", p.ID)
		b.WriteString("\nSignatures (text from the monitored host, shown escaped):\n")
		for _, sc := range p.Signatures {
			fmt.Fprintf(&b, "  - %s: %d\n", escapeText(sc.Signature), sc.Count)
		}
		if p.MoreSignatures > 0 {
			fmt.Fprintf(&b, "  ... and %d more signatures\n", p.MoreSignatures)
		}
		b.WriteString("\nThe paths are on the events page; they are not sent by email.\n")
	case KindTest:
		var p TestPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return EmailMessage{}, fmt.Errorf("alert payload is not readable: %w", err)
		}
		m.Subject = "[ClamFleet] test"
		b.WriteString("ClamFleet: this is a test message for an alert target.\n\n")
		line("Target", p.Target)
		line("Time", p.TS)
		if p.URL != nil {
			line("Console", *p.URL)
		}
		line("Alert id", p.ID)
	default:
		return EmailMessage{}, fmt.Errorf("unknown alert kind %q", escapeText(env.Kind))
	}
	m.Body = b.String()
	return m, nil
}

// Bytes returns the message as sent on the wire (CRLF line ends, no dot-stuffing:
// the SMTP data writer does that).
func (m EmailMessage) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	h := func(k, v string) { buf.WriteString(k + ": " + v + "\r\n") }
	h("From", headerSafe(m.From))
	h("To", headerSafe(m.To))
	h("Subject", qEncode(m.Subject))
	h("Date", m.Date.UTC().Format(time.RFC1123Z))
	h("Message-ID", m.MessageID)
	h("MIME-Version", "1.0")
	h("Content-Type", "text/plain; charset=utf-8")
	h("Content-Transfer-Encoding", "quoted-printable")
	h("Auto-Submitted", "auto-generated") // RFC 3834: no auto-replies, no vacation loops
	h("X-ClamFleet-Alert-Id", headerSafe(m.AlertID))
	buf.WriteString("\r\n")
	w := quotedprintable.NewWriter(&buf)
	if _, err := w.Write([]byte(m.Body)); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
