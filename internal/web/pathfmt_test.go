// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package web

import (
	"strings"
	"testing"
)

// join renders segments in a form that shows which are escape elements.
func join(segs []seg) string {
	var b strings.Builder
	for _, s := range segs {
		if s.Esc {
			b.WriteString("[" + s.Text + "]")
		} else {
			b.WriteString(s.Text)
		}
	}
	return b.String()
}

// One representative of every class that must be shown as an escape element.
func TestDisplayPathEscapesEveryInvisibleClass(t *testing.T) {
	for _, r := range []rune{
		0x0001, 0x0085, 0x00AD, 0x034F, 0x061C, 0x180E, 0x200B, 0x200E, 0x2028, 0x2029, 0x202E, 0x2060, 0x2066, 0x206F,
		0xFE0F, 0xFEFF, 0xFFF9, 0xE000, 0xE0041, 0x3164, 0x115F, 0x1160, 0xFFA0, 0x1D173, 0xE0001, 0x202A, 0x202D, 0x200F, '\n', '\t', 0x7f,
	} {
		got := displayPath("a" + string(r) + "b")
		if len(got) != 3 || !got[1].Esc || got[1].Title == "" || strings.ContainsRune(join(got), r) {
			t.Errorf("U+%04X: %+v, want a, an escape element, b, and the raw character gone", r, got)
		}
	}
}

func TestDisplayPathAgentEncoding(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"plain", "/srv/a.txt", "/srv/a.txt"},
		{"doubled backslash is one backslash", `/a\\b`, `/a\b`},
		{"a byte escape is an element", `/a\xffb`, `/a[\xff]b`},
		{"literal text \\u{202E} stays text", `/a\\u{202E}b`, `/a\u{202E}b`},
		{"a real U+202E is an element", "/a\u202eb", `/a[\u{202E}]b`},
		{"a lone backslash is plain", `/a\b`, `/a\b`},
		{"a trailing backslash is plain", `/a\`, `/a\`},
		{"a \\x with bad hex is plain", `/a\xZZ`, `/a\xZZ`},
		{"uppercase hex is not the agent's escape", `/a\xFF`, `/a\xFF`},
		{"script is text", "<script>", "<script>"},
		{"valid UTF-8 kept", "/srv/日本語", "/srv/日本語"},
		{"a raw invalid byte", "/a\xffb", `/a[\xff]b`},
	} {
		if got := join(displayPath(c.in)); got != c.want {
			t.Errorf("%s: %q -> %q, want %q", c.name, c.in, got, c.want)
		}
	}
	if len(displayPath(`/a\xffb`)) != 3 || displayPath(`/a\xffb`)[1].Title != "byte 0xFF, not valid UTF-8" {
		t.Fatalf("%+v", displayPath(`/a\xffb`))
	}
	// The raw U+202E and its literal spelling must differ in the segments, not only in text.
	raw, lit := displayPath("\u202e"), displayPath(`\\u{202E}`)
	if !raw[0].Esc || lit[0].Esc {
		t.Fatalf("raw %+v literal %+v", raw, lit)
	}
}

// A signature has no agent encoding: a backslash is just a backslash.
func TestDisplaySignature(t *testing.T) {
	if got := join(displaySignature(`Win.Test\\x`)); got != `Win.Test\\x` {
		t.Fatalf("%q", got)
	}
	if got := join(displaySignature("a\u202eb")); got != `a[\u{202E}]b` {
		t.Fatalf("%q", got)
	}
}

func TestPathTruncated(t *testing.T) {
	if !pathTruncated(strings.Repeat("a", 4093)+"...") || pathTruncated("/short...") || pathTruncated(strings.Repeat("a", 5000)) {
		t.Fatal("pathTruncated")
	}
}

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{
		"/events": "/events", "/events?host=a&ack=all": "/events?host=a&ack=all", "/hosts/web01": "/hosts/web01", "/hosts/web01?x=1": "/hosts/web01?x=1",
		"": "/events", "//evil.example": "/events", "https://evil.example": "/events", "/eventsx": "/events", "/events/../admin": "/events",
		"/hosts/": "/events", "/hosts/A B": "/events", "/hosts/web01/x": "/events", "javascript:alert(1)": "/events",
	} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatCount(t *testing.T) {
	for in, want := range map[int64]string{0: "0", 999: "999", 1000: "1,000", 1234: "1,234", 1234567: "1,234,567", -1234: "-1,234"} {
		if got := formatCount(in); got != want {
			t.Errorf("%d: %q", in, got)
		}
	}
}
