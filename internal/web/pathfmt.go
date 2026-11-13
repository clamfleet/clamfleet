// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// pathfmt.go: how a detected file path (and a signature) is shown.
//
// A path is text chosen by whoever named the file, so it can be hostile:
// right-to-left overrides that make "invoice‮txt.exe" read as "invoicexe.txt",
// zero-width characters, U+2028 line separators that break a table row apart.
// displayPath therefore never prints an invisible or direction-changing
// character as itself: it shows it as a visible escape element (a styled <span>
// with the name in its title), so the reader sees what is really there.
//
// The stored path carries the AGENT's encoding (docs/api.md): a backslash is
// doubled and a byte that is not UTF-8 is \xNN. displayPath undoes the
// backslash doubling (so a file named a\b shows as a\b) and renders \xNN as an
// escape element. Escapes are ELEMENTS and literal text is TEXT: a file whose
// name literally contains the characters \u{202E} shows them as plain text,
// while a real U+202E shows as a styled .esc element, so the two can always be
// told apart. The stylesheet is a static file (the CSP forbids inline style).
//
// Dependencies: the standard library only. Everything returned is plain data;
// html/template escapes it on output (template.HTML is never used).

package web

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// seg is one piece of a displayed string: literal text, or an escape element.
type seg struct {
	Text  string
	Esc   bool
	Title string // the element's explanation, for escapes
}

// truncatedAtLeast: the agent cuts a path to at most 4096 bytes ending in "...",
// on a unit boundary (so up to 4 bytes short). A path that ends in "..." and is
// at least this long was cut by the agent.
const truncatedAtLeast = 4090

// displayPath splits a stored path into segments for display.
func displayPath(stored string) []seg { return display(stored, true) }

// displaySignature applies the same escaping to a signature (which has no agent
// encoding: backslashes are plain).
func displaySignature(stored string) []seg { return display(stored, false) }

// pathTruncated reports whether the agent cut this path (it ends in "...").
func pathTruncated(stored string) bool {
	return len(stored) >= truncatedAtLeast && strings.HasSuffix(stored, "...")
}

func display(s string, agentEncoding bool) []seg {
	var out []seg
	var plain strings.Builder
	flush := func() {
		if plain.Len() > 0 {
			out = append(out, seg{Text: plain.String()})
			plain.Reset()
		}
	}
	esc := func(text, title string) {
		flush()
		out = append(out, seg{Text: text, Esc: true, Title: title})
	}
	for i := 0; i < len(s); {
		if agentEncoding && s[i] == '\\' {
			switch {
			case i+1 < len(s) && s[i+1] == '\\':
				plain.WriteByte('\\') // the agent doubled it
				i += 2
				continue
			case i+3 < len(s) && s[i+1] == 'x' && isLowerHex(s[i+2]) && isLowerHex(s[i+3]):
				esc(s[i:i+4], "byte 0x"+strings.ToUpper(s[i+2:i+4])+", not valid UTF-8")
				i += 4
				continue
			}
			// A lone backslash from a client that does not use the encoding.
			plain.WriteByte('\\')
			i++
			continue
		}
		r, w := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && w == 1 {
			esc(fmt.Sprintf(`\x%02x`, s[i]), fmt.Sprintf("byte 0x%02X, not valid UTF-8", s[i]))
			i++
			continue
		}
		if title, hidden := hiddenRune(r); hidden {
			esc(fmt.Sprintf(`\u{%04X}`, r), title)
		} else {
			plain.WriteString(s[i : i+w])
		}
		i += w
	}
	flush()
	return out
}

func isLowerHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }

// hiddenRune says whether r must be shown as an escape, and its explanation:
// every control (Cc), format (Cf), line and paragraph separator (Zl, Zp) and
// private-use (Co) character, the variation selectors, the other default-ignorable
// code points, and the characters that render as blanks (U+034F, U+115F, U+1160,
// U+3164, U+FFA0).
func hiddenRune(r rune) (string, bool) {
	if name, ok := runeNames[r]; ok {
		return fmt.Sprintf("U+%04X %s", r, name), true
	}
	switch {
	case unicode.Is(unicode.Cc, r):
		return fmt.Sprintf("U+%04X control character", r), true
	case unicode.Is(unicode.Cf, r):
		return fmt.Sprintf("U+%04X format character (invisible)", r), true
	case unicode.Is(unicode.Zl, r):
		return fmt.Sprintf("U+%04X line separator", r), true
	case unicode.Is(unicode.Zp, r):
		return fmt.Sprintf("U+%04X paragraph separator", r), true
	case unicode.Is(unicode.Co, r):
		return fmt.Sprintf("U+%04X private use character", r), true
	case unicode.Is(unicode.Variation_Selector, r):
		return fmt.Sprintf("U+%04X variation selector (invisible)", r), true
	case unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r):
		return fmt.Sprintf("U+%04X default-ignorable character (invisible)", r), true
	}
	return "", false
}

// runeNames explains the characters people actually abuse; everything else
// that is hidden gets its category name.
var runeNames = map[rune]string{
	0x00AD: "SOFT HYPHEN (invisible)", 0x034F: "COMBINING GRAPHEME JOINER (invisible)", 0x061C: "ARABIC LETTER MARK (invisible)",
	0x115F: "HANGUL CHOSEONG FILLER (blank)", 0x1160: "HANGUL JUNGSEONG FILLER (blank)", 0x180E: "MONGOLIAN VOWEL SEPARATOR (invisible)",
	0x200B: "ZERO WIDTH SPACE", 0x200C: "ZERO WIDTH NON-JOINER", 0x200D: "ZERO WIDTH JOINER",
	0x200E: "LEFT-TO-RIGHT MARK", 0x200F: "RIGHT-TO-LEFT MARK",
	0x2028: "LINE SEPARATOR", 0x2029: "PARAGRAPH SEPARATOR",
	0x202A: "LEFT-TO-RIGHT EMBEDDING", 0x202B: "RIGHT-TO-LEFT EMBEDDING", 0x202C: "POP DIRECTIONAL FORMATTING",
	0x202D: "LEFT-TO-RIGHT OVERRIDE", 0x202E: "RIGHT-TO-LEFT OVERRIDE",
	0x2060: "WORD JOINER", 0x2066: "LEFT-TO-RIGHT ISOLATE", 0x2067: "RIGHT-TO-LEFT ISOLATE",
	0x2068: "FIRST STRONG ISOLATE", 0x2069: "POP DIRECTIONAL ISOLATE",
	0x3164: "HANGUL FILLER (blank)", 0xFEFF: "ZERO WIDTH NO-BREAK SPACE / BOM", 0xFFA0: "HALFWIDTH HANGUL FILLER (blank)",
}
