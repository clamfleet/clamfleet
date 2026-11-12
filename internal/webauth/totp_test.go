// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package webauth

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// rfcSecret is the ASCII secret of RFC 4226 Appendix D and RFC 6238 Appendix B (SHA-1).
var rfcSecret = []byte("12345678901234567890")

// RFC 4226 Appendix D, "Test values": HOTP for counters 0-9.
func TestHOTPRFC4226Vectors(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for c, w := range want {
		if got := hotp(rfcSecret, uint64(c), 6); got != w {
			t.Errorf("counter %d: %s, want %s", c, got, w)
		}
	}
}

// RFC 6238 Appendix B, SHA-1 column, 8 digits. The 6-digit form is the last six.
func TestTOTPRFC6238Vectors(t *testing.T) {
	for _, v := range []struct {
		unix int64
		code string
	}{
		{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"},
		{1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"},
	} {
		step := TOTPStep(time.Unix(v.unix, 0))
		if got := hotp(rfcSecret, uint64(step), 8); got != v.code {
			t.Errorf("T=%d: %s, want %s", v.unix, got, v.code)
		}
		if got := hotp(rfcSecret, uint64(step), 6); got != v.code[2:] {
			t.Errorf("T=%d (6 digits): %s, want %s", v.unix, got, v.code[2:])
		}
	}
}

func TestTOTPStepBoundaries(t *testing.T) {
	for unix, want := range map[int64]int64{0: 0, 29: 0, 30: 1, 59: 1, 60: 2} {
		if got := TOTPStep(time.Unix(unix, 0)); got != want {
			t.Errorf("unix %d: step %d, want %d", unix, got, want)
		}
	}
}

// Far from the real date, so a time.Now() in the code under test would be visible.
var tOld = time.Date(2031, 3, 4, 12, 0, 10, 0, time.UTC)

func codeAt(step int64) string { return hotp(rfcSecret, uint64(step), 6) }

func TestMatchTOTPWindow(t *testing.T) {
	cur := TOTPStep(tOld)
	for _, c := range []struct {
		off int64
		ok  bool
	}{{-2, false}, {-1, true}, {0, true}, {1, true}, {2, false}} {
		step, ok := MatchTOTP(rfcSecret, codeAt(cur+c.off), tOld, NoStep)
		if ok != c.ok || ok && step != cur+c.off {
			t.Errorf("offset %d: step %d ok=%v, want ok=%v", c.off, step, ok, c.ok)
		}
	}
}

func TestMatchTOTPReplayGuard(t *testing.T) {
	cur := TOTPStep(tOld)
	for _, c := range []struct {
		name string
		code int64
		last int64
		ok   bool
	}{
		{"equal to last step", cur, cur, false},
		{"older than last step", cur - 1, cur, false},
		{"newer than last step", cur + 1, cur, true},
		{"last step is far in the past", cur, cur - 100, true},
	} {
		if _, ok := MatchTOTP(rfcSecret, codeAt(c.code), tOld, c.last); ok != c.ok {
			t.Errorf("%s: ok=%v, want %v", c.name, ok, c.ok)
		}
	}
}

// Two steps can carry the same code (1 in a million); then the higher step must
// win, so the guard moves as far forward as the clock allows. Found by search
// over a fixed secret, so the test is deterministic.
func TestMatchTOTPPicksTheHighestOfSeveralMatches(t *testing.T) {
	for s := int64(1_000_000); s < 3_000_000; s++ {
		if codeAt(s) == codeAt(s+1) {
			// now is in step s, so the window holds s-1, s, s+1.
			now := time.Unix(s*30, 0)
			if step, ok := MatchTOTP(rfcSecret, codeAt(s), now, NoStep); !ok || step != s+1 {
				t.Fatalf("step %d ok=%v, want %d", step, ok, s+1)
			}
			return
		}
	}
	t.Fatal("no adjacent equal codes in the search range: widen it") // never a skip: a test that skips cannot fail
}

func TestNormalizeTOTPCode(t *testing.T) {
	for in, want := range map[string]bool{
		"123456": true, "123 456": true, " 123456 ": true,
		"12345": false, "1234567": false, "12345a": false, "": false,
		"١٢٣٤٥٦": false, // Arabic-Indic digits: six runes, but not ASCII
		"12-456": false, "123456\n": false,
	} {
		if _, ok := NormalizeTOTPCode(in); ok != want {
			t.Errorf("%q: %v, want %v", in, ok, want)
		}
	}
	if got, _ := NormalizeTOTPCode("123 456"); got != "123456" {
		t.Errorf("spaces not stripped: %q", got)
	}
}

func TestTOTPSecretFormat(t *testing.T) {
	s, err := GenerateTOTPSecret()
	if err != nil || len(s) != 20 {
		t.Fatalf("secret: %v %d bytes", err, len(s))
	}
	if e := EncodeTOTPSecret(s); len(e) != 32 || strings.Contains(e, "=") || e != strings.ToUpper(e) {
		t.Errorf("base32 %q: want 32 upper-case characters without padding", e)
	}
	g := FormatTOTPSecret(s)
	if strings.ReplaceAll(g, " ", "") != EncodeTOTPSecret(s) || len(strings.Fields(g)) != 8 {
		t.Errorf("grouping %q", g)
	}
}

func TestTOTPKeyURIEscapesTheAccount(t *testing.T) {
	for _, email := range []string{"ann@example.com", "a+b@example.com", "a:b@example.com", "a?b#c%d/e@example.com", "x y@example.com"} {
		raw := TOTPKeyURI(email, rfcSecret)
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if u.Scheme != "otpauth" || u.Host != "totp" || u.Fragment != "" {
			t.Errorf("%q: scheme %q host %q fragment %q", email, u.Scheme, u.Host, u.Fragment)
		}
		if got, want := strings.TrimPrefix(u.Path, "/"), "ClamFleet:"+email; got != want {
			t.Errorf("label %q, want %q", got, want)
		}
		q := u.Query()
		if q.Get("secret") != EncodeTOTPSecret(rfcSecret) || q.Get("issuer") != "ClamFleet" ||
			q.Get("algorithm") != "SHA1" || q.Get("digits") != "6" || q.Get("period") != "30" || len(q) != 5 {
			t.Errorf("%q: query %v", email, q)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(RecoveryCodeCount)
	if err != nil || len(codes) != 10 {
		t.Fatalf("%v %d", err, len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 19 || c[4] != '-' || c[9] != '-' || c[14] != '-' {
			t.Errorf("display form %q", c)
		}
		n, err := NormalizeRecoveryCode(c)
		if err != nil || len(n) != 16 {
			t.Errorf("%q does not normalise: %v", c, err)
		}
		if seen[n] {
			t.Errorf("duplicate code %q", c)
		}
		seen[n] = true
		if h := HashRecoveryCode(n); len(h) != 32 {
			t.Errorf("hash length %d", len(h))
		}
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	for _, c := range []struct {
		in string
		ok bool
	}{
		{"abcd-efgh-ijkl-mnop", true}, {"ABCD EFGH IJKL MNOP", true}, {"abcdefghijklmnop", true},
		{"abcd-efgh-ijkl-mno", false}, {"abcd-efgh-ijkl-mnopq", false},
		{"abcd-efgh-ijkl-mn01", false}, // 0 and 1 are not in the base32 alphabet
		{"abcd-efgh-ijkl-mn!p", false}, {"", false}, {"123456", false},
	} {
		got, err := NormalizeRecoveryCode(c.in)
		if (err == nil) != c.ok {
			t.Errorf("%q: err=%v, want ok=%v", c.in, err, c.ok)
		}
		if c.ok && got != strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(c.in)) {
			t.Errorf("%q normalised to %q", c.in, got)
		}
	}
	if string(HashRecoveryCode("abcdefghijklmnop")) == string(HashRecoveryCode("abcdefghijklmnoq")) {
		t.Error("different codes hash equal")
	}
}
