// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// totp.go: RFC 6238 time-based one-time passwords (on RFC 4226 HOTP) and the
// recovery codes that stand in for them.
//
// This is implemented here, not imported: it is about a hundred lines on the
// standard library, pinned by the RFC test vectors, and a dependency for it
// would be a larger attack surface than the code it saves. Parameters are the
// ones every authenticator app defaults to and the key URI states them:
// HMAC-SHA1 (RFC 6238 and every app use it; it is never used as a plain
// hash here), 6 digits, 30 s step. They are not configurable.
//
// Everything that depends on time takes the injected clock's value as an
// argument; nothing here reads the wall clock.
package webauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// TOTPDigits and TOTPPeriod are fixed (see the file comment).
	TOTPDigits = 6
	TOTPPeriod = 30 * time.Second
	// totpSecretBytes: 160 bits, the RFC 4226 section 4 recommendation.
	totpSecretBytes = 20
	// NoStep is the lastStep argument of Match for "no code accepted yet".
	NoStep int64 = -1
	// TOTPIssuer labels the account in the authenticator app.
	TOTPIssuer = "ClamFleet"

	// RecoveryCodeCount codes are issued at a time; each is 80 bits.
	RecoveryCodeCount = 10
	recoveryBytes     = 10
	recoveryChars     = 16
)

// secretEnc is base32 without padding, upper case: what apps expect typed in.
var secretEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// recoveryEnc is lower-case base32 for recovery codes (RFC 4648 alphabet).
var recoveryEnc = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a fresh random shared secret.
func GenerateTOTPSecret() ([]byte, error) {
	b := make([]byte, totpSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate totp secret: %w", err)
	}
	return b, nil
}

// EncodeTOTPSecret is the base32 text of a secret (no padding, upper case).
func EncodeTOTPSecret(secret []byte) string { return secretEnc.EncodeToString(secret) }

// FormatTOTPSecret is EncodeTOTPSecret in groups of four for reading and typing.
func FormatTOTPSecret(secret []byte) string {
	s := EncodeTOTPSecret(secret)
	var parts []string
	for len(s) > 0 {
		n := min(4, len(s))
		parts = append(parts, s[:n])
		s = s[n:]
	}
	return strings.Join(parts, " ")
}

// hotp is RFC 4226: HMAC-SHA1 over the 8-byte big-endian counter, dynamic
// truncation (offset = low nibble of the last byte, 31-bit mask so the result
// is never negative), modulo 10^digits, zero padded. digits is a parameter only
// so the 8-digit RFC 6238 test vectors can be checked exactly; production is 6.
func hotp(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// TOTPStep is the RFC 6238 time step of t (floor of unix time / 30 s).
func TOTPStep(t time.Time) int64 { return t.Unix() / int64(TOTPPeriod/time.Second) }

// NormalizeTOTPCode strips spaces and reports whether what is left is exactly
// 6 ASCII digits. Unicode digits are refused on purpose: the comparison is on
// bytes, and a lookalike must never be "normalised" into a match.
func NormalizeTOTPCode(s string) (string, bool) {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) != TOTPDigits {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return "", false
		}
	}
	return s, true
}

// MatchTOTP checks a submitted code against steps now-1, now and now+1 (the
// window of RFC 6238 section 5.2: clock drift and typing time) and returns the
// step that matched. A step at or below lastStep is never accepted, so a code
// that was used once cannot be replayed inside its window (pass NoStep for
// "none yet"). The three candidates are always all computed and compared in
// constant time; when several match, the highest step wins.
//
// This function only decides; recording the step is the store's
// compare-and-swap, which is what makes the replay guard hold under concurrency.
func MatchTOTP(secret []byte, code string, now time.Time, lastStep int64) (step int64, ok bool) {
	code, valid := NormalizeTOTPCode(code)
	if !valid {
		return 0, false
	}
	cur := TOTPStep(now)
	for _, s := range []int64{cur - 1, cur, cur + 1} {
		if s < 0 {
			continue
		}
		match := subtle.ConstantTimeCompare([]byte(hotp(secret, uint64(s), TOTPDigits)), []byte(code)) == 1
		if match && s > lastStep && (!ok || s > step) {
			step, ok = s, true
		}
	}
	return step, ok
}

// TOTPKeyURI is the otpauth:// URI authenticator apps import. Issuer and
// account are escaped strictly: a normalised email may still hold ':', '?',
// '#', '%', '/' or '+', each of which would change the meaning of the URI.
func TOTPKeyURI(email string, secret []byte) string {
	label := uriEscape(TOTPIssuer) + ":" + uriEscape(email)
	q := url.Values{}
	q.Set("secret", EncodeTOTPSecret(secret))
	q.Set("issuer", TOTPIssuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// uriEscape percent-encodes everything but unreserved characters and '@'.
// url.PathEscape is not enough: it leaves ':' and '+' alone.
func uriEscape(s string) string {
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "+", "%20") // QueryEscape's space; a literal '+' is already %2B
	return strings.ReplaceAll(e, "%40", "@")
}

// GenerateRecoveryCodes returns n fresh recovery codes in display form
// ("abcd-efgh-ijkl-mnop"), 80 bits each.
func GenerateRecoveryCodes(n int) ([]string, error) {
	out := make([]string, 0, n)
	seen := map[string]bool{}
	for len(out) < n {
		b := make([]byte, recoveryBytes)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		raw := recoveryEnc.EncodeToString(b) // exactly 16 characters for 10 bytes
		if seen[raw] {
			continue
		}
		seen[raw] = true
		out = append(out, raw[0:4]+"-"+raw[4:8]+"-"+raw[8:12]+"-"+raw[12:16])
	}
	return out, nil
}

// ErrBadRecoveryCode: not shaped like a recovery code. Never contains the input.
var ErrBadRecoveryCode = errors.New("not a recovery code")

// NormalizeRecoveryCode lower-cases and strips dashes and spaces, then checks
// for exactly 16 characters of the code alphabet, so garbage is refused before
// it is hashed or looked up.
func NormalizeRecoveryCode(s string) (string, error) {
	s = strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(s))
	if len(s) != recoveryChars {
		return "", ErrBadRecoveryCode
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return "", ErrBadRecoveryCode
		}
	}
	return s, nil
}

// HashRecoveryCode is the storage form of a normalised code. Unpeppered
// SHA-256 is deliberate: at 80 bits of entropy offline guessing is infeasible,
// and a hash that does not depend on the server key means the codes still
// work if that key is lost (they are the way back in).
func HashRecoveryCode(normalised string) []byte {
	h := sha256.Sum256([]byte(normalised))
	return h[:]
}
