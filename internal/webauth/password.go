// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package webauth authenticates people to the web console: password hashing,
// cookie sessions, CSRF protection and the role middleware.
//
// It is deliberately separate from internal/agentauth and shares no type with
// it: an agent credential yields a host, a session yields a user, and the type
// system plus distinct token prefixes (cfa_ / cfs_) keep one from being
// accepted where the other belongs.
//
// password.go: argon2id hashing in the PHC string format, with a cap on
// concurrent hashes and a dummy verification for unknown accounts.
// Dependency: golang.org/x/crypto/argon2 (approved for this purpose).
package webauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Current argon2id parameters: the first set OWASP recommends (m=19 MiB, t=2,
// p=1). They are stored inside every hash, so raising them later needs no
// migration: NeedsRehash notices old hashes and login replaces them.
const (
	argonMemory  uint32 = 19456 // KiB
	argonTime    uint32 = 2
	argonThreads uint8  = 1
	saltLen             = 16
	keyLen              = 32

	// MaxConcurrentHashes bounds the memory argon2 can take at once:
	// 4 x 19 MiB, about 76 MiB, on a server that targets 512 MB. Without the
	// cap a flood of logins is a memory-exhaustion attack.
	MaxConcurrentHashes = 4

	// Upper bounds when PARSING a stored hash. A tampered row must not be able
	// to make the server allocate or compute without bound.
	// 64 MiB: every OWASP argon2id profile is at most 46 MiB (m=47104), and up
	// to MaxConcurrentHashes (4) verifications run at once, so a tampered hash
	// can cost at most 256 MiB, not 4 GiB on a 512 MB server.
	maxParseMemory  = 64 << 10 // KiB
	maxParseTime    = 10
	maxParseThreads = 16
	maxParseBytes   = 64 // salt and key

	// Password policy (NIST SP 800-63B: length over composition rules).
	MinPasswordLen = 15
	MaxPasswordLen = 256
)

var (
	// ErrBadHash: the stored string is not a well-formed argon2id PHC hash or
	// its parameters are out of bounds. Never contains the hash.
	ErrBadHash = errors.New("malformed password hash")
	// ErrPolicy wraps a violation of the password policy.
	ErrPolicy = errors.New("password policy")
)

// phcEnc is the standard base64 without padding that PHC strings use.
var phcEnc = base64.RawStdEncoding.Strict()

// CheckPolicy enforces the password policy: 15 to 256 bytes, valid UTF-8, no
// NUL. No composition rules and no external breach list.
func CheckPolicy(pw string) error {
	switch {
	case len(pw) < MinPasswordLen:
		return fmt.Errorf("%w: use at least %d characters", ErrPolicy, MinPasswordLen)
	case len(pw) > MaxPasswordLen:
		return fmt.Errorf("%w: use at most %d bytes", ErrPolicy, MaxPasswordLen)
	case !utf8.ValidString(pw) || strings.ContainsRune(pw, 0):
		return fmt.Errorf("%w: the password must be valid text without NUL characters", ErrPolicy)
	}
	return nil
}

// GeneratePassword returns a random one-time password of 24 base64url
// characters (144 bits), which also satisfies the policy.
func GeneratePassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// deriveFunc is argon2.IDKey; tests replace it to count and block calls.
type deriveFunc func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte

// Hasher hashes and verifies passwords, at most MaxConcurrentHashes at a time.
type Hasher struct {
	sem    chan struct{}
	derive deriveFunc
	dummy  string // a valid PHC hash nobody knows the password of
}

// NewHasher returns a Hasher with the production parameters. It does no
// hashing itself.
func NewHasher() *Hasher { return newHasher(argon2.IDKey) }

func newHasher(d deriveFunc) *Hasher {
	// The dummy has the CURRENT parameters, so verifying against it costs what a
	// real verification costs, and the key is arbitrary: no password produces it.
	dummy := encodePHC(argonMemory, argonTime, argonThreads, make([]byte, saltLen), make([]byte, keyLen))
	return &Hasher{sem: make(chan struct{}, MaxConcurrentHashes), derive: d, dummy: dummy}
}

// acquire takes a slot or gives up with the request context.
func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

// Hash returns the PHC string of password with a fresh random salt. It waits
// for a free slot and returns ctx.Err() if the context ends first.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	key := h.derive([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLen)
	return encodePHC(argonMemory, argonTime, argonThreads, salt, key), nil
}

// Verify checks password against a stored PHC hash. needsRehash is true when
// the password is right but the stored parameters differ from the current
// ones. A malformed hash is ErrBadHash (and is rejected before any memory is
// allocated); a wrong password is ok=false with a nil error.
func (h *Hasher) Verify(ctx context.Context, password, phc string) (ok, needsRehash bool, err error) {
	m, t, p, salt, want, err := decodePHC(phc)
	if err != nil {
		return false, false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	defer h.release()
	got := h.derive([]byte(password), salt, t, m, p, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	return true, m != argonMemory || t != argonTime || p != argonThreads || len(salt) != saltLen || len(want) != keyLen, nil
}

// VerifyDummy spends one verification's time and memory on a hash nobody
// knows. The login handler calls it for an unknown or disabled account so
// that response time does not reveal whether the email exists. It always
// returns ok=false.
func (h *Hasher) VerifyDummy(ctx context.Context, password string) error {
	_, _, err := h.Verify(ctx, password, h.dummy)
	return err
}

func encodePHC(m, t uint32, p uint8, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, m, t, p, phcEnc.EncodeToString(salt), phcEnc.EncodeToString(key))
}

// decodePHC parses "$argon2id$v=19$m=..,t=..,p=..$salt$key" strictly: only
// argon2id, only version 19, parameters inside the parse bounds.
func decodePHC(s string) (m, t uint32, p uint8, salt, key []byte, err error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return 0, 0, 0, nil, nil, ErrBadHash
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return 0, 0, 0, nil, nil, ErrBadHash
	}
	var vals [3]uint64
	for i, name := range []string{"m=", "t=", "p="} {
		v, ok := strings.CutPrefix(params[i], name)
		if !ok {
			return 0, 0, 0, nil, nil, ErrBadHash
		}
		n, perr := strconv.ParseUint(v, 10, 32)
		if perr != nil {
			return 0, 0, 0, nil, nil, ErrBadHash
		}
		vals[i] = n
	}
	if vals[0] < 8 || vals[0] > maxParseMemory || vals[1] < 1 || vals[1] > maxParseTime || vals[2] < 1 || vals[2] > maxParseThreads {
		return 0, 0, 0, nil, nil, ErrBadHash
	}
	// Check the encoded lengths before decoding, so a huge string allocates nothing.
	if len(parts[4]) > phcEnc.EncodedLen(maxParseBytes) || len(parts[5]) > phcEnc.EncodedLen(maxParseBytes) {
		return 0, 0, 0, nil, nil, ErrBadHash
	}
	salt, serr := phcEnc.DecodeString(parts[4])
	key, kerr := phcEnc.DecodeString(parts[5])
	if serr != nil || kerr != nil || len(salt) < 8 || len(key) < 16 {
		return 0, 0, 0, nil, nil, ErrBadHash
	}
	return uint32(vals[0]), uint32(vals[1]), uint8(vals[2]), salt, key, nil
}
