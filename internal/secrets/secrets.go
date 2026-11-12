// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package secrets protects the server's secrets at rest: today the TOTP
// shared secrets, in M4 the webhook signing secrets, all with one key file.
//
// Design:
//   - The key file holds one or more 256-bit master keys. The first one seals;
//     every one of them opens, which is what makes rotation possible (add a new
//     key on top, re-seal, then remove the old line).
//   - A purpose-specific subkey is derived from the master key with HKDF-SHA256
//     (stdlib crypto/hkdf), so one purpose's ciphertexts are never valid for
//     another even if the AAD handling had a bug.
//   - Sealing is AES-256-GCM with a random 96-bit nonce. The additional
//     authenticated data binds the blob to its purpose and to the ids of the
//     row it belongs to (user id, session id), so a blob copied into another
//     user's row does not decrypt.
//
// Blob layout: 0x01 || key id (8 bytes) || nonce (12 bytes) || ciphertext+tag.
//
// Errors never contain key or plaintext bytes. The package does not read the
// clock and does not log.
package secrets

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// KeyBytes is the size of a master key.
	KeyBytes = 32
	// DefaultKeyPath is where the key file lives unless secret_key_file says otherwise.
	DefaultKeyPath = "/etc/clamfleet/server-secret.key"

	blobVersion = 1
	kidBytes    = 8
	nonceBytes  = 12
	// maxKeyFile bounds what is read: a key file is a few hundred bytes.
	maxKeyFile = 64 << 10
)

var (
	// ErrUnknownKey: the blob was sealed with a key that is not in the key file.
	ErrUnknownKey = errors.New("secret sealed with an unknown key")
	// ErrDecrypt: the blob is corrupt, or belongs to another purpose or row.
	ErrDecrypt = errors.New("secret cannot be decrypted")
)

type key struct {
	id     [kidBytes]byte
	master [KeyBytes]byte
}

// Keyring is the set of keys loaded from a key file. The zero value holds no
// key; use Parse or LoadFile. It is immutable and safe for concurrent use.
type Keyring struct{ keys []key }

// keyID is the first 8 bytes of SHA-256("clamfleet key id v1" || key): enough
// to pick the right key, and it reveals nothing usable about it.
func keyID(master []byte) (id [kidBytes]byte) {
	h := sha256.New()
	h.Write([]byte("clamfleet key id v1"))
	h.Write(master)
	copy(id[:], h.Sum(nil))
	return id
}

// KeyID is the printable id of a master key (16 hex characters).
func KeyID(master []byte) string {
	id := keyID(master)
	return hex.EncodeToString(id[:])
}

// GenerateKey returns a fresh random master key.
func GenerateKey() ([]byte, error) {
	b := make([]byte, KeyBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return b, nil
}

// EncodeKeyLine is the text a key file holds for one key: a comment with the
// key id, then the standard base64 of the key.
func EncodeKeyLine(master []byte) string {
	return "# key id " + KeyID(master) + "\n" + base64.StdEncoding.EncodeToString(master) + "\n"
}

// Parse reads the key file format: '#' comment lines and blank lines are
// ignored, every other line is the standard base64 of exactly 32 bytes. An
// empty file, a malformed line or a duplicate key is an error, so a damaged
// file never turns into "no encryption" or a silently different key.
func Parse(r io.Reader) (*Keyring, error) {
	var ring Keyring
	sc := bufio.NewScanner(io.LimitReader(r, maxKeyFile))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("key file line %d: not valid base64", n)
		}
		if len(raw) != KeyBytes {
			return nil, fmt.Errorf("key file line %d: a key is %d bytes, this one is %d", n, KeyBytes, len(raw))
		}
		k := key{id: keyID(raw)}
		copy(k.master[:], raw)
		for _, o := range ring.keys {
			if o.id == k.id {
				return nil, fmt.Errorf("key file line %d: the same key appears twice", n)
			}
		}
		ring.keys = append(ring.keys, k)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	if len(ring.keys) == 0 {
		return nil, errors.New("key file holds no key")
	}
	return &ring, nil
}

// LoadFile reads and checks the key file at path.
//
// Rule: the file must be a regular file (not a symlink: Lstat, open with
// O_NOFOLLOW, then Fstat and compare, so it cannot be swapped between the
// check and the read) that no "other" user can touch and no group can write:
// owner root and group clamfleet-server with 0640, or the server user with
// 0600. A missing file returns an error for which errors.Is(err, os.ErrNotExist)
// holds, so the caller can tell "absent" from "present and wrong".
func LoadFile(path string) (*Keyring, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("key file %s is not a regular file (symbolic links are refused)", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	if !os.SameFile(li, fi) || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("key file %s changed while it was being opened", path)
	}
	if perm := fi.Mode().Perm(); perm&0o027 != 0 {
		return nil, fmt.Errorf("key file %s has mode %04o: it must not be readable by others or writable by its group (use 0640 root:clamfleet-server or 0600)", path, perm)
	}
	ring, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("key file %s: %w", path, err)
	}
	return ring, nil
}

// Len is the number of keys.
func (k *Keyring) Len() int { return len(k.keys) }

// ActiveID is the printable id of the key that seals.
func (k *Keyring) ActiveID() string { return hex.EncodeToString(k.keys[0].id[:]) }

func purposeInfo(purpose string) string { return "clamfleet/" + purpose + "/v1" }

// aad binds a blob to its purpose and to the ids of its row.
func aad(purpose string, ids []uint64) []byte {
	b := []byte(purposeInfo(purpose))
	for _, id := range ids {
		b = binary.BigEndian.AppendUint64(b, id)
	}
	return b
}

func (k key) aead(purpose string) (cipher.AEAD, error) {
	sub, err := hkdf.Key(sha256.New, k.master[:], nil, purposeInfo(purpose), 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(sub)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// Seal encrypts plaintext with the active key for purpose ("totp", ...). ids
// are the row identifiers the blob is bound to (a user id, then a session id
// for a pending enrolment): Open must present the same ones.
func (k *Keyring) Seal(purpose string, plaintext []byte, ids ...uint64) ([]byte, error) {
	if len(k.keys) == 0 {
		return nil, errors.New("seal: empty keyring")
	}
	active := k.keys[0]
	g, err := active.aead(purpose)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	out := make([]byte, 0, 1+kidBytes+nonceBytes+len(plaintext)+g.Overhead())
	out = append(out, blobVersion)
	out = append(out, active.id[:]...)
	out = append(out, nonce...)
	return g.Seal(out, nonce, plaintext, aad(purpose, ids)), nil
}

// Open decrypts a blob made by Seal with the same purpose and ids. It returns
// ErrUnknownKey when no key of the ring made the blob and ErrDecrypt for
// anything else wrong with it.
func (k *Keyring) Open(purpose string, blob []byte, ids ...uint64) ([]byte, error) {
	if len(blob) < 1+kidBytes+nonceBytes || blob[0] != blobVersion {
		return nil, ErrDecrypt
	}
	var kid [kidBytes]byte
	copy(kid[:], blob[1:1+kidBytes])
	for _, c := range k.keys {
		if c.id != kid {
			continue
		}
		g, err := c.aead(purpose)
		if err != nil {
			return nil, ErrDecrypt
		}
		nonce := blob[1+kidBytes : 1+kidBytes+nonceBytes]
		pt, err := g.Open(nil, nonce, blob[1+kidBytes+nonceBytes:], aad(purpose, ids))
		if err != nil {
			return nil, ErrDecrypt
		}
		return pt, nil
	}
	return nil, ErrUnknownKey
}

// NeedsReseal reports whether blob was sealed with a key other than the
// active one (a malformed blob counts as needing none: Open reports it).
func (k *Keyring) NeedsReseal(blob []byte) bool {
	if len(blob) < 1+kidBytes || blob[0] != blobVersion {
		return false
	}
	return !bytes.Equal(blob[1:1+kidBytes], k.keys[0].id[:])
}
