// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package agentauth authenticates agents (hosts) to the ingest API.
//
// The package name is deliberate: web-console users arrive later and must never
// share a type, table or package with agent credentials. An agent credential
// yields an Identity that is a host and nothing else; a user principal will be
// a different type in a different package, so the type system keeps a session
// away from /v1/report and an agent token away from the UI routes.
//
// token.go: the token format. A token is "cfa_" + base64url (no padding) of 32
// random bytes, 47 characters. The prefix marks it as an *agent* credential
// (greppable, matches secret-scanning rules); future user API tokens get
// another prefix (e.g. "cfu_") and are rejected here before any lookup.
//
// Storage rule: the server keeps only SHA-256 of the whole token string, in a
// unique-indexed column, and looks it up by equality. No pepper and no slow KDF:
// the secret has 256 bits of entropy, so a leaked hash is not reversible, and
// an indexed lookup rules out per-row password hashing.
package agentauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	// Prefix starts every agent token.
	Prefix = "cfa_"
	// secretBytes is the entropy of a token: 256 bits.
	secretBytes = 32
	// tokenLen is the length of a well-formed token: 4 + 43.
	tokenLen = len(Prefix) + 43
)

// enc is strict: a non-canonical encoding (non-zero trailing bits) is
// rejected, so one secret has exactly one valid spelling.
var enc = base64.RawURLEncoding.Strict()

// Generate returns a new random token and its storage hash. The token is shown
// to the operator once and never stored; only hash goes to the database.
// Error: the system random source failed.
func Generate() (token string, hash []byte, err error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}
	token = Prefix + enc.EncodeToString(b)
	return token, Hash(token), nil
}

// Hash returns the storage hash of a token: SHA-256 of the whole string
// (prefix included), 32 bytes.
func Hash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// ErrMalformed is returned by Parse for anything that is not a well-formed
// agent token. It never contains the input: a wrong credential pasted into the
// wrong place must not travel into logs.
var ErrMalformed = errors.New("malformed agent token")

// Parse checks the format only (prefix, length, strict base64url of 32
// bytes). It is what lets the authenticator answer 401 for garbage without
// touching the database.
func Parse(token string) error {
	if len(token) != tokenLen || token[:len(Prefix)] != Prefix {
		return ErrMalformed
	}
	b, err := enc.DecodeString(token[len(Prefix):])
	if err != nil || len(b) != secretBytes {
		return ErrMalformed
	}
	return nil
}
