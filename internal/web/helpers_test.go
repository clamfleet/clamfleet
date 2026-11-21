// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package web_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"testing"

	"github.com/clamfleet/clamfleet/internal/agentauth"
	"golang.org/x/crypto/argon2"

	_ "modernc.org/sqlite"
)

func openRaw(path string) (*sql.DB, error) { return sql.Open("sqlite", "file:"+path+"?mode=ro") }

// registerHost registers a host directly in the store and returns its agent token.
func registerHost(t *testing.T, e *env, name string) string {
	t.Helper()
	tok, hash, err := agentauth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CreateHost(context.Background(), name, hash, e.clock(), cliAudit); err != nil {
		t.Fatal(err)
	}
	return tok
}

// weakHash returns a valid PHC hash of pw made with older, lighter parameters.
func weakHash(t *testing.T, pw string) string {
	t.Helper()
	salt := make([]byte, 16)
	key := argon2.IDKey([]byte(pw), salt, 1, 8192, 1, 32)
	return "$argon2id$v=19$m=8192,t=1,p=1$" + b64(salt) + "$" + b64(key)
}

func b64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }
