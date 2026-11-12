// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package web_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/binary"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/secrets"
	"github.com/clamfleet/clamfleet/internal/server"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

// testCode is an independent second implementation of RFC 6238 (HMAC-SHA1, 6
// digits, 30 s): the tests do not use the code under test to make their codes.
func testCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[19] & 0x0f
	n := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", n%1_000_000)
}

func stepAt(t time.Time) int64 { return t.Unix() / 30 }

// testRing writes a real key file (mode 0600) and loads it, as the server does.
func testRing(t *testing.T) *secrets.Keyring {
	t.Helper()
	k, err := secrets.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(p, []byte(secrets.EncodeKeyLine(k)), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := secrets.LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func withKeys(r *secrets.Keyring) opt { return func(d *server.Deps) { d.Keys = r } }

// totpUser is a user with TOTP enabled.
type totpUser struct {
	store.User
	secret []byte
	codes  []string // recovery codes in display form
}

// addTOTPUser creates a user with an enrolled authenticator and 10 recovery
// codes, sealed with ring. The last accepted step is 10 steps before the clock,
// so the code of the current step is fresh.
func (e *env) addTOTPUser(ring *secrets.Keyring, email, role, password string) totpUser {
	e.t.Helper()
	u := e.addUser(email, role, password, false)
	secret, err := webauth.GenerateTOTPSecret()
	if err != nil {
		e.t.Fatal(err)
	}
	sealed, err := ring.Seal(secrets.PurposeTOTP, secret, uint64(u.ID))
	if err != nil {
		e.t.Fatal(err)
	}
	codes, err := webauth.GenerateRecoveryCodes(webauth.RecoveryCodeCount)
	if err != nil {
		e.t.Fatal(err)
	}
	var hashes [][]byte
	for _, c := range codes {
		n, _ := webauth.NormalizeRecoveryCode(c)
		hashes = append(hashes, webauth.HashRecoveryCode(n))
	}
	err = e.st.EnableTOTP(context.Background(), store.EnableTOTP{
		UserID: u.ID, ExpectedVersion: u.AuthVersion, Sealed: sealed, Step: stepAt(e.clock()) - 10, RecoveryHashes: hashes,
	}, e.clock(), cliAudit)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err = e.st.UserByEmail(context.Background(), email)
	if err != nil {
		e.t.Fatal(err)
	}
	return totpUser{User: u, secret: secret, codes: codes}
}

// wrongCode returns a 6-digit code that is not valid for any step of the window.
func wrongCode(secret []byte, now time.Time) string {
	s := stepAt(now)
	for _, c := range []string{"000000", "111111", "222222", "333333"} {
		bad := true
		for d := int64(-3); d <= 3; d++ {
			bad = bad && testCode(secret, s+d) != c
		}
		if bad {
			return c
		}
	}
	panic("no wrong code found")
}

// exec runs a write statement on the test database, for setting up states the
// public API cannot reach (a failure count near the lock).
func (e *env) exec(query string, args ...any) {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+e.dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		e.t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(query, args...); err != nil {
		e.t.Fatal(err)
	}
}

// cookie returns the jar's cookie whose name ends with suffix, or nil.
func (e *env) cookie(b *browser, suffix string) string {
	u, _ := url.Parse(e.srv.URL)
	for _, c := range b.c.Jar.Cookies(u) {
		if strings.HasSuffix(c.Name, suffix) {
			return c.Value
		}
	}
	return ""
}

// another starts a second server on the same store, with fresh throttles: a restart.
func (e *env) another(opts ...opt) *env {
	e.t.Helper()
	d := server.Deps{Store: e.st, Now: e.clock, Log: e.log, Hasher: e.hasher, Version: "9.9.9-test"}
	for _, o := range opts {
		o(&d)
	}
	e2 := &env{t: e.t, st: e.st, dbPath: e.dbPath, logs: e.logs, hasher: e.hasher, log: e.log, parent: e}
	e2.srv = httptest.NewTLSServer(server.NewHandler(d))
	e.t.Cleanup(e2.srv.Close)
	return e2
}

// passwordStep runs the password step and returns the browser holding the challenge.
func (e *env) passwordStep(email, password string) (*browser, page) {
	e.t.Helper()
	b := e.browser()
	return b, b.post("/login", url.Values{"email": {email}, "password": {password}})
}

func mustURL(s string) *url.URL { u, _ := url.Parse(s); return u }

func itoa(n int) string { return fmt.Sprint(n) }

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// Include the write-ahead log: recent rows may live only there.
	if w, err := os.ReadFile(p + "-wal"); err == nil {
		b = append(b, w...)
	}
	return string(b)
}

func hashOf(t *testing.T, pw string) string {
	t.Helper()
	h, err := webauth.NewHasher().Hash(context.Background(), pw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func webauthSecretText(secret []byte) string    { return webauth.EncodeTOTPSecret(secret) }
func webauthSecretGrouped(secret []byte) string { return webauth.FormatTOTPSecret(secret) }

// auditDump is every audit row's action, target and detail as text.
func auditDump(t *testing.T, e *env) string {
	t.Helper()
	raw, err := openRaw(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rows, err := raw.Query(`SELECT action || ' ' || actor || ' ' || target || ' ' || coalesce(detail, '') FROM audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var sb strings.Builder
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		sb.WriteString(s + "\n")
	}
	return sb.String()
}
