// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/secrets"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
	"github.com/clamfleet/clamfleet/internal/testtls"
)

var testAudit = store.Audit{Kind: store.ActorCLI, Actor: "test"}

// writeKeyFile writes a key file made of the given keys (first = active) with mode.
func writeKeyFile(t *testing.T, mode os.FileMode, keys ...[]byte) string {
	t.Helper()
	var text string
	for _, k := range keys {
		text += secrets.EncodeKeyLine(k)
	}
	p := filepath.Join(t.TempDir(), "server-secret.key")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func newKey(t *testing.T) []byte {
	t.Helper()
	k, err := secrets.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// seedTOTPUser creates a user with TOTP enabled whose secret is sealed with ring.
func seedTOTPUser(t *testing.T, db, email string, ring *secrets.Keyring) {
	t.Helper()
	ctx := context.Background()
	st, err := sqlite.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	u, err := st.CreateUser(ctx, store.NewUser{Email: email, Role: "viewer", PasswordHash: "h"}, time.Now(), testAudit)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := ring.Seal(secrets.PurposeTOTP, []byte("12345678901234567890"), uint64(u.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnableTOTP(ctx, store.EnableTOTP{UserID: u.ID, ExpectedVersion: u.AuthVersion, Sealed: blob, Step: 1}, time.Now(), testAudit); err != nil {
		t.Fatal(err)
	}
}

func openRawDB(t *testing.T, db string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", "file:"+db+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func loadRing(t *testing.T, path string) *secrets.Keyring {
	t.Helper()
	r, err := secrets.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestKeyGenerate(t *testing.T) {
	_, env := newDB(t)
	path := filepath.Join(t.TempDir(), "k.key")
	r := runServer(t, env, "key", "generate", "--file", path)
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("stdout must stay empty: %+v", r)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v mode %v", err, fi.Mode().Perm())
	}
	ring := loadRing(t, path)
	if ring.Len() != 1 || !strings.Contains(r.stderr, ring.ActiveID()) || !strings.Contains(r.stderr, "chmod 0640") {
		t.Fatalf("stderr must carry the key id and the next step: %s", r.stderr)
	}
	// It never overwrites.
	before, _ := os.ReadFile(path)
	if r := runServer(t, env, "key", "generate", "--file", path); r.code != 1 || !strings.Contains(r.stderr, "already exists") {
		t.Fatalf("overwrite: %+v", r)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("the existing key file was modified")
	}
	// The configured path is the default.
	cfgPath := filepath.Join(t.TempDir(), "conf.key")
	r = runServer(t, append(env, "CLAMFLEET_SERVER_SECRET_KEY_FILE="+cfgPath), "key", "generate")
	if r.code != 0 {
		t.Fatalf("default path: %+v", r)
	}
	loadRing(t, cfgPath)
	if r := runServer(t, env, "key", "generate", "--file", "relative.key"); r.code != 2 {
		t.Fatalf("relative path: %+v", r)
	}
	if r := runServer(t, env, "key", "frob"); r.code != 2 {
		t.Fatalf("unknown subcommand: %+v", r)
	}
}

func TestKeyGenerateAddPutsTheNewKeyFirstAndKeepsTheRest(t *testing.T) {
	_, env := newDB(t)
	old := newKey(t)
	path := writeKeyFile(t, 0o640, old)
	r := runServer(t, env, "key", "generate", "--add", "--file", path)
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("%+v", r)
	}
	ring := loadRing(t, path)
	if ring.Len() != 2 || ring.ActiveID() == secrets.KeyID(old) {
		t.Fatalf("the new key must be first: %d keys, active %s, old %s", ring.Len(), ring.ActiveID(), secrets.KeyID(old))
	}
	oldRing, _ := secrets.Parse(strings.NewReader(secrets.EncodeKeyLine(old)))
	blob, _ := oldRing.Seal(secrets.PurposeTOTP, []byte("x"), 1)
	if _, err := ring.Open(secrets.PurposeTOTP, blob, 1); err != nil {
		t.Fatalf("the old key must still open old blobs: %v", err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v, want 0640 preserved", fi.Mode().Perm())
	}
	if _, err := os.Stat(path + ".new"); err == nil {
		t.Fatal("the temp file was left behind")
	}
	// --add on a missing file, or on a file the server would refuse, is an error.
	if r := runServer(t, env, "key", "generate", "--add", "--file", filepath.Join(t.TempDir(), "none.key")); r.code != 1 {
		t.Fatalf("add to a missing file: %+v", r)
	}
	bad := writeKeyFile(t, 0o644, old)
	if r := runServer(t, env, "key", "generate", "--add", "--file", bad); r.code != 1 {
		t.Fatalf("add to a world-readable file: %+v", r)
	}
	if got, _ := os.ReadFile(bad); strings.Count(string(got), "\n") != 2 {
		t.Fatal("a refused --add modified the file")
	}
}

func TestKeyReencrypt(t *testing.T) {
	db, env := newDB(t)
	oldKey := newKey(t)
	path := writeKeyFile(t, 0o600, oldKey)
	seedTOTPUser(t, db, "a@example.com", loadRing(t, path))
	seedTOTPUser(t, db, "b@example.com", loadRing(t, path))
	env = append(env, "CLAMFLEET_SERVER_SECRET_KEY_FILE="+path)

	if r := runServer(t, env, "key", "generate", "--add"); r.code != 0 {
		t.Fatalf("add: %+v", r)
	}
	ring := loadRing(t, path)
	st, err := sqlite.Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pending := func() int {
		all, _ := st.SealedTOTPSecrets(context.Background())
		n := 0
		for _, s := range all {
			if ring.NeedsReseal(s.Sealed) {
				n++
			}
		}
		return n
	}
	if pending() != 2 {
		t.Fatalf("setup: %d blobs on the old key", pending())
	}
	r := runServer(t, env, "key", "reencrypt")
	if r.code != 0 || r.stdout != "" || !strings.Contains(r.stderr, `"count":2`) {
		t.Fatalf("%+v", r)
	}
	if pending() != 0 {
		t.Fatalf("%d blobs still on the old key", pending())
	}
	// The re-sealed secrets still open, for their own user only.
	all, _ := st.SealedTOTPSecrets(context.Background())
	for _, s := range all {
		if pt, err := ring.Open(secrets.PurposeTOTP, s.Sealed, uint64(s.UserID)); err != nil || string(pt) != "12345678901234567890" {
			t.Fatalf("%s: %v", s.Email, err)
		}
	}
	// Idempotent: the second run changes nothing and writes no audit row.
	r = runServer(t, env, "key", "reencrypt")
	if r.code != 0 || !strings.Contains(r.stderr, `"count":0`) {
		t.Fatalf("second run: %+v", r)
	}
	raw := openRawDB(t, db)
	defer raw.Close()
	var n int
	if err := raw.QueryRow(`SELECT count(*) FROM audit_log WHERE action='secrets.reencrypt' AND target_kind='server' AND actor_kind='cli'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d audit rows, %v; want 1", n, err)
	}
	// Without a key file it fails and says so.
	if r := runServer(t, cliEnv(db), "key", "reencrypt"); r.code != 1 || !strings.Contains(r.stderr, "key file") {
		t.Fatalf("no key file: %+v", r)
	}
}

// A secret that cannot be opened stops the whole run: nothing is half rotated.
func TestKeyReencryptChangesNothingWhenOneSecretCannotBeOpened(t *testing.T) {
	db, env := newDB(t)
	keyA, keyB, keyC := newKey(t), newKey(t), newKey(t)
	ringA, _ := secrets.Parse(strings.NewReader(secrets.EncodeKeyLine(keyA)))
	ringB, _ := secrets.Parse(strings.NewReader(secrets.EncodeKeyLine(keyB)))
	seedTOTPUser(t, db, "a@example.com", ringA)
	seedTOTPUser(t, db, "b@example.com", ringB) // sealed with a key that is not in the file
	path := writeKeyFile(t, 0o600, keyC, keyA)
	r := runServer(t, append(env, "CLAMFLEET_SERVER_SECRET_KEY_FILE="+path), "key", "reencrypt")
	if r.code != 1 || !strings.Contains(r.stderr, "b@example.com") {
		t.Fatalf("%+v", r)
	}
	st, _ := sqlite.Open(context.Background(), db)
	defer st.Close()
	all, _ := st.SealedTOTPSecrets(context.Background())
	if _, err := ringA.Open(secrets.PurposeTOTP, all[0].Sealed, uint64(all[0].UserID)); err != nil {
		t.Fatalf("the secret that could be opened was re-sealed anyway: %v", err)
	}
}

// serveRefuses runs `serve`, which must stop by itself with exit 1. A server that
// starts instead is killed after a timeout and the test fails with that, rather
// than hanging until the test binary's own timeout.
func serveRefuses(t *testing.T, db string, extra ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, serverBin, "serve")
	cmd.Env = cliEnv(db, extra...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("serve did not refuse to start (still running after 20 s):\n%s", se.String())
	}
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{so.String(), se.String(), code}
}

func TestServeKeyFileStartupRules(t *testing.T) {
	// Refusals: each runs the real binary and checks exit code and message.
	t.Run("totp_required without a key file", func(t *testing.T) {
		db, _ := newDB(t)
		r := serveRefuses(t, db, "CLAMFLEET_SERVER_AUTH_LOCAL_TOTP_REQUIRED=true")
		if r.code != 1 || !strings.Contains(r.stderr, "totp_required") || !strings.Contains(r.stderr, "key generate") {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("a TOTP user and no key file", func(t *testing.T) {
		db, _ := newDB(t)
		seedTOTPUser(t, db, "a@example.com", loadRing(t, writeKeyFile(t, 0o600, newKey(t))))
		r := serveRefuses(t, db)
		if r.code != 1 || !strings.Contains(r.stderr, "1 user(s) have TOTP enabled") || !strings.Contains(r.stderr, "reset-totp") {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("a key file others can read", func(t *testing.T) {
		db, _ := newDB(t)
		path := writeKeyFile(t, 0o644, newKey(t))
		r := serveRefuses(t, db, "CLAMFLEET_SERVER_SECRET_KEY_FILE="+path)
		if r.code != 1 || !strings.Contains(r.stderr, "mode 0644") {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("a key file that is not a key file", func(t *testing.T) {
		db, _ := newDB(t)
		p := filepath.Join(t.TempDir(), "k.key")
		if err := os.WriteFile(p, []byte("hello\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if r := serveRefuses(t, db, "CLAMFLEET_SERVER_SECRET_KEY_FILE="+p); r.code != 1 || !strings.Contains(r.stderr, "base64") {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("a key file that does not open a stored secret", func(t *testing.T) {
		db, _ := newDB(t)
		seedTOTPUser(t, db, "a@example.com", loadRing(t, writeKeyFile(t, 0o600, newKey(t))))
		other := writeKeyFile(t, 0o600, newKey(t))
		r := serveRefuses(t, db, "CLAMFLEET_SERVER_SECRET_KEY_FILE="+other)
		if r.code != 1 || !strings.Contains(r.stderr, "1 of 1 stored TOTP secrets cannot be opened") {
			t.Fatalf("%+v", r)
		}
	})

	// Starts: with TLS bundle, as the live tests do.
	tlsb, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Run("no key file and no TOTP: starts and warns", func(t *testing.T) {
		db, _ := newDB(t)
		s := startServe(t, tlsb, db)
		if !strings.Contains(s.stderr.String(), "two-factor sign-in (TOTP) is unavailable") {
			t.Fatalf("no warning:\n%s", s.stderr.String())
		}
	})
	t.Run("a key file that opens every stored secret: starts", func(t *testing.T) {
		db, _ := newDB(t)
		path := writeKeyFile(t, 0o640, newKey(t))
		seedTOTPUser(t, db, "a@example.com", loadRing(t, path))
		s := startServe(t, tlsb, db, "CLAMFLEET_SERVER_SECRET_KEY_FILE="+path, "CLAMFLEET_SERVER_AUTH_LOCAL_TOTP_REQUIRED=true")
		if !strings.Contains(s.stderr.String(), "secret key file loaded") {
			t.Fatalf("\n%s", s.stderr.String())
		}
	})
}
