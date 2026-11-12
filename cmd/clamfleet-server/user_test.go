// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
	"github.com/clamfleet/clamfleet/internal/webauth"
)

var passwordRE = regexp.MustCompile(`^[A-Za-z0-9_-]{24}\n$`)

// runServerStdin is runServer with a piped stdin.
func runServerStdin(t *testing.T, env []string, stdin string, args ...string) result {
	t.Helper()
	cmd := exec.Command(serverBin, args...)
	cmd.Env = append(env, "SUDO_USER=alice")
	cmd.Stdin = strings.NewReader(stdin)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{so.String(), se.String(), code}
}

func TestUserAddPrintsOnlyThePasswordOnce(t *testing.T) {
	db, env := newDB(t)
	r := runServerStdin(t, env, "", "user", "add", "Ann@Example.com", "--role", "admin", "--name", "Ann")
	if r.code != 0 || !passwordRE.MatchString(r.stdout) {
		t.Fatalf("stdout must be exactly the password line: %+v", r)
	}
	pw := strings.TrimSpace(r.stdout)
	if strings.Contains(r.stderr, pw) {
		t.Fatalf("the password is in stderr: %s", r.stderr)
	}
	if !strings.Contains(r.stderr, `"user":"ann@example.com"`) || !strings.Contains(r.stderr, `"actor":"alice"`) {
		t.Fatalf("no audit-style log line: %s", r.stderr)
	}
	// Only an argon2id hash is on disk, and it verifies; the user must change it.
	st, err := sqlite.Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	u, err := st.UserByEmail(context.Background(), "ann@example.com")
	if err != nil || u.Role != "admin" || !u.MustChange || !strings.HasPrefix(u.PasswordHash, "$argon2id$") {
		t.Fatalf("%+v %v", u, err)
	}
	if ok, _, err := webauth.NewHasher().Verify(context.Background(), pw, u.PasswordHash); err != nil || !ok {
		t.Fatalf("printed password does not verify: %v %v", ok, err)
	}
	var all []byte
	for _, suf := range []string{"", "-wal"} {
		if b, err := os.ReadFile(db + suf); err == nil {
			all = append(all, b...)
		}
	}
	if bytes.Contains(all, []byte(pw)) {
		t.Fatal("the plain password is in the database file")
	}

	// A duplicate exits 1 and prints nothing on stdout.
	if r := runServerStdin(t, env, "", "user", "add", "ann@example.com", "--role", "viewer"); r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, "already exists") {
		t.Fatalf("duplicate: %+v", r)
	}
	// Usage errors exit 2.
	for name, args := range map[string][]string{
		"no role":       {"user", "add", "x@example.com"},
		"invalid role":  {"user", "add", "x@example.com", "--role", "root"},
		"no email":      {"user", "add", "--role", "viewer"},
		"bad set-role":  {"user", "set-role", "ann@example.com", "root"},
		"bad email":     {"user", "disable", "not-an-email"},
		"unknown sub":   {"user", "frob"},
		"no sub":        {"user"},
		"stdin on list": {"user", "list", "--password-stdin"},
	} {
		if r := runServerStdin(t, env, "", args...); r.code != 2 {
			t.Errorf("%s: exit %d, want 2: %+v", name, r.code, r)
		}
	}
}

func TestUserPasswordStdin(t *testing.T) {
	db, env := newDB(t)
	long := "a-long-enough-password"
	r := runServerStdin(t, env, long+"\n", "user", "add", "bob@example.com", "--role", "viewer", "--password-stdin")
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("stdin add prints nothing on stdout: %+v", r)
	}
	if strings.Contains(r.stderr, long) {
		t.Fatalf("password in stderr: %s", r.stderr)
	}
	st, _ := sqlite.Open(context.Background(), db)
	defer st.Close()
	u, _ := st.UserByEmail(context.Background(), "bob@example.com")
	if ok, _, _ := webauth.NewHasher().Verify(context.Background(), long, u.PasswordHash); !ok || !u.MustChange {
		t.Fatalf("stdin password not set or not forced to change: ok=%v %+v", ok, u)
	}
	// Policy and empty stdin: exit 1, no user created.
	for name, in := range map[string]string{"too short": "short\n", "empty": "", "blank line": "\n"} {
		r := runServerStdin(t, env, in, "user", "add", "carl@example.com", "--role", "viewer", "--password-stdin")
		if r.code != 1 || r.stdout != "" {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if _, err := st.UserByEmail(context.Background(), "carl@example.com"); err == nil {
		t.Fatal("a user was created despite a rejected password")
	}
	// A last line without a newline is fine (printf piping).
	if r := runServerStdin(t, env, "another-long-password", "user", "reset-password", "bob@example.com", "--password-stdin"); r.code != 0 || r.stdout != "" {
		t.Fatalf("reset from stdin: %+v", r)
	}
	u, _ = st.UserByEmail(context.Background(), "bob@example.com")
	if ok, _, _ := webauth.NewHasher().Verify(context.Background(), "another-long-password", u.PasswordHash); !ok {
		t.Fatal("reset password not stored")
	}
}

func TestUserListDisableEnableRoleReset(t *testing.T) {
	db, env := newDB(t)
	runServerStdin(t, env, "", "user", "add", "ann@example.com", "--role", "admin")
	runServerStdin(t, env, "", "user", "add", "bob@example.com", "--role", "viewer")

	type uj struct {
		Email, Role string
		Disabled    bool
	}
	list := func() map[string]uj {
		r := runServerStdin(t, env, "", "user", "list", "--json")
		if r.code != 0 {
			t.Fatalf("%+v", r)
		}
		if strings.Contains(r.stdout, "argon2") || strings.Contains(r.stdout, "password_hash") {
			t.Fatalf("the hash is in the JSON listing: %s", r.stdout)
		}
		var us []map[string]any
		if err := json.Unmarshal([]byte(r.stdout), &us); err != nil {
			t.Fatal(err)
		}
		out := map[string]uj{}
		for _, u := range us {
			out[u["email"].(string)] = uj{u["email"].(string), u["role"].(string), u["disabled"].(bool)}
		}
		return out
	}
	if l := list(); len(l) != 2 || l["bob@example.com"].Role != "viewer" || l["ann@example.com"].Disabled {
		t.Fatalf("%+v", l)
	}
	if r := runServerStdin(t, env, "", "user", "disable", "BOB@example.com"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if !list()["bob@example.com"].Disabled {
		t.Fatal("bob not disabled")
	}
	if r := runServerStdin(t, env, "", "user", "list"); !strings.Contains(r.stdout, "disabled") || strings.Contains(r.stdout, "argon2") {
		t.Fatalf("%+v", r)
	}
	runServerStdin(t, env, "", "user", "enable", "bob@example.com")
	runServerStdin(t, env, "", "user", "set-role", "bob@example.com", "admin")
	if l := list(); l["bob@example.com"].Disabled || l["bob@example.com"].Role != "admin" {
		t.Fatalf("%+v", l)
	}
	if r := runServerStdin(t, env, "", "user", "reset-password", "bob@example.com"); r.code != 0 || !passwordRE.MatchString(r.stdout) {
		t.Fatalf("%+v", r)
	}
	for _, args := range [][]string{{"disable", "ghost@example.com"}, {"reset-password", "ghost@example.com"}, {"set-role", "ghost@example.com", "viewer"}} {
		if r := runServerStdin(t, env, "", append([]string{"user"}, args...)...); r.code != 1 || !strings.Contains(r.stderr, "no such user") {
			t.Errorf("%v: %+v", args, r)
		}
	}
	// Every command is audited with the OS actor.
	raw, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, a := range []string{"user.add", "user.disable", "user.enable", "user.role", "user.password.reset"} {
		var n int
		if err := raw.QueryRow(`SELECT count(*) FROM audit_log WHERE action=? AND actor='alice' AND actor_kind='cli'`, a).Scan(&n); err != nil || n == 0 {
			t.Errorf("no audit row for %s (n=%d, %v)", a, n, err)
		}
	}
}

// seedFullTOTPUser makes a user with TOTP, recovery codes, a session and an open
// login challenge, so a reset has something to remove.
func seedFullTOTPUser(t *testing.T, db, email string) {
	t.Helper()
	ctx := context.Background()
	seedTOTPUser(t, db, email, loadRing(t, writeKeyFile(t, 0o600, newKey(t))))
	st, err := sqlite.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	u, _ := st.UserByEmail(ctx, email)
	now := time.Now()
	if err := st.ReplaceRecoveryCodes(ctx, u.ID, [][]byte{[]byte("h1-" + email), []byte("h2-" + email)}, now, testAudit); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(ctx, store.Session{TokenHash: []byte("s-" + email), UserID: u.ID, CSRF: []byte("c"), CreatedAt: now, ExpiresAt: now.Add(time.Hour), PasswordHash: u.PasswordHash, AuthVersion: u.AuthVersion}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateLoginChallenge(ctx, store.LoginChallenge{TokenHash: []byte("c-" + email), UserID: u.ID, AuthVersion: u.AuthVersion, PasswordHash: u.PasswordHash, Next: "/", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}, now); err != nil {
		t.Fatal(err)
	}
}

func TestUserResetTOTP(t *testing.T) {
	db, env := newDB(t)
	seedFullTOTPUser(t, db, "ann@example.com")
	seedFullTOTPUser(t, db, "bob@example.com")
	// Ann is locked out of her second factor: reset-totp lifts that too.
	raw, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE users SET totp_failures = 100 WHERE email = 'ann@example.com'`); err != nil {
		t.Fatal(err)
	}
	count := func(q string, args ...any) int {
		var n int
		if err := raw.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	r := runServerStdin(t, env, "", "user", "reset-totp", "ANN@example.com")
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("stdout must stay empty: %+v", r)
	}
	if n := count(`SELECT count(*) FROM users WHERE email='ann@example.com' AND totp_secret IS NULL AND totp_enabled_at IS NULL AND totp_last_step IS NULL AND totp_failures = 0`); n != 1 {
		t.Fatal("ann's TOTP state was not cleared")
	}
	for name, q := range map[string]string{
		"recovery codes":   `SELECT count(*) FROM user_recovery_codes WHERE user_id = (SELECT id FROM users WHERE email='ann@example.com')`,
		"sessions":         `SELECT count(*) FROM user_sessions WHERE user_id = (SELECT id FROM users WHERE email='ann@example.com')`,
		"login challenges": `SELECT count(*) FROM user_login_challenges WHERE user_id = (SELECT id FROM users WHERE email='ann@example.com')`,
	} {
		if n := count(q); n != 0 {
			t.Errorf("%d %s survived the reset", n, name)
		}
	}
	// Only Ann is touched.
	if n := count(`SELECT count(*) FROM users WHERE email='bob@example.com' AND totp_secret IS NOT NULL`); n != 1 {
		t.Fatal("bob's TOTP was removed")
	}
	if n := count(`SELECT count(*) FROM user_sessions`) + count(`SELECT count(*) FROM user_recovery_codes`); n != 3 {
		t.Fatalf("bob lost sessions or codes (%d rows left, want 3)", n)
	}
	if n := count(`SELECT count(*) FROM audit_log WHERE action='user.totp.reset' AND target='ann@example.com' AND actor='alice' AND actor_kind='cli'`); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
	// It works without any key file (cliEnv points at a nonexistent one): the way out of a lost key.
	if r := runServerStdin(t, env, "", "user", "reset-totp", "ghost@example.com"); r.code != 1 || !strings.Contains(r.stderr, "no such user") {
		t.Fatalf("unknown user: %+v", r)
	}
	if r := runServerStdin(t, env, "", "user", "reset-totp"); r.code != 2 {
		t.Fatalf("missing argument: %+v", r)
	}
	if r := runServerStdin(t, env, "", "user", "reset-totp", "not-an-email"); r.code != 2 {
		t.Fatalf("bad email: %+v", r)
	}
}

func TestUserListShowsTOTP(t *testing.T) {
	db, env := newDB(t)
	runServerStdin(t, env, "", "user", "add", "plain@example.com", "--role", "viewer")
	seedTOTPUser(t, db, "on@example.com", loadRing(t, writeKeyFile(t, 0o600, newKey(t))))
	seedTOTPUser(t, db, "locked@example.com", loadRing(t, writeKeyFile(t, 0o600, newKey(t))))
	raw, _ := sql.Open("sqlite", db)
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE users SET totp_failures = 100 WHERE email = 'locked@example.com'`); err != nil {
		t.Fatal(err)
	}
	r := runServerStdin(t, env, "", "user", "list")
	if r.code != 0 || !strings.Contains(r.stdout, "TOTP") {
		t.Fatalf("%+v", r)
	}
	want := map[string]string{"plain@example.com": "off", "on@example.com": "on", "locked@example.com": "locked"}
	for _, line := range strings.Split(strings.TrimSpace(r.stdout), "\n")[1:] {
		f := strings.Fields(line)
		if got := f[len(f)-1]; got != want[f[0]] {
			t.Errorf("%s: TOTP column %q, want %q", f[0], got, want[f[0]])
		}
	}
	// The JSON gains two additive fields and still leaks no secret.
	j := runServerStdin(t, env, "", "user", "list", "--json")
	var us []map[string]any
	if err := json.Unmarshal([]byte(j.stdout), &us); err != nil {
		t.Fatal(err)
	}
	for _, u := range us {
		if _, ok := u["totp_enabled"].(bool); !ok {
			t.Errorf("%v: no totp_enabled", u["email"])
		}
		if _, ok := u["totp_failures"].(float64); !ok {
			t.Errorf("%v: no totp_failures", u["email"])
		}
		for k := range u {
			if strings.Contains(k, "secret") || strings.Contains(k, "auth_version") {
				t.Errorf("the listing exposes %q", k)
			}
		}
	}
}

// A locked second factor is also lifted by `user reset-password` (a lock means
// someone had the password, and the reset is the response to that).
func TestUserResetPasswordLiftsTheSecondFactorLock(t *testing.T) {
	db, env := newDB(t)
	seedTOTPUser(t, db, "ann@example.com", loadRing(t, writeKeyFile(t, 0o600, newKey(t))))
	raw, _ := sql.Open("sqlite", db)
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE users SET totp_failures = 100 WHERE email = 'ann@example.com'`); err != nil {
		t.Fatal(err)
	}
	if r := runServerStdin(t, env, "a-long-enough-password\n", "user", "reset-password", "ann@example.com", "--password-stdin"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	var n int
	if err := raw.QueryRow(`SELECT totp_failures FROM users WHERE email='ann@example.com'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("totp_failures %d, %v", n, err)
	}
	// TOTP itself stays on: only the lock is lifted.
	if err := raw.QueryRow(`SELECT count(*) FROM users WHERE email='ann@example.com' AND totp_secret IS NOT NULL`).Scan(&n); err != nil || n != 1 {
		t.Fatal("reset-password removed the authenticator")
	}
}
