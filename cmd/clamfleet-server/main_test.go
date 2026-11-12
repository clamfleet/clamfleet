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
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
)

// serverBin and agentBin are the real binaries, built once. The tests run the
// compiled programs through their real command dispatch.
var serverBin, agentBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cfserver")
	if err != nil {
		panic(err)
	}
	serverBin = filepath.Join(dir, "clamfleet-server")
	agentBin = filepath.Join(dir, "clamfleet-agent")
	for _, b := range [][]string{{serverBin, "."}, {agentBin, "../clamfleet-agent"}} {
		if out, err := exec.Command("go", "build", "-o", b[0], b[1]).CombinedOutput(); err != nil {
			os.Stderr.Write(out)
			os.RemoveAll(dir)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type result struct {
	stdout, stderr string
	code           int
}

// cliEnv configures the server purely through the environment (which also
// exercises the CLAMFLEET_SERVER_ overrides): plaintext on loopback, port 0.
func cliEnv(db string, extra ...string) []string {
	return append([]string{
		"PATH=" + os.Getenv("PATH"), // a clean environment: the developer's own CLAMFLEET_SERVER_* must not leak in
		"CLAMFLEET_SERVER_DB_PATH=" + db,
		"CLAMFLEET_SERVER_TLS_CERT=", "CLAMFLEET_SERVER_TLS_KEY=",
		"CLAMFLEET_SERVER_LISTEN=127.0.0.1:0",
		// Never the developer's own key file: tests that need one set their own (later entries win).
		"CLAMFLEET_SERVER_SECRET_KEY_FILE=/nonexistent/clamfleet-test-secret.key",
	}, extra...)
}

func runServer(t *testing.T, env []string, args ...string) result {
	t.Helper()
	cmd := exec.Command(serverBin, args...)
	cmd.Env = env
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

var tokenRE = regexp.MustCompile(`^cfa_[A-Za-z0-9_-]{43}\n$`)

func newDB(t *testing.T) (db string, env []string) {
	t.Helper()
	db = filepath.Join(t.TempDir(), "cf.db")
	env = cliEnv(db)
	if r := runServer(t, env, "migrate"); r.code != 0 {
		t.Fatalf("migrate: %+v", r)
	}
	return db, env
}

func TestUsageAndVersion(t *testing.T) {
	env := cliEnv("/nonexistent/x.db")
	if r := runServer(t, env); r.code != 2 || !strings.Contains(r.stderr, "usage:") {
		t.Fatalf("no args: %+v", r)
	}
	if r := runServer(t, env, "frobnicate"); r.code != 2 {
		t.Fatalf("unknown command: %+v", r)
	}
	if r := runServer(t, env, "host"); r.code != 2 {
		t.Fatalf("host without subcommand: %+v", r)
	}
	if r := runServer(t, env, "host", "add"); r.code != 2 {
		t.Fatalf("host add without a name: %+v", r)
	}
	if r := runServer(t, env, "host", "list", "extra"); r.code != 2 {
		t.Fatalf("host list with an argument: %+v", r)
	}
	if r := runServer(t, env, "version"); r.code != 0 || !strings.HasPrefix(r.stdout, "clamfleet-server ") {
		t.Fatalf("version: %+v", r)
	}
}

func TestHostAddPrintsOnlyToken(t *testing.T) {
	db, env := newDB(t)
	r := runServer(t, env, "host", "add", "Web01")
	if r.code != 0 || !tokenRE.MatchString(r.stdout) {
		t.Fatalf("stdout must be exactly the token line: %+v", r)
	}
	token := strings.TrimSpace(r.stdout)
	if strings.Contains(r.stderr, token) || strings.Contains(r.stderr, token[4:]) {
		t.Fatalf("the token is in stderr: %s", r.stderr)
	}
	if !strings.Contains(r.stderr, `"host added"`) || !strings.Contains(r.stderr, `"host":"web01"`) {
		t.Fatalf("no audit-style log line: %s", r.stderr)
	}
	// A duplicate fails, prints nothing on stdout, and names the problem.
	r2 := runServer(t, env, "host", "add", "web01")
	if r2.code != 1 || r2.stdout != "" || !strings.Contains(r2.stderr, "already exists") {
		t.Fatalf("duplicate: %+v", r2)
	}
	if r := runServer(t, env, "host", "add", "bad name"); r.code != 1 || r.stdout != "" {
		t.Fatalf("invalid name: %+v", r)
	}
	// Only the hash is on disk.
	var all []byte
	for _, suf := range []string{"", "-wal"} {
		if b, err := os.ReadFile(db + suf); err == nil {
			all = append(all, b...)
		}
	}
	if bytes.Contains(all, []byte(token)) || bytes.Contains(all, []byte(token[4:])) {
		t.Fatal("the plain token is in the database file")
	}
}

type hostJSON struct {
	Name     string `json:"name"`
	HasToken bool   `json:"has_token"`
	Audit    []struct {
		Action string `json:"action"`
		Actor  string `json:"actor"`
	} `json:"audit"`
	LastReport json.RawMessage `json:"last_report"`
	FirstSeen  *string         `json:"first_seen"`
}

func TestListShowRotateRevoke(t *testing.T) {
	_, env := newDB(t)
	sudo := append(append([]string{}, env...), "SUDO_USER=alice")
	tok1 := strings.TrimSpace(runServer(t, sudo, "host", "add", "web01").stdout)
	runServer(t, env, "host", "add", "db01")

	list := runServer(t, env, "host", "list")
	if list.code != 0 || !strings.Contains(list.stdout, "web01") || !strings.Contains(list.stdout, "db01") || strings.Count(list.stdout, "active") != 2 {
		t.Fatalf("list: %+v", list)
	}
	if strings.Index(list.stdout, "db01") > strings.Index(list.stdout, "web01") {
		t.Fatalf("list is not sorted by name:\n%s", list.stdout)
	}

	rot := runServer(t, sudo, "host", "rotate-token", "WEB01")
	tok2 := strings.TrimSpace(rot.stdout)
	if rot.code != 0 || !tokenRE.MatchString(rot.stdout) || tok2 == tok1 {
		t.Fatalf("rotate: %+v", rot)
	}
	if strings.Contains(rot.stderr, tok2) || strings.Contains(rot.stderr, tok1) {
		t.Fatalf("a token is in the rotate log: %s", rot.stderr)
	}

	// show --json (flag after the name works too).
	show := runServer(t, env, "host", "show", "web01", "--json")
	var d hostJSON
	if err := json.Unmarshal([]byte(show.stdout), &d); err != nil || show.code != 0 {
		t.Fatalf("show: %+v %v", show, err)
	}
	if d.Name != "web01" || !d.HasToken || d.FirstSeen != nil || string(d.LastReport) != "null" {
		t.Fatalf("%+v", d)
	}
	if len(d.Audit) != 2 || d.Audit[0].Action != "host.token.rotate" || d.Audit[1].Action != "host.add" || d.Audit[0].Actor != "alice" {
		t.Fatalf("audit (newest first, actor from SUDO_USER): %+v", d.Audit)
	}

	rev := runServer(t, env, "host", "revoke-token", "web01")
	if rev.code != 0 || rev.stdout != "" {
		t.Fatalf("revoke: %+v", rev)
	}
	if l := runServer(t, env, "host", "list"); !strings.Contains(l.stdout, "revoked") || strings.Count(l.stdout, "active") != 1 {
		t.Fatalf("list after revoke:\n%s", l.stdout)
	}
	text := runServer(t, env, "host", "show", "web01")
	if text.code != 0 || !strings.Contains(text.stdout, "revoked") {
		t.Fatalf("show: %+v", text)
	}
	for _, cmd := range []string{"rotate-token", "revoke-token", "show"} {
		if r := runServer(t, env, "host", cmd, "ghost"); r.code != 1 || !strings.Contains(r.stderr, "no such host") {
			t.Errorf("%s ghost: %+v", cmd, r)
		}
	}
}

func TestHostCommandsRefuseMissingOrUnmigratedDatabase(t *testing.T) {
	// No database at all: refuse, and do not create a stray file.
	db := filepath.Join(t.TempDir(), "missing.db")
	env := cliEnv(db)
	r := runServer(t, env, "host", "list")
	if r.code != 1 || !strings.Contains(r.stderr, "migrate") {
		t.Fatalf("missing db: %+v", r)
	}
	if _, err := os.Stat(db); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a host command created the database file")
	}

	// A database that exists but was never migrated: exit 1 with the hint, no schema written.
	st, err := sqlite.Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	r = runServer(t, env, "host", "add", "web01")
	if r.code != 1 || !strings.Contains(r.stderr, "clamfleet-server migrate") || r.stdout != "" {
		t.Fatalf("unmigrated: %+v", r)
	}
	st, _ = sqlite.Open(context.Background(), db)
	defer st.Close()
	if v, _ := st.SchemaVersion(context.Background()); v != 0 {
		t.Fatalf("a host command migrated the database to %d", v)
	}

	// migrate fixes it; running it twice is fine.
	for i := 0; i < 2; i++ {
		if r := runServer(t, env, "migrate"); r.code != 0 || !strings.Contains(r.stderr, "up to date") {
			t.Fatalf("migrate #%d: %+v", i, r)
		}
	}
	if r := runServer(t, env, "host", "add", "web01"); r.code != 0 {
		t.Fatalf("after migrate: %+v", r)
	}
}

func TestInvalidConfigIsRefused(t *testing.T) {
	db := filepath.Join(t.TempDir(), "x.db")
	// Plaintext on a public address.
	env := cliEnv(db, "CLAMFLEET_SERVER_LISTEN=:8443")
	if r := runServer(t, env, "serve"); r.code != 1 || !strings.Contains(r.stderr, "loopback") {
		t.Fatalf("serve: %+v", r)
	}
	if _, err := os.Stat(db); err == nil {
		t.Fatal("a refused configuration still created the database")
	}
	// The agent's variables are not ours: no warning, no effect.
	env = cliEnv(db, "CLAMFLEET_AGENT_SERVER=https://x")
	if r := runServer(t, env, "migrate"); r.code != 0 || strings.Contains(r.stderr, "CLAMFLEET_AGENT") {
		t.Fatalf("%+v", r)
	}
	// A typo with our prefix warns.
	env = cliEnv(db, "CLAMFLEET_SERVER_LISTN=:1")
	if r := runServer(t, env, "migrate"); r.code != 0 || !strings.Contains(r.stderr, "CLAMFLEET_SERVER_LISTN") {
		t.Fatalf("%+v", r)
	}
}

func TestCheckCanCreate(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "new.db")
	if err := checkCanCreate(missing, os.Geteuid()); err != nil {
		t.Fatalf("owner of the directory: %v", err)
	}
	err := checkCanCreate(missing, os.Geteuid()+1)
	if err == nil || !strings.Contains(err.Error(), "refusing to create") {
		t.Fatalf("a user that does not own the directory must be refused, got %v", err)
	}
	// An existing database is never refused (and not touched).
	existing := filepath.Join(dir, "old.db")
	os.WriteFile(existing, nil, 0o600)
	if err := checkCanCreate(existing, os.Geteuid()+1); err != nil {
		t.Fatal(err)
	}
	// A missing directory is Open's error to report.
	if err := checkCanCreate(filepath.Join(dir, "no", "x.db"), os.Geteuid()+1); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerMismatch(t *testing.T) {
	f := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(f)
	if _, bad := ownerMismatch(fi, os.Geteuid()); bad {
		t.Fatal("own file reported as owned by someone else")
	}
	if owner, bad := ownerMismatch(fi, os.Geteuid()+1); !bad || int(owner) != os.Geteuid() {
		t.Fatalf("a different euid must be a mismatch, got owner %d bad=%v", owner, bad)
	}
	// And the normal path stays quiet.
	_, env := newDB(t)
	if r := runServer(t, env, "host", "list"); strings.Contains(r.stderr, "owned by another user") {
		t.Fatalf("spurious warning: %s", r.stderr)
	}
}

// seedState writes a state for a host through the store, as the evaluator in
// `serve` would (the CLI only reads it).
func seedState(t *testing.T, db string, state string, reasons string, at time.Time) {
	t.Helper()
	ctx := context.Background()
	st, err := sqlite.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = st.EvaluateHosts(ctx, at, nil, func(in store.HealthInput) store.HealthOutcome {
		if in.Name != "web01" {
			return store.HealthOutcome{} // db01 stays pending
		}
		return store.HealthOutcome{State: state, Reasons: json.RawMessage(reasons)}
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHostListAndShowPrintState(t *testing.T) {
	db, env := newDB(t)
	runServer(t, env, "host", "add", "web01")
	runServer(t, env, "host", "add", "db01")
	at := time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC)
	seedState(t, db, "OK", `[]`, at)
	seedState(t, db, "CRIT", `[{"rule":"clamd_down","severity":"CRIT","msg":"clamd is not answering: ping: timeout"}]`, at.Add(time.Hour))

	list := runServer(t, env, "host", "list")
	if list.code != 0 || !strings.Contains(list.stdout, "STATE") {
		t.Fatalf("list: %+v", list)
	}
	for _, line := range strings.Split(list.stdout, "\n") {
		switch {
		case strings.HasPrefix(line, "web01"):
			if !strings.Contains(line, "CRIT") {
				t.Errorf("web01 line: %q", line)
			}
		case strings.HasPrefix(line, "db01"):
			if !strings.Contains(line, "pending") {
				t.Errorf("a never-evaluated host must read pending: %q", line)
			}
		}
	}

	show := runServer(t, env, "host", "show", "web01")
	for _, want := range []string{
		"state:          CRIT (since 2031-03-04T13:00:00Z)",
		"CRIT  clamd_down: clamd is not answering: ping: timeout",
		"2031-03-04T13:00:00Z  OK -> CRIT",
		"2031-03-04T12:00:00Z  none -> OK",
	} {
		if !strings.Contains(show.stdout, want) {
			t.Errorf("show lacks %q:\n%s", want, show.stdout)
		}
	}
	if !strings.Contains(runServer(t, env, "host", "show", "db01").stdout, "state:          pending") {
		t.Error("pending host: show must say pending")
	}

	js := runServer(t, env, "host", "show", "web01", "--json")
	var d struct {
		State        *string `json:"state"`
		StateReason  []struct{ Rule string }
		StateChanges []struct {
			From *string `json:"from_state"`
			To   string  `json:"to_state"`
		} `json:"state_changes"`
	}
	if err := json.Unmarshal([]byte(js.stdout), &d); err != nil {
		t.Fatal(err)
	}
	if d.State == nil || *d.State != "CRIT" || len(d.StateChanges) != 2 || d.StateChanges[1].From != nil {
		t.Fatalf("%s", js.stdout)
	}
	if !strings.Contains(js.stdout, `"state_reason": [`) || !strings.Contains(js.stdout, `"clamd_down"`) {
		t.Fatalf("state_reason must be a JSON array in --json output:\n%s", js.stdout)
	}
	var pending struct {
		State *string `json:"state"`
	}
	json.Unmarshal([]byte(runServer(t, env, "host", "show", "db01", "--json").stdout), &pending)
	if pending.State != nil {
		t.Fatalf("a pending host has state null in JSON, got %v", *pending.State)
	}
}

func TestHostDelete(t *testing.T) {
	db, env := newDB(t)
	sudo := append(append([]string{}, env...), "SUDO_USER=alice")
	runServer(t, env, "host", "add", "web01")
	runServer(t, env, "host", "add", "keep01")
	seedState(t, db, "OK", `[]`, time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC))

	// Without --yes: usage error, nothing deleted, and the database is not even opened.
	if r := runServer(t, env, "host", "delete", "web01"); r.code != 2 || !strings.Contains(r.stderr, "--yes") {
		t.Fatalf("delete without --yes: %+v", r)
	}
	if r := runServer(t, cliEnv("/nonexistent/x.db"), "host", "delete", "web01"); r.code != 2 {
		t.Fatalf("delete without --yes must be a usage error before touching the database: %+v", r)
	}
	if r := runServer(t, env, "host", "show", "web01"); r.code != 0 {
		t.Fatalf("host vanished without --yes: %+v", r)
	}
	if r := runServer(t, env, "host", "delete", "--yes"); r.code != 2 {
		t.Fatalf("delete without a name: %+v", r)
	}

	if r := runServer(t, sudo, "host", "delete", "WEB01", "--yes"); r.code != 0 || r.stdout != "" {
		t.Fatalf("delete: %+v", r)
	}
	if r := runServer(t, env, "host", "show", "web01"); r.code != 1 || !strings.Contains(r.stderr, "no such host") {
		t.Fatalf("host still there: %+v", r)
	}
	if r := runServer(t, env, "host", "show", "keep01"); r.code != 0 {
		t.Fatalf("another host was deleted: %+v", r)
	}
	if r := runServer(t, env, "host", "delete", "web01", "--yes"); r.code != 1 || !strings.Contains(r.stderr, "no such host") {
		t.Fatalf("second delete: %+v", r)
	}

	// The audit row names the operator and the host, and outlives the host.
	raw, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var actor, kind, target string
	if err := raw.QueryRow(`SELECT actor, target_kind, target FROM audit_log WHERE action='host.delete'`).Scan(&actor, &kind, &target); err != nil {
		t.Fatal(err)
	}
	if actor != "alice" || kind != "host" || target != "web01" {
		t.Fatalf("audit: %q %q %q", actor, kind, target)
	}
	var n int
	raw.QueryRow(`SELECT count(*) FROM state_changes`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d state_changes rows survived the delete", n)
	}
}
