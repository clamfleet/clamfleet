// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/clamfleet/clamfleet/internal/alert"
	"github.com/clamfleet/clamfleet/internal/testsmtp"
)

// alertCLIEnv: a migrated database, a key file, and the environment for the CLI.
func alertCLIEnv(t *testing.T, extra ...string) (db string, env []string) {
	t.Helper()
	db, env = newDB(t)
	key := writeKeyFile(t, 0o600, newKey(t))
	env = append(env, "CLAMFLEET_SERVER_SECRET_KEY_FILE="+key)
	return db, append(env, extra...)
}

func auditRows(t *testing.T, db string) string {
	t.Helper()
	raw := openRawDB(t, db)
	defer raw.Close()
	rows, err := raw.Query(`SELECT action || ' ' || actor_kind || ' ' || actor || ' ' || target || ' ' || COALESCE(detail, '') FROM audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var s string
		rows.Scan(&s)
		b.WriteString(s + "\n")
	}
	return b.String()
}

// Mutation 35: the CLI accepts a positional URL, or a usage or validation error
// echoes it.
func TestAlertAddWebhookNeverTakesTheURLAsAnArgument(t *testing.T) {
	db, env := alertCLIEnv(t, "CLAMFLEET_SERVER_ALERT_WEBHOOK_ALLOW_LOOPBACK=true")
	const marker = "TOKEN-MARKER"
	for name, args := range map[string][]string{
		"positional":       {"alert", "add-webhook", "ops", "https://hooks.example/T/" + marker},
		"positional first": {"alert", "add-webhook", "https://hooks.example/T/" + marker, "ops"},
		"as a flag value":  {"alert", "add-webhook", "ops", "--url=https://hooks.example/T/" + marker},
		"bool flag value":  {"alert", "add-webhook", "ops", "--url-stdin=https://hooks.example/T/" + marker},
		"short flag":       {"alert", "add-webhook", "ops", "-u", "https://hooks.example/T/" + marker},
	} {
		r := runServerStdin(t, env, "", args...)
		if r.code != 2 {
			t.Errorf("%s: exit %d, want 2\n%s", name, r.code, r.stderr)
		}
		if strings.Contains(r.stdout+r.stderr, marker) {
			t.Errorf("%s: the URL was echoed:\nstdout %q\nstderr %q", name, r.stdout, r.stderr)
		}
	}
	if strings.Contains(auditRows(t, db), marker) {
		t.Fatal("the URL reached the audit log")
	}
	// No source, or both: usage errors too.
	if r := runServerStdin(t, env, "", "alert", "add-webhook", "ops"); r.code != 2 {
		t.Errorf("no URL source: %d", r.code)
	}
	if r := runServerStdin(t, env, "", "alert", "add-webhook", "ops", "--url-stdin", "--url-file", "/x"); r.code != 2 {
		t.Errorf("both sources: %d", r.code)
	}
}

func TestAlertAddWebhookFromStdinAndFile(t *testing.T) {
	db, env := alertCLIEnv(t, "CLAMFLEET_SERVER_ALERT_WEBHOOK_ALLOW_LOOPBACK=true")
	r := runServerStdin(t, env, "http://127.0.0.1:9/hook/TOKEN-MARKER\n", "alert", "add-webhook", "ops", "--url-stdin", "--min-severity", "CRIT", "--tags", "prod, web")
	if r.code != 0 || !regexpKey.MatchString(r.stdout) {
		t.Fatalf("stdout must be exactly one whsec_ line: %+v", r)
	}
	if strings.Contains(r.stderr, "TOKEN-MARKER") {
		t.Fatalf("the URL reached stderr:\n%s", r.stderr)
	}
	// From a file: mode 0600 works, 0644 is refused.
	dir := t.TempDir()
	good, bad := filepath.Join(dir, "url"), filepath.Join(dir, "url-open")
	for p, mode := range map[string]os.FileMode{good: 0o600, bad: 0o644} {
		if err := os.WriteFile(p, []byte("http://127.0.0.1:9/hook/FILE-MARKER\n"), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
	}
	if r := runServerStdin(t, env, "", "alert", "add-webhook", "viafile", "--url-file", good); r.code != 0 || !regexpKey.MatchString(r.stdout) {
		t.Fatalf("%+v", r)
	}
	if r := runServerStdin(t, env, "", "alert", "add-webhook", "open", "--url-file", bad); r.code != 1 || !strings.Contains(r.stderr, "mode 0644") || strings.Contains(r.stderr, "FILE-MARKER") {
		t.Fatalf("%+v", r)
	}
	// The stored row: sealed, no marker anywhere in the database file or the audit log.
	for _, m := range []string{"TOKEN-MARKER", "FILE-MARKER"} {
		for _, suffix := range []string{"", "-wal"} {
			if b, err := os.ReadFile(db + suffix); err == nil && bytes.Contains(b, []byte(m)) {
				t.Errorf("%s in the database%s", m, suffix)
			}
		}
		if strings.Contains(auditRows(t, db), m) {
			t.Errorf("%s in the audit log", m)
		}
	}
	list := runServer(t, env, "alert", "list", "--json")
	var entries []alertListEntry
	if list.code != 0 || json.Unmarshal([]byte(list.stdout), &entries) != nil || len(entries) != 2 {
		t.Fatalf("%+v", list)
	}
	if entries[1].Name != "viafile" && entries[0].Name != "ops" {
		t.Fatalf("%+v", entries)
	}
	var ops alertListEntry
	for _, e := range entries {
		if e.Name == "ops" {
			ops = e
		}
	}
	if ops.Type != "webhook" || ops.Destination != "http://127.0.0.1:9/…" || ops.MinSeverity != "CRIT" || len(ops.Tags) != 2 || ops.Tags[1] != "web" || !ops.Enabled {
		t.Fatalf("%+v", ops)
	}
	if strings.Contains(list.stdout, "MARKER") {
		t.Fatal("alert list shows a URL path")
	}
	if a := auditRows(t, db); !strings.Contains(a, "alert_target.add cli alice") || !strings.Contains(a, `{"type":"webhook"}`) {
		t.Fatalf("audit rows must carry the OS actor:\n%s", a)
	}
}

var regexpKey = func() interface{ MatchString(string) bool } { return keyLine{} }()

type keyLine struct{}

func (keyLine) MatchString(s string) bool {
	if !strings.HasSuffix(s, "\n") || strings.Count(s, "\n") != 1 || !strings.HasPrefix(s, "whsec_") {
		return false
	}
	_, err := alert.DecodeSigningKey(strings.TrimSpace(s))
	return err == nil
}

func TestAlertAddWebhookRefusals(t *testing.T) {
	const marker = "TOKEN-MARKER"
	_, env := alertCLIEnv(t) // loopback NOT allowed
	for name, in := range map[string]string{
		"loopback":    "http://127.0.0.1:9/" + marker + "\n",
		"localhost":   "http://localhost:9/" + marker + "\n",
		"metadata":    "http://169.254.169.254/" + marker + "\n",
		"userinfo":    "https://u:p@hooks.example/" + marker + "\n",
		"ftp":         "ftp://hooks.example/" + marker + "\n",
		"public http": "http://203.0.113.5/" + marker + "\n",
		"empty":       "\n",
	} {
		r := runServerStdin(t, env, in, "alert", "add-webhook", "x", "--url-stdin")
		if r.code != 1 || r.stdout != "" || strings.Contains(r.stderr, marker) {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// Without a key file: exit 1 with the hint.
	db, env2 := newDB(t)
	r := runServerStdin(t, env2, "https://hooks.example/x\n", "alert", "add-webhook", "x", "--url-stdin")
	if r.code != 1 || !strings.Contains(r.stderr, "key generate") || r.stdout != "" {
		t.Fatalf("%+v", r)
	}
	_ = db
	// A duplicate name.
	_, env3 := alertCLIEnv(t)
	if r := runServerStdin(t, env3, "https://hooks.example/x\n", "alert", "add-webhook", "dup", "--url-stdin"); r.code != 0 {
		t.Fatal(r)
	}
	if r := runServerStdin(t, env3, "https://hooks.example/x\n", "alert", "add-webhook", "dup", "--url-stdin"); r.code != 1 || r.stdout != "" {
		t.Fatalf("%+v", r)
	}
}

func TestAlertEmailLogTestDelete(t *testing.T) {
	srv, err := testsmtp.Listen("127.0.0.1:0", testsmtp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	host, port, _ := strings.Cut(srv.Addr, ":")
	var mu sync.Mutex
	status := 204
	rcv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		w.WriteHeader(status)
		mu.Unlock()
	}))
	defer rcv.Close()
	db, env := alertCLIEnv(t, "CLAMFLEET_SERVER_ALERT_WEBHOOK_ALLOW_LOOPBACK=true",
		"CLAMFLEET_SERVER_SMTP_HOST="+host, "CLAMFLEET_SERVER_SMTP_PORT="+port, "CLAMFLEET_SERVER_SMTP_TLS=none", "CLAMFLEET_SERVER_SMTP_FROM=cf@test.example")

	if r := runServer(t, env, "alert", "add-email", "mail", "--to", "a@x.example,b@x.example"); r.code != 0 || r.stdout != "" {
		t.Fatalf("%+v", r)
	}
	if r := runServer(t, env, "alert", "add-email", "bad", "--to", "nope"); r.code != 1 {
		t.Fatalf("%+v", r)
	}
	if r := runServer(t, env, "alert", "add-email", "x"); r.code != 2 {
		t.Fatalf("missing --to: %+v", r)
	}
	// Email is refused while smtp.host is empty.
	if r := runServer(t, append(env, "CLAMFLEET_SERVER_SMTP_HOST="), "alert", "add-email", "off", "--to", "a@x.example"); r.code != 1 || !strings.Contains(r.stderr, "smtp.host") {
		t.Fatalf("%+v", r)
	}
	if r := runServerStdin(t, env, rcv.URL+"/hook\n", "alert", "add-webhook", "ops", "--url-stdin"); r.code != 0 {
		t.Fatalf("%+v", r)
	}

	// test: exit 0 against a loopback receiver, one line per recipient for email.
	if r := runServer(t, env, "alert", "test", "ops"); r.code != 0 || !strings.Contains(r.stdout, "delivered: HTTP 204") {
		t.Fatalf("%+v", r)
	}
	mt := runServer(t, env, "alert", "test", "mail")
	if mt.code != 0 || strings.Count(mt.stdout, "delivered ") != 2 || len(srv.Messages()) != 2 {
		t.Fatalf("%+v", mt)
	}
	mu.Lock()
	status = 404
	mu.Unlock()
	if r := runServer(t, env, "alert", "test", "ops"); r.code != 1 || !strings.Contains(r.stdout, "failed: HTTP 404") {
		t.Fatalf("a 404 must exit 1: %+v", r)
	}
	if r := runServer(t, env, "alert", "test", "ghost"); r.code != 1 {
		t.Fatalf("%+v", r)
	}
	// With loopback off the test is blocked and says so.
	if r := runServer(t, append(env, "CLAMFLEET_SERVER_ALERT_WEBHOOK_ALLOW_LOOPBACK=false"), "alert", "test", "ops"); r.code != 1 || !strings.Contains(r.stdout, "blocked") {
		t.Fatalf("%+v", r)
	}

	lg := runServer(t, env, "alert", "log", "--json", "--target", "ops")
	var entries []alertLogJSON
	if lg.code != 0 || json.Unmarshal([]byte(lg.stdout), &entries) != nil || len(entries) != 3 {
		t.Fatalf("%+v", lg)
	}
	if entries[len(entries)-1].Status != "test_sent" || entries[0].Status != "test_failed" || entries[0].Kind != "test" {
		t.Fatalf("%+v", entries)
	}
	if r := runServer(t, env, "alert", "log", "--limit", "1"); r.code != 0 || strings.Count(strings.TrimSpace(r.stdout), "\n") != 1 {
		t.Fatalf("%+v", r)
	}

	// delete needs --yes.
	if r := runServer(t, env, "alert", "delete", "ops"); r.code != 2 {
		t.Fatalf("%+v", r)
	}
	if r := runServer(t, env, "alert", "delete", "ops", "--yes"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if r := runServer(t, env, "alert", "delete", "ops", "--yes"); r.code != 1 {
		t.Fatalf("a second delete: %+v", r)
	}
	list := runServer(t, env, "alert", "list")
	if list.code != 0 || strings.Contains(list.stdout, "ops") || !strings.Contains(list.stdout, "a@x.example,b@x.example") {
		t.Fatalf("%+v", list)
	}
	// Every change is audited with the OS actor (cli).
	a := auditRows(t, db)
	for _, want := range []string{"alert_target.add cli ", "alert_target.test cli ", "alert_target.delete cli "} {
		if !strings.Contains(a, want) {
			t.Errorf("audit lacks %q:\n%s", want, a)
		}
	}
	for _, bad := range []string{"unknown", "x"} {
		if r := runServer(t, env, "alert", bad); r.code != 2 {
			t.Errorf("alert %s: %d", bad, r.code)
		}
	}
}

// An extra positional argument next to --url-stdin is a usage error, and it is
// not echoed (it could be the URL typed in the wrong place).
func TestAlertAddWebhookExtraArgumentWithURLStdinIsUsageError(t *testing.T) {
	_, env := alertCLIEnv(t)
	const marker = "TOKEN-MARKER"
	r := runServerStdin(t, env, "https://hooks.example/ok\n", "alert", "add-webhook", "ops", "https://hooks.example/"+marker, "--url-stdin")
	if r.code != 2 || strings.Contains(r.stdout+r.stderr, marker) || r.stdout != "" {
		t.Fatalf("%+v", r)
	}
	if l := runServer(t, env, "alert", "list", "--json"); strings.TrimSpace(l.stdout) != "[]" {
		t.Fatalf("a target was created: %s", l.stdout)
	}
}

// The CLI validates exactly as the console does (shared parsers): tags with
// control characters or over 64 characters are refused, and duplicate
// recipients are stored once.
func TestAlertCLIUsesTheConsoleValidation(t *testing.T) {
	srv, err := testsmtp.Listen("127.0.0.1:0", testsmtp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	host, port, _ := strings.Cut(srv.Addr, ":")
	_, env := alertCLIEnv(t, "CLAMFLEET_SERVER_SMTP_HOST="+host, "CLAMFLEET_SERVER_SMTP_PORT="+port, "CLAMFLEET_SERVER_SMTP_TLS=none", "CLAMFLEET_SERVER_SMTP_FROM=cf@test.example")
	for name, tags := range map[string]string{"too long": strings.Repeat("a", 65), "control": "a\x07b"} {
		if r := runServer(t, env, "alert", "add-email", "m"+name[:1], "--to", "a@x.example", "--tags", tags); r.code != 2 {
			t.Errorf("tags %s: exit %d, want 2", name, r.code)
		}
	}
	if r := runServer(t, env, "alert", "add-email", "dup", "--to", "a@x.example,A@X.example, a@x.example"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	l := runServer(t, env, "alert", "list", "--json")
	var es []alertListEntry
	if json.Unmarshal([]byte(l.stdout), &es) != nil || len(es) != 1 || es[0].Destination != "a@x.example" {
		t.Fatalf("duplicates must collapse to one recipient: %s", l.stdout)
	}
}
