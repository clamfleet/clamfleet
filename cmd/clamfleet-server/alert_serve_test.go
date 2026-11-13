// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Tests of what `serve` does with the alerting configuration and secrets, with
// the real binaries: refusals at start, start-up with an unreadable webhook
// secret, and the dispatcher actually running inside serve (a webhook arrives,
// signed, after the real agent reports a non-OK state).
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/alert"
	"github.com/clamfleet/clamfleet/internal/secrets"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
	"github.com/clamfleet/clamfleet/internal/testtls"
)

func TestServeRefusesBadAlertConfiguration(t *testing.T) {
	pw := func(mode os.FileMode) string {
		p := filepath.Join(t.TempDir(), "smtp.pass")
		if err := os.WriteFile(p, []byte("hunter2\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	smtp := func(extra ...string) []string {
		return append([]string{"CLAMFLEET_SERVER_SMTP_HOST=relay.example", "CLAMFLEET_SERVER_SMTP_FROM=cf@example.org"}, extra...)
	}
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"tls none to a public literal", smtp("CLAMFLEET_SERVER_SMTP_HOST=203.0.113.5", "CLAMFLEET_SERVER_SMTP_TLS=none"), "public"},
		{"tls none with credentials to a private relay", smtp("CLAMFLEET_SERVER_SMTP_HOST=10.0.0.25", "CLAMFLEET_SERVER_SMTP_TLS=none",
			"CLAMFLEET_SERVER_SMTP_USERNAME=u", "CLAMFLEET_SERVER_SMTP_PASSWORD_FILE="+pw(0o600)), "clear"},
		{"password file readable by others", smtp("CLAMFLEET_SERVER_SMTP_USERNAME=u", "CLAMFLEET_SERVER_SMTP_PASSWORD_FILE="+pw(0o644)), "mode 0644"},
		{"password file missing", smtp("CLAMFLEET_SERVER_SMTP_USERNAME=u", "CLAMFLEET_SERVER_SMTP_PASSWORD_FILE=/nonexistent/smtp.pass"), "smtp.password_file"},
		{"invalid public_url", []string{"CLAMFLEET_SERVER_PUBLIC_URL=clamfleet.example"}, "public_url"},
		{"invalid deny_networks entry", []string{"CLAMFLEET_SERVER_ALERT_WEBHOOK_DENY_NETWORKS=10.0.0.0/99"}, "deny_networks"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db, _ := newDB(t)
			r := serveRefuses(t, db, c.env...)
			if r.code != 1 || !strings.Contains(r.stderr, c.want) {
				t.Fatalf("%+v", r)
			}
			if strings.Contains(r.stderr, "hunter2") {
				t.Fatalf("the password reached the log:\n%s", r.stderr)
			}
		})
	}
}

// seedWebhookTarget creates a webhook target whose secret is sealed with ring
// and returns the signing key (whsec_...).
func seedWebhookTarget(t *testing.T, db, name, hookURL string, ring *secrets.Keyring, edit func(*store.NewAlertTarget)) string {
	t.Helper()
	ctx := context.Background()
	st, err := sqlite.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key, err := alert.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	nt := store.NewAlertTarget{Name: name, Type: store.TargetTypeWebhook, Config: []byte(`{"url_display":"x"}`), MinSeverity: "WARN",
		SendStateChanges: true, SendDetections: true, Enabled: true}
	if edit != nil {
		edit(&nt)
	}
	_, err = st.CreateAlertTarget(ctx, nt, func(id int64) ([]byte, error) {
		plain, _ := alert.WebhookSecret{URL: hookURL, SigningKey: key}.Marshal()
		return ring.Seal(secrets.PurposeAlertTarget, plain, uint64(id))
	}, time.Now(), testAudit)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Decision 10: an alert-target secret the key cannot open does NOT stop the
// server (email and the other targets keep working); it logs the count and the fix.
func TestServeStartsWithAnUnopenableWebhookSecret(t *testing.T) {
	tlsb, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, _ := newDB(t)
	sealedWith := loadRing(t, writeKeyFile(t, 0o600, newKey(t)))
	seedWebhookTarget(t, db, "ops", "https://hooks.example/T/TOKEN-MARKER", sealedWith, nil)
	other := writeKeyFile(t, 0o600, newKey(t))
	s := startServe(t, tlsb, db, "CLAMFLEET_SERVER_SECRET_KEY_FILE="+other)
	out := s.stderr.String()
	if !strings.Contains(out, "webhook alert targets cannot be opened") || !strings.Contains(out, `"unreadable":1`) {
		t.Fatalf("no start-up error naming the count:\n%s", out)
	}
	if strings.Contains(out, "TOKEN-MARKER") {
		t.Fatal("the webhook URL reached the log")
	}
	// No key file at all: starts too.
	db2, _ := newDB(t)
	seedWebhookTarget(t, db2, "ops", "https://hooks.example/T", sealedWith, nil)
	s2 := startServe(t, tlsb, db2)
	if !strings.Contains(s2.stderr.String(), `"unreadable":1`) {
		t.Fatalf("no key file:\n%s", s2.stderr.String())
	}
}

type hookHit struct {
	header http.Header
	body   string
}

// Mutation 43: unwire the dispatcher from serve. With a webhook target and the
// real agent reporting a down clamd, the receiver gets one signed alert within
// 10 s (the real 5 s ticker).
func TestServeDeliversAnAlertWhenTheAgentReportsAProblem(t *testing.T) {
	var mu sync.Mutex
	var hits []hookHit
	rcv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		hits = append(hits, hookHit{r.Header.Clone(), string(b)})
		mu.Unlock()
		w.WriteHeader(204)
	}))
	defer rcv.Close()

	tlsb, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, _ := newDB(t)
	keyPath := writeKeyFile(t, 0o600, newKey(t))
	signing := seedWebhookTarget(t, db, "ops", rcv.URL+"/hook/TOKEN-MARKER", loadRing(t, keyPath), nil)
	srv := startServe(t, tlsb, db, "CLAMFLEET_SERVER_SECRET_KEY_FILE="+keyPath,
		"CLAMFLEET_SERVER_ALERT_WEBHOOK_ALLOW_LOOPBACK=true", "CLAMFLEET_SERVER_PUBLIC_URL=https://cf.example")
	reg := runServer(t, srv.env, "host", "add", "web01")
	if reg.code != 0 {
		t.Fatal(reg)
	}
	ag := newAgent(t, srv.addr, tlsb.CA, "")
	ag.token(strings.TrimSpace(reg.stdout))
	if res := ag.runOnce(); res.code != 0 {
		t.Fatalf("agent: %+v", res)
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(hits)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hits) != 1 {
		t.Fatalf("%d webhook requests, want exactly 1\n%s", len(hits), srv.stderr.String())
	}
	var p alert.StateChangePayload
	if err := json.Unmarshal([]byte(hits[0].body), &p); err != nil || p.Kind != "state_change" || p.Host != "web01" || p.From != nil || p.URL == nil || *p.URL != "https://cf.example/hosts/web01" {
		t.Fatalf("%+v %v", p, err)
	}
	if p.To != "CRIT" && p.To != "WARN" {
		t.Fatalf("to %s", p.To)
	}
	key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(signing, "whsec_"))
	ts, _ := strconv.ParseInt(hits[0].header.Get("webhook-timestamp"), 10, 64)
	if !alert.VerifySignature(key, hits[0].header.Get("webhook-id"), ts, []byte(hits[0].body), hits[0].header.Get("webhook-signature")) {
		t.Fatalf("the signature does not verify: %v", hits[0].header)
	}
	if strings.Contains(srv.stderr.String(), "TOKEN-MARKER") {
		t.Fatal("the URL path reached the server log")
	}
}
