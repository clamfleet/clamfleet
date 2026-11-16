// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/testtls"
)

const secret = "cfa_TESTTOKENTESTTOKENTESTTOKENTESTTOKENTESTTOK"

type captured struct {
	method, path, auth, ctype, ua string
	body                          []byte
}

// fakeServer is a loopback TLS server (httptest.NewTLSServer binds 127.0.0.1)
// that records requests and answers with the configured status and body.
type fakeServer struct {
	*httptest.Server
	mu     sync.Mutex
	reqs   []captured
	status int
	reply  string
}

func newFake(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{status: 202, reply: "{}"}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, captured{r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Header.Get("User-Agent"), b})
		st, rep := f.status, f.reply
		f.mu.Unlock()
		w.WriteHeader(st)
		io.WriteString(w, rep)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeServer) set(status int, reply string) {
	f.mu.Lock()
	f.status, f.reply = status, reply
	f.mu.Unlock()
}

func (f *fakeServer) requests() []captured {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]captured(nil), f.reqs...)
}

func tokenFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func senderFor(t *testing.T, f *fakeServer, prefix, tokPath string, log *slog.Logger) *Sender {
	t.Helper()
	u, _ := url.Parse(f.URL + prefix)
	return &Sender{Server: u, TokenFile: tokPath, Client: f.Client(), UserAgent: "clamfleet-agent/test", Log: log}
}

func TestSendRequestIsExact(t *testing.T) {
	f := newFake(t)
	s := senderFor(t, f, "/prefix", tokenFile(t, secret+"\n"), nil)
	rep := proto.Report{Schema: 1, Host: "app01", Tags: []string{"x"}}
	body, _ := json.Marshal(rep)
	resp, err := s.Send(context.Background(), "v1/report", body)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != "{}" {
		t.Fatalf("response %q", resp)
	}
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests", len(reqs))
	}
	r := reqs[0]
	if r.method != "POST" || r.path != "/prefix/v1/report" {
		t.Fatalf("%s %s: the reverse-proxy prefix must be kept", r.method, r.path)
	}
	if r.auth != "Bearer "+secret {
		t.Fatalf("Authorization %q (the trailing newline of the token file must be trimmed)", r.auth)
	}
	if r.ctype != "application/json" || r.ua != "clamfleet-agent/test" {
		t.Fatalf("headers: %q %q", r.ctype, r.ua)
	}
	var got proto.Report
	if err := json.Unmarshal(r.body, &got); err != nil || got.Host != "app01" {
		t.Fatalf("body: %v %s", err, r.body)
	}
}

// A rotated token must work without restarting the agent.
func TestSendRereadsTokenFileEverySend(t *testing.T) {
	f := newFake(t)
	p := tokenFile(t, "cfa_first")
	s := senderFor(t, f, "", p, nil)
	for _, tok := range []string{"cfa_first", "cfa_second"} {
		if err := os.WriteFile(p, []byte(tok), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Send(context.Background(), "v1/report", []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	reqs := f.requests()
	if reqs[0].auth != "Bearer cfa_first" || reqs[1].auth != "Bearer cfa_second" {
		t.Fatalf("auth headers: %q %q", reqs[0].auth, reqs[1].auth)
	}
}

func TestSendTokenFileProblems(t *testing.T) {
	f := newFake(t)
	dir := t.TempDir()
	cases := map[string]string{
		"missing":    filepath.Join(dir, "nope"),
		"empty":      tokenFile(t, "  \n"),
		"two lines":  tokenFile(t, secret+"\nmore"),
		"with space": tokenFile(t, "cfa_a b"),
		"control":    tokenFile(t, "cfa_a\x01b"),
		"non-ASCII":  tokenFile(t, "cfa_é"),
	}
	for name, p := range cases {
		_, err := senderFor(t, f, "", p, nil).Send(context.Background(), "v1/report", []byte("{}"))
		var se *SendError
		if !errors.As(err, &se) || se.Class != ClassToken {
			t.Errorf("%s: err = %v, want class token", name, err)
			continue
		}
		if !strings.Contains(err.Error(), p) {
			t.Errorf("%s: error does not name the path: %v", name, err)
		}
		for _, leak := range []string{secret, "cfa_a b", "more"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: error leaks token content: %v", name, err)
			}
		}
	}
	if n := len(f.requests()); n != 0 {
		t.Fatalf("%d requests were sent with a bad token file", n)
	}
}

func TestSendStatusClasses(t *testing.T) {
	f := newFake(t)
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	s := senderFor(t, f, "", tokenFile(t, secret), log)
	cases := []struct {
		status int
		reply  string
		class  Class
		text   string
	}{
		{401, `{"error":"unauthorized"}`, ClassUnauthorized, ""},
		{400, `{"error":"tags: at most 32 allowed, got 33"}`, ClassRejected, "tags: at most 32"},
		{413, `{"error":"request body exceeds 1048576 bytes"}`, ClassRejected, "exceeds"},
		{404, `not json`, ClassRejected, ""},
		{503, `{"error":"service unavailable"}`, ClassServer, "service unavailable"},
		{500, ``, ClassServer, ""},
		{302, ``, ClassRejected, ""},
	}
	for _, c := range cases {
		f.set(c.status, c.reply)
		_, err := s.Send(context.Background(), "v1/report", []byte("{}"))
		var se *SendError
		if !errors.As(err, &se) || se.Class != c.class || se.Status != c.status {
			t.Errorf("HTTP %d: err = %v, want class %s", c.status, err, c.class)
			continue
		}
		if c.text != "" && !strings.Contains(err.Error(), c.text) {
			t.Errorf("HTTP %d: the server's error text is missing: %v", c.status, err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("HTTP %d: token in error", c.status)
		}
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatal("token in log")
	}
}

// Forward compatibility: a success body may grow keys (tasks, later); the agent ignores them.
func TestSendAcceptsUnknownResponseKeys(t *testing.T) {
	f := newFake(t)
	f.set(202, `{"tasks":[{"id":1}],"future":true}`)
	resp, err := senderFor(t, f, "", tokenFile(t, secret), nil).Send(context.Background(), "v1/report", []byte("{}"))
	if err != nil || !strings.Contains(string(resp), "tasks") {
		t.Fatalf("%q %v", resp, err)
	}
}

// A redirect is never followed: Go would resend the bearer token to the target.
func TestSendDoesNotFollowRedirects(t *testing.T) {
	target := newFake(t)
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stolen", http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	// NewSender's client policy, with this test server's CA.
	built, err := NewSender(Config{Server: redir.URL, TokenFile: tokenFile(t, secret)}, "x", nil)
	if err != nil {
		t.Fatal(err)
	}
	built.Client.Transport.(*http.Transport).TLSClientConfig.RootCAs = poolOf(redir.Certificate())
	_, err = built.Send(context.Background(), "v1/report", []byte("{}"))
	var se *SendError
	if !errors.As(err, &se) || se.Class != ClassRejected || se.Status != 307 {
		t.Fatalf("err = %v", err)
	}
	if n := len(target.requests()); n != 0 {
		t.Fatalf("the redirect target received %d requests (and the token)", n)
	}
}

func poolOf(c *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c)
	return p
}

// The real client (NewSender) trusts the system store only: a test server's
// self-signed certificate must fail the handshake, not be accepted.
func TestSendUntrustedCertificateFails(t *testing.T) {
	f := newFake(t)
	s, err := NewSender(Config{Server: f.URL, TokenFile: tokenFile(t, secret)}, "x", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Send(context.Background(), "v1/report", []byte("{}"))
	var se *SendError
	if !errors.As(err, &se) || se.Class != ClassNetwork {
		t.Fatalf("err = %v, want class network", err)
	}
	if n := len(f.requests()); n != 0 {
		t.Fatalf("%d requests reached a server with an untrusted certificate", n)
	}
	if got := s.Client.Transport.(*http.Transport).TLSClientConfig.MinVersion; got != tls.VersionTLS12 {
		t.Fatalf("MinVersion %x", got)
	}
}

func TestSendWorldReadableTokenFileWarnsOnce(t *testing.T) {
	f := newFake(t)
	p := tokenFile(t, secret)
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	s := senderFor(t, f, "", p, slog.New(slog.NewTextHandler(&logs, nil)))
	for i := 0; i < 3; i++ {
		if _, err := s.Send(context.Background(), "v1/report", []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(logs.String(), "world-readable"); n != 1 {
		t.Fatalf("%d warnings, want 1:\n%s", n, logs.String())
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatal("token in log")
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	s2 := senderFor(t, f, "", p, slog.New(slog.NewTextHandler(&logs, nil)))
	s2.Send(context.Background(), "v1/report", []byte("{}"))
	if logs.Len() != 0 {
		t.Fatalf("a 0640 token file warned: %s", logs.String())
	}
}

// mTLS (M2 decision 11): the agent presents its client certificate; without one
// the server's handshake fails.
func TestSendPresentsClientCertificate(t *testing.T) {
	dir := t.TempDir()
	b, err := testtls.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(b.CA)
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(caPEM)
	var mu sync.Mutex
	var cn string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cn = r.TLS.PeerCertificates[0].Subject.CommonName
		mu.Unlock()
		w.WriteHeader(202)
		io.WriteString(w, "{}")
	}))
	cert, _ := tls.LoadX509KeyPair(b.Cert, b.Key)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
	srv.StartTLS()
	defer srv.Close()

	tok := tokenFile(t, secret)
	with, err := NewSender(Config{Server: srv.URL, TokenFile: tok, TLS: TLS{ClientCert: b.ClientCert, ClientKey: b.ClientKey}}, "x", nil)
	if err != nil {
		t.Fatal(err)
	}
	with.Client.Transport.(*http.Transport).TLSClientConfig.RootCAs = clientCAs // the test CA is also the server CA
	if _, err := with.Send(context.Background(), "v1/report", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if cn != "clamfleet test agent" {
		t.Fatalf("server saw client certificate %q", cn)
	}
	mu.Unlock()

	without, _ := NewSender(Config{Server: srv.URL, TokenFile: tok}, "x", nil)
	without.Client.Transport.(*http.Transport).TLSClientConfig.RootCAs = clientCAs
	if _, err := without.Send(context.Background(), "v1/report", []byte("{}")); err == nil {
		t.Fatal("a send without a client certificate succeeded against an mTLS server")
	}

	// An unusable pair fails at start, not at the first send.
	if _, err := NewSender(Config{Server: srv.URL, TokenFile: tok, TLS: TLS{ClientCert: b.ClientCert, ClientKey: b.Key}}, "x", nil); err == nil {
		t.Fatal("mismatched cert and key accepted")
	}
}
