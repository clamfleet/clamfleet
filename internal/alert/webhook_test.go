// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package alert

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The published Standard Webhooks vector: secret, message id and payload are the
// constants of the standard-webhooks libraries' own tests
// (github.com/standard-webhooks/standard-webhooks, libraries/python/tests); the
// spec text itself gives no secret. The timestamp is fixed here (the libraries
// use the current time) and the expected signature was computed with Python's
// hmac and base64 modules, which share no code with Sign. NOTE: the secret
// decodes to 24 bytes, the spec's minimum.
const (
	vecSecret = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	vecID     = "msg_p5jXN8AQM9LWM0D4loKWxJek"
	vecBody   = `{"test": 2432232314}`
	vecTS     = 1614265330
	vecSig    = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
)

func TestSignMatchesPublishedVector(t *testing.T) {
	key, err := base64.StdEncoding.DecodeString(vecSecret)
	if err != nil {
		t.Fatal(err)
	}
	if got := Sign(key, vecID, vecTS, []byte(vecBody)); got != vecSig {
		t.Fatalf("got %s, want %s", got, vecSig)
	}
	// DecodeSigningKey of the whsec_ form yields the same bytes.
	k2, err := DecodeSigningKey("whsec_" + vecSecret)
	if err != nil || Sign(k2, vecID, vecTS, []byte(vecBody)) != vecSig {
		t.Fatalf("whsec_ form: %v", err)
	}
}

// Mutation 29: HMAC keyed with the whsec_ string, over the body only, or
// without the timestamp. None of these verifies against the vector.
func TestSignatureVariantsDoNotVerify(t *testing.T) {
	key, _ := base64.StdEncoding.DecodeString(vecSecret)
	body := []byte(vecBody)
	if VerifySignature([]byte("whsec_"+vecSecret), vecID, vecTS, body, vecSig) {
		t.Fatal("a signature keyed with the whsec_ string verified")
	}
	if VerifySignature([]byte(vecSecret), vecID, vecTS, body, vecSig) {
		t.Fatal("a signature keyed with the base64 text verified")
	}
	if !VerifySignature(key, vecID, vecTS, body, vecSig) {
		t.Fatal("the vector does not verify")
	}
	for name, bad := range map[string]func() bool{
		"other timestamp": func() bool { return VerifySignature(key, vecID, vecTS+1, body, vecSig) },
		"other id":        func() bool { return VerifySignature(key, "msg_x", vecTS, body, vecSig) },
		"other body":      func() bool { return VerifySignature(key, vecID, vecTS, []byte(vecBody+" "), vecSig) },
		"empty header":    func() bool { return VerifySignature(key, vecID, vecTS, body, "") },
	} {
		if bad() {
			t.Errorf("%s verified", name)
		}
	}
	// Several space-separated entries: any one matching is enough.
	if !VerifySignature(key, vecID, vecTS, body, "v1,AAAA "+vecSig+" v1a,zzzz") {
		t.Fatal("a multi-signature header must verify when one entry matches")
	}
}

// ---------------------------------------------------------------- fixtures

var t0wh = time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return t0wh }

type receiver struct {
	srv  *httptest.Server
	hits atomic.Int64
	mu   sync.Mutex
	reqs []*recorded
}

type recorded struct {
	header http.Header
	body   string
}

func newReceiver(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *receiver {
	t.Helper()
	rc := &receiver{}
	rc.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		rc.mu.Lock()
		rc.reqs = append(rc.reqs, &recorded{header: r.Header.Clone(), body: string(b)})
		rc.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(rc.srv.Close)
	return rc
}

func (rc *receiver) addr() string { return strings.TrimPrefix(rc.srv.URL, "http://") }
func (rc *receiver) port() string { _, p, _ := net.SplitHostPort(rc.addr()); return p }

func testSecret(t *testing.T, url string) WebhookSecret {
	t.Helper()
	k, err := NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return WebhookSecret{URL: url, SigningKey: k}
}

func sender(p Policy) *WebhookSender {
	return &WebhookSender{Policy: p, Timeout: 2 * time.Second, Now: fixedNow, Version: "test"}
}

// scriptedResolver answers each lookup from a list (the last answer repeats).
type scriptedResolver struct {
	mu      sync.Mutex
	answers [][]netip.Addr
	calls   int
}

func (r *scriptedResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := min(r.calls, len(r.answers)-1)
	r.calls++
	return r.answers[i], nil
}

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// recordingDial records every address it is asked to connect to and connects
// the ones in `fail` with a refusal; everything else goes to the receiver.
type recordingDial struct {
	mu    sync.Mutex
	asked []string
	fail  map[string]bool
	to    string // the receiver's real address
}

func (d *recordingDial) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(address)
	d.mu.Lock()
	d.asked = append(d.asked, host)
	refuse := d.fail[host]
	d.mu.Unlock()
	if refuse {
		return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	}
	return (&net.Dialer{}).DialContext(ctx, network, d.to)
}

func (d *recordingDial) list() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.Join(d.asked, ",")
}

func hookURL(rc *receiver, host string) string {
	return "http://" + host + ":" + rc.port() + "/hook/TOKEN-MARKER"
}

// ------------------------------------------------- resolver and dialer tests

// Mutation 22: handing the hostname to net.Dialer. In every case the recorded
// list contains zero forbidden addresses.
func TestWebhookResolveFilterDial(t *testing.T) {
	body := []byte(`{"schema":1}`)
	cases := []struct {
		name    string
		policy  Policy
		answers [][]netip.Addr
		fail    map[string]bool
		wantDia string
		want    Outcome
		code    string
	}{
		{"mixed answers, loopback off", Policy{AllowPrivate: true}, [][]netip.Addr{addrs("127.0.0.1", "10.0.0.5")}, nil, "10.0.0.5", OutcomeSent, ""},
		{"only forbidden answers", Policy{AllowPrivate: true}, [][]netip.Addr{addrs("169.254.169.254", "::1")}, nil, "", OutcomePermanent, "blocked"},
		{"metadata in a mixed answer", Policy{AllowPrivate: true}, [][]netip.Addr{addrs("100.100.100.200", "10.0.0.5")}, nil, "10.0.0.5", OutcomeSent, ""},
		{"4in6 loopback and metadata", Policy{AllowPrivate: true}, [][]netip.Addr{addrs("::ffff:127.0.0.1", "::ffff:100.100.100.200")}, nil, "", OutcomePermanent, "blocked"},
		{"fallback to the second address", Policy{AllowPrivate: true}, [][]netip.Addr{addrs("fd00::5", "10.0.0.5")}, map[string]bool{"fd00::5": true}, "fd00::5,10.0.0.5", OutcomeSent, ""},
		{"fallback never reaches a forbidden one", Policy{AllowPrivate: true}, [][]netip.Addr{addrs("fd00::5", "127.0.0.1")}, map[string]bool{"fd00::5": true}, "fd00::5", OutcomeRetry, "connection refused"},
		{"plaintext to a public address", Policy{AllowPrivate: true}, [][]netip.Addr{addrs("203.0.113.5")}, nil, "", OutcomePermanent, "plaintext"},
		{"private answers with allow_private off", Policy{}, [][]netip.Addr{addrs("10.0.0.5")}, nil, "", OutcomePermanent, "blocked"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rc := newReceiver(t, nil)
			d := &recordingDial{fail: c.fail, to: rc.addr()}
			s := sender(c.policy)
			s.Resolver, s.Dial = &scriptedResolver{answers: c.answers}, d.dial
			r := s.Send(context.Background(), testSecret(t, hookURL(rc, "receiver.example")), "id1", body)
			if r.Outcome != c.want || (c.code != "" && r.Code != c.code) {
				t.Fatalf("%+v", r)
			}
			if d.list() != c.wantDia {
				t.Fatalf("dialled %q, want %q", d.list(), c.wantDia)
			}
			if c.want != OutcomeSent && rc.hits.Load() != 0 {
				t.Fatalf("the receiver was hit %d times", rc.hits.Load())
			}
			if strings.Contains(r.Text, "TOKEN-MARKER") {
				t.Fatalf("the result text leaks the URL: %q", r.Text)
			}
		})
	}
}

// Rebinding between connections: the first resolve gives a private address and
// the attempt is sent; the next delivery's resolve gives 127.0.0.1, which is
// blocked with zero dials to it.
func TestWebhookRebindingIsFilteredPerConnection(t *testing.T) {
	rc := newReceiver(t, nil)
	d := &recordingDial{to: rc.addr()}
	s := sender(Policy{AllowPrivate: true})
	s.Resolver, s.Dial = &scriptedResolver{answers: [][]netip.Addr{addrs("10.0.0.5"), addrs("127.0.0.1")}}, d.dial
	sec := testSecret(t, hookURL(rc, "receiver.example"))
	if r := s.Send(context.Background(), sec, "a", []byte(`{}`)); r.Outcome != OutcomeSent {
		t.Fatalf("first: %+v", r)
	}
	if r := s.Send(context.Background(), sec, "b", []byte(`{}`)); r.Outcome != OutcomePermanent || r.Code != "blocked" {
		t.Fatalf("second: %+v", r)
	}
	if d.list() != "10.0.0.5" || rc.hits.Load() != 1 {
		t.Fatalf("dialled %q, hits %d: the rebound address must never be dialled", d.list(), rc.hits.Load())
	}
}

// Mutation 23: without ControlContext a dial function that ignores the filtered
// list and connects to loopback anyway would get through.
func TestWebhookSecondLayerStopsABypass(t *testing.T) {
	rc := newReceiver(t, nil)
	p := Policy{AllowPrivate: true} // loopback off
	hostile := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return NetDialer(p, true, time.Second).DialContext(ctx, network, rc.addr()) // the real receiver, on 127.0.0.1
	}
	s := sender(p)
	s.Resolver, s.Dial = &scriptedResolver{answers: [][]netip.Addr{addrs("10.0.0.5")}}, hostile
	r := s.Send(context.Background(), testSecret(t, hookURL(rc, "receiver.example")), "id", []byte(`{}`))
	if r.Outcome != OutcomePermanent || r.Code != "blocked" || rc.hits.Load() != 0 {
		t.Fatalf("%+v hits=%d", r, rc.hits.Load())
	}
}

// ------------------------------------------------- real resolver, real sockets

func TestWebhookLoopbackBlockedByDefault(t *testing.T) {
	rc := newReceiver(t, nil)
	for _, host := range []string{"127.0.0.1", "localhost"} {
		r := sender(Policy{AllowPrivate: true}).Send(context.Background(), testSecret(t, hookURL(rc, host)), "id", []byte(`{}`))
		if r.Outcome != OutcomePermanent || r.Code != "blocked" {
			t.Fatalf("%s: %+v", host, r)
		}
	}
	if rc.hits.Load() != 0 {
		t.Fatalf("hits = %d", rc.hits.Load())
	}
	// localhost through the system resolver (/etc/hosts) is blocked by the
	// address filter alone, with the save-time name rule out of the picture.
	d := &SafeDialer{Policy: Policy{AllowPrivate: true}, Timeout: time.Second}
	if c, err := d.DialContext(context.Background(), "tcp", "localhost:"+rc.port()); err == nil {
		c.Close()
		t.Fatal("localhost was dialled")
	} else if _, ok := err.(*PermanentError); !ok {
		t.Fatalf("want a permanent block, got %v", err)
	}
}

func TestWebhookClassificationOverRealHTTP(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header map[string]string
		want   Outcome
		code   string
		retry  time.Duration
	}{
		{"204", 204, nil, OutcomeSent, "HTTP 204", 0},
		{"200", 200, nil, OutcomeSent, "HTTP 200", 0},
		{"503", 503, nil, OutcomeRetry, "HTTP 503", 0},
		{"404", 404, nil, OutcomePermanent, "HTTP 404", 0},
		{"429 Retry-After", 429, map[string]string{"Retry-After": "120"}, OutcomeRetry, "HTTP 429", 2 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rc := newReceiver(t, func(w http.ResponseWriter, r *http.Request) {
				for k, v := range c.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(c.status)
				io.WriteString(w, "SECRET-BODY-MARKER")
			})
			r := sender(Policy{AllowLoopback: true}).Send(context.Background(), testSecret(t, hookURL(rc, "127.0.0.1")), "id", []byte(`{}`))
			if r.Outcome != c.want || r.Code != c.code || r.RetryAfter != c.retry {
				t.Fatalf("%+v", r)
			}
			if strings.Contains(r.Text+r.Code, "SECRET-BODY-MARKER") {
				t.Fatalf("the response body reached the result: %+v", r)
			}
		})
	}
}

// Mutation 21: following redirects.
func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	second := newReceiver(t, nil)
	first := newReceiver(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.srv.URL+"/elsewhere", http.StatusFound)
	})
	r := sender(Policy{AllowLoopback: true}).Send(context.Background(), testSecret(t, hookURL(first, "127.0.0.1")), "id", []byte(`{}`))
	if r.Outcome != OutcomePermanent || r.Code != "HTTP 302" {
		t.Fatalf("%+v", r)
	}
	if second.hits.Load() != 0 {
		t.Fatal("the redirect was followed")
	}
}

func TestWebhookTimeoutIsARetry(t *testing.T) {
	rc := newReceiver(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(600 * time.Millisecond) })
	s := sender(Policy{AllowLoopback: true})
	s.Timeout = 200 * time.Millisecond
	r := s.Send(context.Background(), testSecret(t, hookURL(rc, "127.0.0.1")), "id", []byte(`{}`))
	if r.Outcome != OutcomeRetry || r.Code != "timeout" {
		t.Fatalf("%+v", r)
	}
}

func TestWebhookConnectionRefusedIsARetry(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	r := sender(Policy{AllowLoopback: true}).Send(context.Background(), testSecret(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/x"), "id", []byte(`{}`))
	if r.Outcome != OutcomeRetry || r.Code != "connection refused" {
		t.Fatalf("%+v", r)
	}
}

// Mutation 27: Proxy: http.ProxyFromEnvironment.
func TestWebhookIgnoresProxyEnvironment(t *testing.T) {
	proxy := newReceiver(t, nil)
	t.Setenv("HTTP_PROXY", proxy.srv.URL)
	t.Setenv("HTTPS_PROXY", proxy.srv.URL)
	t.Setenv("http_proxy", proxy.srv.URL)
	t.Setenv("https_proxy", proxy.srv.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	target := newReceiver(t, nil)
	// 127.0.0.1 is normally exempt from proxies in Go; a hostname that the
	// scripted resolver maps to loopback is not, so the proxy WOULD be used.
	s := sender(Policy{AllowLoopback: true})
	s.Resolver = &scriptedResolver{answers: [][]netip.Addr{addrs("127.0.0.1")}}
	r := s.Send(context.Background(), testSecret(t, hookURL(target, "receiver.example")), "id", []byte(`{}`))
	if r.Outcome != OutcomeSent || proxy.hits.Load() != 0 || target.hits.Load() != 1 {
		t.Fatalf("%+v proxy hits %d, target hits %d", r, proxy.hits.Load(), target.hits.Load())
	}
}

// The receiver recomputes the signature independently and checks the headers:
// webhook-timestamp is the injected clock's time, webhook-id the alert id.
func TestWebhookRequestIsSignedWithTheInjectedClock(t *testing.T) {
	rc := newReceiver(t, nil)
	sec := testSecret(t, hookURL(rc, "127.0.0.1"))
	body := []byte(`{"schema":1,"id":"abc"}`)
	if r := sender(Policy{AllowLoopback: true}).Send(context.Background(), sec, "abc", body); r.Outcome != OutcomeSent {
		t.Fatalf("%+v", r)
	}
	req := rc.reqs[0]
	if req.body != string(body) {
		t.Fatalf("body %q", req.body)
	}
	h := req.header
	if h.Get("webhook-id") != "abc" || h.Get("webhook-timestamp") != strconv.FormatInt(t0wh.Unix(), 10) {
		t.Fatalf("headers %v", h)
	}
	if h.Get("Content-Type") != "application/json" || h.Get("User-Agent") != "ClamFleet/test" {
		t.Fatalf("headers %v", h)
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(sec.SigningKey, "whsec_"))
	if !VerifySignature(raw, "abc", t0wh.Unix(), body, h.Get("webhook-signature")) {
		t.Fatal("the signature does not verify with the decoded key")
	}
	if VerifySignature([]byte(sec.SigningKey), "abc", t0wh.Unix(), body, h.Get("webhook-signature")) {
		t.Fatal("the signature verifies with the whsec_ string as the key")
	}
}

func TestWebhookStoredBadSecretsArePermanent(t *testing.T) {
	s := sender(Policy{AllowLoopback: true})
	for name, sec := range map[string]WebhookSecret{
		"bad key":      {URL: "http://127.0.0.1:9/x", SigningKey: "nope"},
		"bad url":      {URL: "ftp://x/y", SigningKey: "whsec_" + vecSecret},
		"userinfo url": {URL: "http://u:p@127.0.0.1:9/x", SigningKey: "whsec_" + vecSecret},
	} {
		if r := s.Send(context.Background(), sec, "id", []byte(`{}`)); r.Outcome != OutcomePermanent {
			t.Errorf("%s: %+v", name, r)
		}
	}
	r := s.Send(context.Background(), WebhookSecret{URL: "ftp://x/TOKEN-MARKER", SigningKey: "whsec_" + vecSecret}, "id", nil)
	if strings.Contains(r.Text, "TOKEN-MARKER") {
		t.Fatalf("leak: %+v", r)
	}
}

// TLS: a private CA is trusted only through RootCAs; the system roots never
// verify it (no InsecureSkipVerify anywhere).
func TestWebhookTLSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	sec := testSecret(t, "https://127.0.0.1:"+u.Port()+"/x")
	s := sender(Policy{AllowLoopback: true})
	if r := s.Send(context.Background(), sec, "id", []byte(`{}`)); r.Outcome != OutcomeRetry || r.Code != "tls" {
		t.Fatalf("an untrusted certificate: %+v", r)
	}
	s.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	if r := s.Send(context.Background(), sec, "id", []byte(`{}`)); r.Outcome != OutcomeSent {
		t.Fatalf("a trusted certificate: %+v", r)
	}
}

func TestSafeDialerResolverErrorIsReturned(t *testing.T) {
	d := &SafeDialer{Policy: Policy{AllowPrivate: true}, Resolver: failingResolver{}}
	if _, err := d.DialContext(context.Background(), "tcp", "x.example:80"); err == nil {
		t.Fatal("want the resolver's error")
	}
	var perm *PermanentError
	d2 := &SafeDialer{Resolver: &scriptedResolver{answers: [][]netip.Addr{{}}}}
	if _, err := d2.DialContext(context.Background(), "tcp", "x.example:80"); !errors.As(err, &perm) {
		t.Fatalf("no answers at all: %v", err)
	}
}

type failingResolver struct{}

func (failingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, &net.DNSError{Err: "no such host", Name: "x.example", IsNotFound: true}
}
