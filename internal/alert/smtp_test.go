// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package alert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"net/smtp"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/testsmtp"
	"github.com/clamfleet/clamfleet/internal/testtls"
)

type tlsKit struct {
	server *tls.Config
	pool   *x509.CertPool
}

func newTLSKit(t *testing.T) tlsKit {
	t.Helper()
	b, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(b.Cert, b.Key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(b.CA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	return tlsKit{server: &tls.Config{Certificates: []tls.Certificate{cert}}, pool: pool}
}

func startSMTP(t *testing.T, o testsmtp.Options) *testsmtp.Server {
	t.Helper()
	s, err := testsmtp.Listen("127.0.0.1:0", o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func smtpSender(s *testsmtp.Server, mode string) *SMTPSender {
	host, port, _ := net.SplitHostPort(s.Addr)
	p, _ := net.LookupPort("tcp", port)
	return &SMTPSender{
		Config: SMTPConfig{Host: host, Port: p, TLS: mode, From: "clamfleet@test.example", Timeout: 3 * time.Second, Helo: "clamfleet.test"},
		Now:    fixedNow,
	}
}

func testMessage(to string) EmailMessage {
	return EmailMessage{From: "clamfleet@test.example", To: to, Subject: "[ClamFleet] test", Date: t0wh, MessageID: "<a.1@test.example>", AlertID: "a",
		Body: "line one\n.\n..two\nlast\n"}
}

func TestSMTPStartTLSBeforeAuthAndDelivery(t *testing.T) {
	kit := newTLSKit(t)
	srv := startSMTP(t, testsmtp.Options{TLS: kit.server, AdvertiseSTARTTLS: true, AuthMechs: []string{"PLAIN", "LOGIN"}, AuthAfterTLS: true, Username: "u", Password: "p"})
	s := smtpSender(srv, SMTPStartTLS)
	s.Config.Username, s.Config.Password, s.Config.RootCAs = "u", "p", kit.pool
	msg := testMessage("ops@x.example")
	r := s.Send(context.Background(), msg)
	if r.Outcome != OutcomeSent || r.Code != "SMTP 250" {
		t.Fatalf("%+v", r)
	}
	if !srv.Saw("AUTH PLAIN tls=true") || srv.Saw("AUTH PLAIN tls=false") {
		t.Fatalf("AUTH must follow STARTTLS: %v", srv.Events())
	}
	got := srv.Messages()
	if len(got) != 1 || !got[0].TLS || got[0].From != "clamfleet@test.example" || len(got[0].To) != 1 || got[0].To[0] != "ops@x.example" {
		t.Fatalf("%+v", got)
	}
	// The delivered message equals the rendered one (dot-stuffing undone by the server).
	want, _ := msg.Bytes()
	if got[0].Data != string(want) {
		t.Fatalf("data differs:\n got %q\nwant %q", got[0].Data, want)
	}
	if r.Duration != 0 { // injected, fixed clock
		t.Fatalf("duration %v", r.Duration)
	}
}

// Mutation 31: STARTTLS optional. Without STARTTLS offered the attempt fails
// permanently and the server never saw AUTH or MAIL.
func TestSMTPNoDowngradeWhenStartTLSIsNotOffered(t *testing.T) {
	srv := startSMTP(t, testsmtp.Options{AuthMechs: []string{"PLAIN"}, Username: "u", Password: "p"})
	s := smtpSender(srv, SMTPStartTLS)
	s.Config.Username, s.Config.Password = "u", "p"
	r := s.Send(context.Background(), testMessage("ops@x.example"))
	if r.Outcome != OutcomePermanent || r.Code != "tls" {
		t.Fatalf("%+v", r)
	}
	if srv.Saw("AUTH") || srv.Saw("MAIL") || srv.Saw("RCPT") {
		t.Fatalf("the client went on without TLS: %v", srv.Events())
	}
}

func TestSMTPImplicitTLS(t *testing.T) {
	kit := newTLSKit(t)
	srv := startSMTP(t, testsmtp.Options{TLS: kit.server, Implicit: true, AuthMechs: []string{"PLAIN"}, Username: "u", Password: "p"})
	s := smtpSender(srv, SMTPTLS)
	s.Config.Username, s.Config.Password, s.Config.RootCAs = "u", "p", kit.pool
	if r := s.Send(context.Background(), testMessage("ops@x.example")); r.Outcome != OutcomeSent {
		t.Fatalf("%+v", r)
	}
	if !srv.Saw("AUTH PLAIN tls=true") { // plan A5: smtp.NewClient on a *tls.Conn reports TLS to Auth
		t.Fatalf("%v", srv.Events())
	}
	// A client that does not trust the CA fails the handshake (retry, "tls").
	s.Config.RootCAs = nil
	if r := s.Send(context.Background(), testMessage("ops@x.example")); r.Outcome != OutcomeRetry || r.Code != "tls" {
		t.Fatalf("%+v", r)
	}
}

func TestSMTPLoginWhenPlainIsNotOffered(t *testing.T) {
	srv := startSMTP(t, testsmtp.Options{AuthMechs: []string{"LOGIN"}, Username: "u", Password: "p"})
	s := smtpSender(srv, SMTPNone) // loopback: credentials allowed
	s.Config.Username, s.Config.Password = "u", "p"
	if r := s.Send(context.Background(), testMessage("ops@x.example")); r.Outcome != OutcomeSent {
		t.Fatalf("%+v", r)
	}
	if !srv.Saw("AUTH LOGIN") || srv.Saw("AUTH PLAIN") {
		t.Fatalf("%v", srv.Events())
	}
	// A wrong password is a permanent 535.
	s.Config.Password = "wrong"
	if r := s.Send(context.Background(), testMessage("ops@x.example")); r.Outcome != OutcomePermanent || r.Code != "SMTP 535" {
		t.Fatalf("%+v", r)
	}
}

func TestLoginAuthRefusesPlaintextToANonLoopbackName(t *testing.T) {
	a := loginAuth{"u", "p"}
	if _, _, err := a.Start(&smtp.ServerInfo{Name: "relay.example", TLS: false}); err == nil {
		t.Fatal("credentials would go out in clear")
	}
	for _, si := range []*smtp.ServerInfo{{Name: "relay.example", TLS: true}, {Name: "localhost"}, {Name: "127.0.0.1"}, {Name: "::1"}} {
		if proto, _, err := a.Start(si); err != nil || proto != "LOGIN" {
			t.Errorf("%+v: %v", si, err)
		}
	}
	if resp, err := a.Next([]byte("Username:"), true); err != nil || string(resp) != "u" {
		t.Fatal(err)
	}
	if resp, err := a.Next([]byte("Password:"), true); err != nil || string(resp) != "p" {
		t.Fatal(err)
	}
	if _, err := a.Next([]byte("Surprise:"), true); err == nil {
		t.Fatal("an unknown challenge must fail")
	}
}

func TestSMTPReplyClassification(t *testing.T) {
	cases := []struct {
		name string
		o    testsmtp.Options
		want Outcome
		code string
	}{
		{"RCPT 450", testsmtp.Options{RcptReplies: map[string]string{"ops@x.example": "450 try later"}}, OutcomeRetry, "SMTP 450"},
		{"RCPT 550", testsmtp.Options{RcptReplies: map[string]string{"ops@x.example": "550 no such user"}}, OutcomePermanent, "SMTP 550"},
		{"MAIL 550", testsmtp.Options{MailReply: "550 sender refused"}, OutcomePermanent, "SMTP 550"},
		{"MAIL 421", testsmtp.Options{MailReply: "421 busy"}, OutcomeRetry, "SMTP 421"},
		{"DATA 554", testsmtp.Options{DataReply: "554 no"}, OutcomePermanent, "SMTP 554"},
		{"final 451", testsmtp.Options{FinalReply: "451 try again"}, OutcomeRetry, "SMTP 451"},
		{"final 554", testsmtp.Options{FinalReply: "554 rejected"}, OutcomePermanent, "SMTP 554"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := startSMTP(t, c.o)
			r := smtpSender(srv, SMTPNone).Send(context.Background(), testMessage("ops@x.example"))
			if r.Outcome != c.want || r.Code != c.code {
				t.Fatalf("%+v", r)
			}
			if len(srv.Messages()) != 0 {
				t.Fatal("a refused message was recorded as accepted")
			}
		})
	}
}

// Mutation 19: record success before the DATA reply, or treat a QUIT error as
// a failure. The commit point is the final reply.
func TestSMTPCommitPoint(t *testing.T) {
	t.Run("dropped at the final dot without a reply is a retry", func(t *testing.T) {
		srv := startSMTP(t, testsmtp.Options{DropAtFinalDot: true})
		r := smtpSender(srv, SMTPNone).Send(context.Background(), testMessage("ops@x.example"))
		if r.Outcome != OutcomeRetry || r.Code != "connection lost" {
			t.Fatalf("%+v", r)
		}
		if len(srv.Unacked()) != 1 || len(srv.Messages()) != 0 {
			t.Fatalf("unacked %d, accepted %d", len(srv.Unacked()), len(srv.Messages()))
		}
	})
	t.Run("250 then a drop before QUIT is sent", func(t *testing.T) {
		srv := startSMTP(t, testsmtp.Options{DropAfterFinalReply: true})
		if r := smtpSender(srv, SMTPNone).Send(context.Background(), testMessage("ops@x.example")); r.Outcome != OutcomeSent {
			t.Fatalf("%+v", r)
		}
		if len(srv.Messages()) != 1 {
			t.Fatal("not accepted")
		}
	})
	t.Run("250 then QUIT answered 421 is sent", func(t *testing.T) {
		srv := startSMTP(t, testsmtp.Options{QuitReply: "421 closing"})
		if r := smtpSender(srv, SMTPNone).Send(context.Background(), testMessage("ops@x.example")); r.Outcome != OutcomeSent {
			t.Fatalf("%+v", r)
		}
	})
}

func TestSMTPSessionDeadline(t *testing.T) {
	srv := startSMTP(t, testsmtp.Options{Stall: true})
	s := smtpSender(srv, SMTPNone)
	s.Config.Timeout = 300 * time.Millisecond
	done := make(chan Result, 1)
	go func() { done <- s.Send(context.Background(), testMessage("ops@x.example")) }()
	select {
	case r := <-done:
		if r.Outcome != OutcomeRetry || r.Code != "timeout" {
			t.Fatalf("%+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session ignored its deadline")
	}
}

func TestSMTPNotConfigured(t *testing.T) {
	r := (&SMTPSender{Now: fixedNow}).Send(context.Background(), testMessage("a@b.example"))
	if r.Outcome != OutcomePermanent || !strings.Contains(r.Text, "smtp.host") {
		t.Fatalf("%+v", r)
	}
}

// Decision 19: tls none only reaches loopback or private relays; credentials
// over plaintext only reach loopback. Mutation 39 for SMTP.
func TestSMTPPlaintextPolicy(t *testing.T) {
	t.Run("a public relay is refused without a dial", func(t *testing.T) {
		d := &recordingDial{to: "127.0.0.1:1"}
		s := &SMTPSender{Config: SMTPConfig{Host: "relay.example", Port: 25, TLS: SMTPNone, From: "a@b.example"}, Now: fixedNow,
			Resolver: &scriptedResolver{answers: [][]netip.Addr{addrs("203.0.113.5")}}, Dial: d.dial}
		r := s.Send(context.Background(), testMessage("ops@x.example"))
		if r.Outcome != OutcomePermanent || r.Code != "plaintext" || d.list() != "" {
			t.Fatalf("%+v dialled %q", r, d.list())
		}
	})
	t.Run("NAT64 of a public address is public: refused without a dial", func(t *testing.T) {
		d := &recordingDial{to: "127.0.0.1:1"}
		s := &SMTPSender{Config: SMTPConfig{Host: "relay.example", Port: 25, TLS: SMTPNone, From: "a@b.example"}, Now: fixedNow,
			Resolver: &scriptedResolver{answers: [][]netip.Addr{addrs("64:ff9b::808:808")}}, Dial: d.dial}
		r := s.Send(context.Background(), testMessage("ops@x.example"))
		if r.Outcome != OutcomePermanent || r.Code != "plaintext" || d.list() != "" {
			t.Fatalf("%+v dialled %q", r, d.list())
		}
	})
	t.Run("NAT64 of loopback is allowed as loopback, a deprecated embedding is not", func(t *testing.T) {
		srv := startSMTP(t, testsmtp.Options{})
		d := &recordingDial{to: srv.Addr}
		s := smtpSender(srv, SMTPNone)
		s.Config.Host = "relay.example"
		s.Resolver, s.Dial = &scriptedResolver{answers: [][]netip.Addr{addrs("64:ff9b::7f00:1")}}, d.dial
		if r := s.Send(context.Background(), testMessage("ops@x.example")); r.Outcome != OutcomeSent || d.list() != "64:ff9b::7f00:1" {
			t.Fatalf("%+v dialled %q", r, d.list())
		}
		d2 := &recordingDial{to: srv.Addr}
		s2 := smtpSender(srv, SMTPNone)
		s2.Config.Host = "relay.example"
		s2.Resolver, s2.Dial = &scriptedResolver{answers: [][]netip.Addr{addrs("2002:7f00:1::1")}}, d2.dial
		if r := s2.Send(context.Background(), testMessage("ops@x.example")); r.Outcome != OutcomePermanent || d2.list() != "" {
			t.Fatalf("6to4 relay: %+v dialled %q", r, d2.list())
		}
	})
	t.Run("a listed local-use prefix is decoded, an unlisted one is blocked", func(t *testing.T) {
		d := &recordingDial{to: "127.0.0.1:1"}
		s := &SMTPSender{Config: SMTPConfig{Host: "relay.example", Port: 25, TLS: SMTPNone, From: "a@b.example"}, Now: fixedNow,
			Resolver: &scriptedResolver{answers: [][]netip.Addr{addrs("64:ff9b:1::a00:1")}}, Dial: d.dial}
		if r := s.Send(context.Background(), testMessage("ops@x.example")); r.Outcome != OutcomePermanent || d.list() != "" {
			t.Fatalf("unlisted: %+v dialled %q", r, d.list())
		}
		srv := startSMTP(t, testsmtp.Options{})
		d2 := &recordingDial{to: srv.Addr}
		s2 := smtpSender(srv, SMTPNone)
		s2.Config.Host = "relay.example"
		s2.NAT64 = []netip.Prefix{netip.MustParsePrefix("64:ff9b:1::/96")}
		s2.Resolver, s2.Dial = &scriptedResolver{answers: [][]netip.Addr{addrs("64:ff9b:1::a00:1")}}, d2.dial
		if r := s2.Send(context.Background(), testMessage("ops@x.example")); r.Outcome != OutcomeSent {
			t.Fatalf("listed (10.0.0.1 behind it, private): %+v dialled %q", r, d2.list())
		}
	})
	t.Run("a private relay without credentials is allowed", func(t *testing.T) {
		srv := startSMTP(t, testsmtp.Options{})
		d := &recordingDial{to: srv.Addr}
		s := smtpSender(srv, SMTPNone)
		s.Config.Host = "relay.example"
		s.Resolver, s.Dial = &scriptedResolver{answers: [][]netip.Addr{addrs("10.0.0.25")}}, d.dial
		if r := s.Send(context.Background(), testMessage("ops@x.example")); r.Outcome != OutcomeSent || d.list() != "10.0.0.25" {
			t.Fatalf("%+v dialled %q", r, d.list())
		}
	})
	t.Run("credentials never go to a private, non-loopback relay in clear", func(t *testing.T) {
		srv := startSMTP(t, testsmtp.Options{AuthMechs: []string{"PLAIN"}, Username: "u", Password: "p"})
		s := smtpSender(srv, SMTPNone)
		s.Config.Host, s.Config.Username, s.Config.Password = "relay.example", "u", "p"
		s.Resolver = &scriptedResolver{answers: [][]netip.Addr{addrs("10.0.0.25")}}
		s.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, srv.Addr)
			return remoteAs{c, "10.0.0.25:25"}, err // the connection claims to be a private, non-loopback peer
		}
		r := s.Send(context.Background(), testMessage("ops@x.example"))
		if r.Outcome != OutcomePermanent || r.Code != "plaintext" {
			t.Fatalf("%+v", r)
		}
		if srv.Saw("AUTH") || srv.Saw("MAIL") {
			t.Fatalf("credentials or mail went out: %v", srv.Events())
		}
	})
}

// remoteAs reports a different peer address (the test cannot dial a real
// private address).
type remoteAs struct {
	net.Conn
	addr string
}

func (r remoteAs) RemoteAddr() net.Addr {
	a, _ := net.ResolveTCPAddr("tcp", r.addr)
	return a
}

// Two recipients are two sessions: each gets only its own message (the
// recipients do not see each other).
func TestSMTPOneMessagePerRecipient(t *testing.T) {
	srv := startSMTP(t, testsmtp.Options{})
	s := smtpSender(srv, SMTPNone)
	for _, to := range []string{"a@x.example", "b@x.example"} {
		if r := s.Send(context.Background(), testMessage(to)); r.Outcome != OutcomeSent {
			t.Fatalf("%+v", r)
		}
	}
	got := srv.Messages()
	if len(got) != 2 || len(got[0].To) != 1 || len(got[1].To) != 1 || got[0].To[0] == got[1].To[0] {
		t.Fatalf("%+v", got)
	}
	if strings.Contains(got[0].Data, "b@x.example") {
		t.Fatal("recipient a saw b's address")
	}
}
