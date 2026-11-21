// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// smtp.go: the SMTP client session on top of net/smtp (M4 decision 11).
//
// net/smtp is frozen but not deprecated, and has no LOGIN auth and no context
// support; this file adds LOGIN, a session deadline and the delivery
// semantics around it.
//
// One session delivers ONE message to ONE recipient, so each recipient's result
// is its own durable delivery row.
//
// The commit point is the server's reply to the final "." of DATA: the
// io.WriteCloser that Client.Data returns reads that reply in Close and returns
// an error for a non-2xx reply (checked against the Go source). A 2xx
// there makes the attempt SENT whatever happens next: QUIT is best-effort, its
// error or a dropped connection changes nothing. A lost connection or 4xx before
// or instead of that reply is a retry (the message may then arrive twice, with
// the same Message-ID and X-ClamFleet-Alert-Id: at least once, as for
// webhooks); 5xx is permanent.
//
// There is no downgrade: in starttls mode a server that does not offer STARTTLS
// fails the attempt before AUTH and MAIL. Plaintext (tls: none) only reaches
// loopback and private addresses (M4 decision 19), and credentials never go over
// plaintext beyond loopback.
package alert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// SMTP security modes.
const (
	SMTPStartTLS = "starttls"
	SMTPTLS      = "tls" // implicit TLS, port 465
	SMTPNone     = "none"
)

// SMTPConfig is the validated server configuration of the sender.
type SMTPConfig struct {
	Host     string
	Port     int
	TLS      string
	From     string
	Username string
	Password string
	// Helo is the name announced in EHLO.
	Helo string
	// Timeout is the deadline of the whole session.
	Timeout time.Duration
	RootCAs *x509.CertPool
}

// SMTPSender delivers one rendered message.
type SMTPSender struct {
	Config SMTPConfig
	// Resolver and Dial are injectable for tests; nil means the real ones.
	Resolver Resolver
	Dial     DialFunc
	// NAT64 are the operator's translation prefixes (alert.webhook.nat64_prefixes):
	// the relay address gets the same embedded-IPv4 classification as a webhook.
	NAT64 []netip.Prefix
	// Now is the injected clock.
	Now func() time.Time
}

// loginAuth implements AUTH LOGIN, which net/smtp lacks. Like smtp.PlainAuth it
// refuses to send the password over an unencrypted connection unless the server
// is loopback.
type loginAuth struct{ username, password string }

func isLocalName(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func (a loginAuth) Start(s *smtp.ServerInfo) (string, []byte, error) {
	if !s.TLS && !isLocalName(s.Name) {
		return "", nil, errors.New("refusing to send credentials over an unencrypted connection")
	}
	return "LOGIN", nil, nil
}

func (a loginAuth) Next(from []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(from))) {
	case "username:":
		return []byte(a.username), nil
	case "password:":
		return []byte(a.password), nil
	}
	return nil, errors.New("unexpected LOGIN challenge from the server")
}

// stageResult turns an error of one SMTP step into a Result.
func stageResult(stage string, err error) Result {
	var te *textproto.Error
	if errors.As(err, &te) {
		return ClassifySMTPReply(te.Code, stage)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return Result{Outcome: OutcomeRetry, Code: "connection lost", Text: "the connection was lost during " + stage}
	}
	return ClassifyError(err)
}

// Send delivers msg. It never returns an error: every outcome is a Result.
func (s *SMTPSender) Send(ctx context.Context, msg EmailMessage) Result {
	start := s.Now()
	timeout := s.Config.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	r := s.send(ctx, msg)
	if r.Outcome == OutcomeRetry && ctx.Err() != nil {
		// The deadline (or a shutdown) closed the connection under the session, so
		// the step that failed reports "use of closed connection": say what really
		// happened instead.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			r = Result{Outcome: OutcomeRetry, Code: "timeout", Text: "the mail session timed out"}
		} else {
			r = Result{Outcome: OutcomeRetry, Code: "cancelled", Text: "the mail session was cancelled (server stopping)"}
		}
	}
	r.Duration = s.Now().Sub(start)
	return r
}

func (s *SMTPSender) send(ctx context.Context, msg EmailMessage) Result {
	c := s.Config
	if c.Host == "" {
		return Result{Outcome: OutcomePermanent, Code: "not configured", Text: "email is not configured (smtp.host)"}
	}
	body, err := msg.Bytes()
	if err != nil {
		return Result{Outcome: OutcomePermanent, Code: "invalid", Text: "the message could not be rendered"}
	}
	deadline, _ := ctx.Deadline()

	// The relay address policy: always-blocked addresses never; plaintext only to
	// loopback or private (M4 decision 19). Public relays over TLS are fine, so no
	// private/loopback restriction otherwise.
	d := &SafeDialer{
		Policy:    Policy{AllowPrivate: true, AllowLoopback: true, NAT64Prefixes: s.NAT64},
		Plaintext: c.TLS == SMTPNone,
		Resolver:  s.Resolver, Dial: s.Dial, Timeout: 10 * time.Second,
	}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)))
	if err != nil {
		return ClassifyError(err)
	}
	defer conn.Close()
	conn.SetDeadline(deadline)
	// Abort promptly on shutdown, not only at the deadline.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	// Credentials over plaintext only to loopback (M4 decision 19).
	if c.TLS == SMTPNone && c.Username != "" {
		if ap, err := netipFromAddr(conn.RemoteAddr()); err != nil || !ap.IsLoopback() {
			return Result{Outcome: OutcomePermanent, Code: "plaintext", Text: "credentials are never sent over plaintext to a non-loopback relay; use tls or starttls"}
		}
	}

	tlsCfg := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12, RootCAs: c.RootCAs}
	if c.TLS == SMTPTLS {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return ClassifyError(err)
		}
		conn = tc
	}
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return stageResult("the greeting", err)
	}
	helo := c.Helo
	if helo == "" {
		helo = "localhost"
	}
	if err := cl.Hello(helo); err != nil {
		return stageResult("EHLO", err)
	}
	if c.TLS == SMTPStartTLS {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return Result{Outcome: OutcomePermanent, Code: "tls", Text: "the mail server does not offer STARTTLS; credentials and mail are not sent without it"}
		}
		if err := cl.StartTLS(tlsCfg); err != nil {
			return stageResult("STARTTLS", err)
		}
	}
	if c.Username != "" {
		ok, mechs := cl.Extension("AUTH")
		if !ok {
			return Result{Outcome: OutcomePermanent, Code: "auth", Text: "the mail server does not offer AUTH"}
		}
		var auth smtp.Auth
		switch {
		case hasMech(mechs, "PLAIN"):
			auth = smtp.PlainAuth("", c.Username, c.Password, c.Host)
		case hasMech(mechs, "LOGIN"):
			auth = loginAuth{c.Username, c.Password}
		default:
			return Result{Outcome: OutcomePermanent, Code: "auth", Text: "the mail server offers no supported AUTH mechanism (PLAIN, LOGIN)"}
		}
		if err := cl.Auth(auth); err != nil {
			var te *textproto.Error
			if !errors.As(err, &te) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !isTimeout(err) {
				return Result{Outcome: OutcomePermanent, Code: "auth", Text: "authentication was refused locally: " + err.Error()}
			}
			return stageResult("AUTH", err)
		}
	}
	if err := cl.Mail(c.From); err != nil {
		return stageResult("MAIL", err)
	}
	if err := cl.Rcpt(msg.To); err != nil {
		return stageResult("RCPT", err)
	}
	w, err := cl.Data()
	if err != nil {
		return stageResult("DATA", err)
	}
	if _, err := w.Write(body); err != nil {
		return stageResult("DATA", err)
	}
	// Close sends the final "." and reads the server's reply: THE commit point.
	if err := w.Close(); err != nil {
		var te *textproto.Error
		if errors.As(err, &te) && te.Code >= 200 && te.Code < 300 {
			// A 2xx other than 250 still accepts the message.
		} else {
			return stageResult("the end of DATA", err)
		}
	}
	// Accepted. QUIT is courtesy: whatever it does changes nothing.
	_ = cl.Quit()
	return Result{Outcome: OutcomeSent, Code: "SMTP 250"}
}

func hasMech(list, want string) bool {
	for _, m := range strings.Fields(list) {
		if strings.EqualFold(m, want) {
			return true
		}
	}
	return false
}

// netipFromAddr parses the IP of a connection's remote address.
func netipFromAddr(a net.Addr) (net.IP, error) {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("not an IP address")
	}
	return ip, nil
}
