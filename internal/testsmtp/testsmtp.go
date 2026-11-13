// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package testsmtp is a small, scriptable fake SMTP server for the alert
// sender's tests and for the container e2e sink (hack/alertsink).
//
// TEST ONLY. Nothing in a production binary may import it. It binds loopback
// addresses only: Listen refuses anything else.
//
// What it speaks: EHLO/HELO, STARTTLS, AUTH PLAIN and LOGIN, MAIL, RCPT, DATA,
// RSET, NOOP, QUIT, and implicit TLS. What makes it useful is that every reply
// can be scripted, and that it can drop the connection at the moments that
// matter for delivery semantics: after the final "." without answering (the
// message may or may not have been accepted), or after answering it and before
// QUIT.
package testsmtp

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// Options scripts the server. The zero value is a plaintext server that
// accepts everything.
type Options struct {
	// TLS is the server certificate configuration. With Implicit false it is
	// used for STARTTLS (when AdvertiseSTARTTLS is true); with Implicit true every
	// connection starts as TLS.
	TLS      *tls.Config
	Implicit bool
	// AdvertiseSTARTTLS makes EHLO offer STARTTLS (needs TLS).
	AdvertiseSTARTTLS bool
	// AuthMechs lists the mechanisms offered in EHLO ("PLAIN", "LOGIN"); empty =
	// no AUTH. AuthAfterTLS offers them only once the connection is TLS.
	AuthMechs    []string
	AuthAfterTLS bool
	// Username and Password are what AUTH accepts; any other pair gets 535.
	Username, Password string

	// MailReply, RcptReplies (by address, lower case) and DataReply script the
	// replies ("550 no"); the defaults are 250, 250 and 354.
	MailReply   string
	RcptReplies map[string]string
	DataReply   string
	// FinalReply is the reply to the "." that ends the message (default
	// "250 2.0.0 queued").
	FinalReply string
	// DropAtFinalDot: read the message, then close the connection WITHOUT
	// replying. The message counts as Unacked.
	DropAtFinalDot bool
	// DropAfterFinalReply: reply to the "." and then close before QUIT.
	DropAfterFinalReply bool
	// QuitReply scripts the reply to QUIT (default "221 bye").
	QuitReply string
	// Stall: send the greeting, then never answer anything.
	Stall bool
	// OnMessage is called for every acknowledged message (the sink uses it).
	OnMessage func(Message)
}

// Message is one message the server accepted (or, for Unacked, read).
type Message struct {
	From string
	To   []string
	// Data is the message as received, with dot-stuffing removed and CRLF line ends.
	Data string
	// TLS is true when it arrived over TLS.
	TLS bool
}

// Server is a running fake.
type Server struct {
	// Addr is the 127.0.0.1:port the server listens on.
	Addr string
	opt  Options
	ln   net.Listener
	wg   sync.WaitGroup

	mu       sync.Mutex
	messages []Message
	unacked  []Message
	events   []string
	conns    map[net.Conn]struct{}
	closed   bool
}

// Listen starts a server on addr, which must be a loopback address ("127.0.0.1:0").
func Listen(addr string, opt Options) (*Server, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("testsmtp binds loopback only, got %q", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{Addr: ln.Addr().String(), opt: opt, ln: ln, conns: map[net.Conn]struct{}{}}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

// Close stops the server and drops every open connection.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.ln.Close()
	s.wg.Wait()
}

// Messages returns the acknowledged messages.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.messages...)
}

// Unacked returns messages that were read to the final "." but never answered.
func (s *Server) Unacked() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.unacked...)
}

// Events returns what the server saw, in order: "EHLO", "STARTTLS", "AUTH
// PLAIN tls=true", "MAIL a@x", "RCPT b@y", "DATA", "QUIT".
func (s *Server) Events() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.events...)
}

// Saw reports whether an event starting with prefix was recorded.
func (s *Server) Saw(prefix string) bool {
	for _, e := range s.Events() {
		if strings.HasPrefix(e, prefix) {
			return true
		}
	}
	return false
}

func (s *Server) event(f string, a ...any) {
	s.mu.Lock()
	s.events = append(s.events, fmt.Sprintf(f, a...))
	s.mu.Unlock()
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				c.Close()
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
			}()
			s.serve(c)
		}()
	}
}

type session struct {
	s    *Server
	c    net.Conn
	r    *bufio.Reader
	tls  bool
	from string
	to   []string
}

func (ss *session) reply(format string, a ...any) error {
	_, err := fmt.Fprintf(ss.c, format+"\r\n", a...)
	return err
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func (s *Server) serve(c net.Conn) {
	ss := &session{s: s, c: c}
	if s.opt.Implicit {
		tc := tls.Server(c, s.opt.TLS)
		if err := tc.Handshake(); err != nil {
			return
		}
		ss.c, ss.tls = tc, true
	}
	ss.r = bufio.NewReader(ss.c)
	if ss.reply("220 testsmtp ready") != nil {
		return
	}
	if s.opt.Stall {
		io.Copy(io.Discard, ss.c) // until the client gives up or Close
		return
	}
	for {
		line, err := ss.r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			s.event("EHLO")
			ss.ehlo()
		case "STARTTLS":
			if !s.opt.AdvertiseSTARTTLS || s.opt.TLS == nil || ss.tls {
				ss.reply("502 not offered")
				continue
			}
			s.event("STARTTLS")
			ss.reply("220 go ahead")
			tc := tls.Server(ss.c, s.opt.TLS)
			if err := tc.Handshake(); err != nil {
				return
			}
			ss.c, ss.r, ss.tls = tc, bufio.NewReader(tc), true
			ss.from, ss.to = "", nil
		case "AUTH":
			if !ss.auth(arg) {
				return
			}
		case "MAIL":
			s.event("MAIL %s", addrOf(arg))
			ss.from, ss.to = addrOf(arg), nil
			ss.reply("%s", orDefault(s.opt.MailReply, "250 ok"))
		case "RCPT":
			rcpt := strings.ToLower(addrOf(arg))
			s.event("RCPT %s", rcpt)
			if r, ok := s.opt.RcptReplies[rcpt]; ok {
				ss.reply("%s", r)
				continue
			}
			ss.to = append(ss.to, rcpt)
			ss.reply("250 ok")
		case "DATA":
			s.event("DATA")
			if !ss.data() {
				return
			}
		case "RSET":
			ss.from, ss.to = "", nil
			ss.reply("250 ok")
		case "NOOP":
			ss.reply("250 ok")
		case "QUIT":
			s.event("QUIT")
			ss.reply("%s", orDefault(s.opt.QuitReply, "221 bye"))
			return
		default:
			ss.reply("500 unknown command")
		}
	}
}

func (ss *session) ehlo() {
	lines := []string{"testsmtp", "8BITMIME"}
	if ss.s.opt.AdvertiseSTARTTLS && !ss.tls {
		lines = append(lines, "STARTTLS")
	}
	if len(ss.s.opt.AuthMechs) > 0 && (ss.tls || !ss.s.opt.AuthAfterTLS) {
		lines = append(lines, "AUTH "+strings.Join(ss.s.opt.AuthMechs, " "))
	}
	for i, l := range lines {
		sep := "-"
		if i == len(lines)-1 {
			sep = " "
		}
		ss.reply("250%s%s", sep, l)
	}
}

// addrOf extracts the address from "FROM:<a@b> SIZE=..." / "TO:<a@b>".
func addrOf(arg string) string {
	i, j := strings.Index(arg, "<"), strings.Index(arg, ">")
	if i < 0 || j < i {
		return ""
	}
	return arg[i+1 : j]
}

// auth handles AUTH PLAIN and AUTH LOGIN; it returns false when the connection
// should end.
func (ss *session) auth(arg string) bool {
	mech, rest, _ := strings.Cut(arg, " ")
	mech = strings.ToUpper(mech)
	ss.s.event("AUTH %s tls=%v", mech, ss.tls)
	okMech := false
	for _, m := range ss.s.opt.AuthMechs {
		if m == mech {
			okMech = true
		}
	}
	if !okMech {
		ss.reply("504 mechanism not offered")
		return true
	}
	read := func() (string, bool) {
		line, err := ss.r.ReadString('\n')
		if err != nil {
			return "", false
		}
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
		return string(b), err == nil
	}
	var user, pass string
	switch mech {
	case "PLAIN":
		resp := rest
		if resp == "" {
			ss.reply("334 ")
			line, err := ss.r.ReadString('\n')
			if err != nil {
				return false
			}
			resp = strings.TrimSpace(line)
		}
		b, err := base64.StdEncoding.DecodeString(resp)
		if err != nil {
			ss.reply("501 bad base64")
			return true
		}
		parts := strings.Split(string(b), "\x00")
		if len(parts) != 3 {
			ss.reply("501 bad PLAIN")
			return true
		}
		user, pass = parts[1], parts[2]
	case "LOGIN":
		ss.reply("334 %s", base64.StdEncoding.EncodeToString([]byte("Username:")))
		var ok bool
		if user, ok = read(); !ok {
			return false
		}
		ss.reply("334 %s", base64.StdEncoding.EncodeToString([]byte("Password:")))
		if pass, ok = read(); !ok {
			return false
		}
	}
	if user == ss.s.opt.Username && pass == ss.s.opt.Password && user != "" {
		ss.reply("235 2.7.0 authenticated")
	} else {
		ss.reply("535 5.7.8 authentication failed")
	}
	return true
}

// data runs DATA; it returns false when the connection should end.
func (ss *session) data() bool {
	if len(ss.to) == 0 {
		ss.reply("503 no valid recipients")
		return true
	}
	if r := ss.s.opt.DataReply; r != "" && !strings.HasPrefix(r, "354") {
		ss.reply("%s", r)
		return true
	}
	ss.reply("354 end with <CRLF>.<CRLF>")
	var b strings.Builder
	for {
		line, err := ss.r.ReadString('\n')
		if err != nil {
			return false
		}
		if line == ".\r\n" {
			break
		}
		line = strings.TrimPrefix(line, ".") // undo dot-stuffing
		b.WriteString(line)
	}
	m := Message{From: ss.from, To: append([]string(nil), ss.to...), Data: b.String(), TLS: ss.tls}
	if ss.s.opt.DropAtFinalDot {
		ss.s.mu.Lock()
		ss.s.unacked = append(ss.s.unacked, m)
		ss.s.mu.Unlock()
		return false
	}
	final := orDefault(ss.s.opt.FinalReply, "250 2.0.0 queued")
	if strings.HasPrefix(final, "2") {
		ss.s.mu.Lock()
		ss.s.messages = append(ss.s.messages, m)
		ss.s.mu.Unlock()
		if ss.s.opt.OnMessage != nil {
			ss.s.opt.OnMessage(m)
		}
	}
	ss.from, ss.to = "", nil
	ss.reply("%s", final)
	return !ss.s.opt.DropAfterFinalReply
}
