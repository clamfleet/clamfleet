// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package testldap is a minimal in-process LDAP server for tests and for the browser
// fixture (docs/plans/milestone-6.md section 2, "6b, new"). It speaks just enough of
// LDAPv3 for ClamFleet's search-then-bind sign-in: simple bind, search with the filters
// of RFC 4511 (and, or, not, equality, presence, substrings), the StartTLS extended
// operation, and unbind. It uses the BER package that comes with go-ldap.
//
// What makes it a test tool and not a toy: it RECORDS every bind and every search (the
// filter exactly as it arrived on the wire, decompiled), whether the bind came over TLS,
// and the StartTLS requests, and it can be scripted to misbehave (refuse StartTLS,
// fail every bind with a result code, answer slowly, go away). The tests assert on what
// the server saw: that an empty password sent no bind at all, that the filter arrived
// escaped, that a refused StartTLS was never followed by a password in clear.
//
// It is not a directory: no schema, no ACLs, attribute matching is a case-insensitive
// string compare, the extensible match (the AD nested-group rule) is not supported.
// Listens on 127.0.0.1 only. Never use it outside tests.
package testldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// OIDStartTLS is the StartTLS extended operation (RFC 4511 section 4.14).
const OIDStartTLS = "1.3.6.1.4.1.1466.20037"

// Options configure Start.
type Options struct {
	// CertFile and KeyFile are the server certificate (internal/testtls). Without them the
	// server has no TLS and answers a StartTLS request with an error.
	CertFile, KeyFile string
	// Implicit makes the listener speak TLS from the first byte (ldaps://).
	Implicit bool
}

// BindRecord is one bind the server received.
type BindRecord struct {
	DN       string
	Password string
	TLS      bool // the connection was encrypted (ldaps, or after StartTLS)
	Code     uint16
}

// SearchRecord is one search the server received.
type SearchRecord struct {
	Base      string
	Scope     int
	Filter    string // decompiled from the wire: shows what was escaped
	Attrs     []string
	SizeLimit int
	TLS       bool
	AsDN      string // the DN of the last successful bind on the connection ("" = anonymous)
}

type entry struct {
	dn       string
	attrs    map[string][][]byte // keyed by lower-case attribute name
	names    map[string]string   // lower-case -> the spelling given
	password string
}

// Server is a running fake directory.
type Server struct {
	l    net.Listener
	opts Options
	cfg  *tls.Config

	mu        sync.Mutex
	entries   map[string]*entry // by normalised DN
	binds     []BindRecord
	searches  []SearchRecord
	startTLS  int
	refuseTLS bool
	failBind  uint16
	delay     time.Duration
	conns     map[net.Conn]bool
	closed    bool
	wg        sync.WaitGroup
}

// Start listens on 127.0.0.1 with a free port.
func Start(o Options) (*Server, error) {
	s := &Server{opts: o, entries: map[string]*entry{}, conns: map[net.Conn]bool{}}
	if o.CertFile != "" {
		c, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return nil, err
		}
		s.cfg = &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12}
	} else if o.Implicit {
		return nil, errors.New("testldap: Implicit needs a certificate")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.l = l
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

// Addr is host:port.
func (s *Server) Addr() string { return s.l.Addr().String() }

// URL is ldap://127.0.0.1:port, or ldaps:// for an implicit-TLS server.
func (s *Server) URL() string {
	if s.opts.Implicit {
		return "ldaps://" + s.Addr()
	}
	return "ldap://" + s.Addr()
}

// Close stops the listener and every connection, and waits for the handlers.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.l.Close()
	s.wg.Wait()
}

// NormalizeDN is how the fake compares DNs: case-folded, spaces around = and , removed.
func NormalizeDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		for j := range kv {
			kv[j] = strings.TrimSpace(kv[j])
		}
		parts[i] = strings.Join(kv, "=")
	}
	return strings.ToLower(strings.Join(parts, ","))
}

// Add creates or replaces an entry. attrs maps attribute names to values.
func (s *Server) Add(dn string, attrs map[string][]string) {
	e := &entry{dn: dn, attrs: map[string][][]byte{}, names: map[string]string{}}
	for k, vs := range attrs {
		for _, v := range vs {
			e.add(k, []byte(v))
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[NormalizeDN(dn)] = e
}

func (e *entry) add(name string, v []byte) {
	l := strings.ToLower(name)
	e.attrs[l] = append(e.attrs[l], v)
	e.names[l] = name
}

// SetPassword sets the password the entry binds with.
func (s *Server) SetPassword(dn, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.entries[NormalizeDN(dn)]; e != nil {
		e.password = password
	}
}

// SetAttr replaces an attribute's values (strings).
func (s *Server) SetAttr(dn, attr string, vals ...string) {
	raw := make([][]byte, len(vals))
	for i, v := range vals {
		raw[i] = []byte(v)
	}
	s.SetRawAttr(dn, attr, raw...)
}

// SetRawAttr replaces an attribute's values (binary, such as objectGUID).
func (s *Server) SetRawAttr(dn, attr string, vals ...[]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[NormalizeDN(dn)]
	if e == nil {
		return
	}
	l := strings.ToLower(attr)
	if len(vals) == 0 {
		delete(e.attrs, l)
		return
	}
	e.attrs[l], e.names[l] = vals, attr
}

// Rename moves an entry to a new DN, keeping its attributes and password (a rename in the directory).
func (s *Server) Rename(oldDN, newDN string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[NormalizeDN(oldDN)]
	if e == nil {
		return
	}
	delete(s.entries, NormalizeDN(oldDN))
	e.dn = newDN
	s.entries[NormalizeDN(newDN)] = e
}

// Remove deletes an entry.
func (s *Server) Remove(dn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, NormalizeDN(dn))
}

// RefuseStartTLS makes the server answer the StartTLS request with an error (unwillingToPerform).
func (s *Server) RefuseStartTLS(v bool) { s.mu.Lock(); s.refuseTLS = v; s.mu.Unlock() }

// FailBinds makes every bind answer with result code c (0 = normal behaviour), e.g. 51 busy.
func (s *Server) FailBinds(c uint16) { s.mu.Lock(); s.failBind = c; s.mu.Unlock() }

// Delay makes every operation wait this long before answering.
func (s *Server) Delay(d time.Duration) { s.mu.Lock(); s.delay = d; s.mu.Unlock() }

// Binds, Searches and StartTLSRequests return what the server saw since Start or Reset.
func (s *Server) Binds() []BindRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]BindRecord(nil), s.binds...)
}

// Searches returns the recorded searches.
func (s *Server) Searches() []SearchRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]SearchRecord(nil), s.searches...)
}

// StartTLSRequests counts StartTLS extended requests.
func (s *Server) StartTLSRequests() int { s.mu.Lock(); defer s.mu.Unlock(); return s.startTLS }

// Reset forgets the recorded binds, searches and StartTLS requests.
func (s *Server) Reset() {
	s.mu.Lock()
	s.binds, s.searches, s.startTLS = nil, nil, 0
	s.mu.Unlock()
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.l.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.conns[c] = true
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serve(c)
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
		}()
	}
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	isTLS := false
	if s.opts.Implicit {
		c = tls.Server(c, s.cfg)
		isTLS = true
	}
	asDN := ""
	for {
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		s.mu.Lock()
		delay := s.delay
		s.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		switch int(op.Tag) {
		case ldap.ApplicationUnbindRequest:
			return
		case ldap.ApplicationBindRequest:
			code := s.handleBind(op, isTLS, &asDN)
			if _, err := c.Write(message(id, result(ldap.ApplicationBindResponse, code, ""))); err != nil {
				return
			}
		case ldap.ApplicationSearchRequest:
			if !s.handleSearch(c, id, op, isTLS, asDN) {
				return
			}
		case ldap.ApplicationExtendedRequest:
			oid := ""
			if len(op.Children) > 0 {
				oid = op.Children[0].Data.String()
			}
			if oid != OIDStartTLS {
				if _, err := c.Write(message(id, result(ldap.ApplicationExtendedResponse, ldap.LDAPResultProtocolError, "unsupported extended operation"))); err != nil {
					return
				}
				continue
			}
			s.mu.Lock()
			s.startTLS++
			refuse := s.refuseTLS || s.cfg == nil || isTLS
			s.mu.Unlock()
			if refuse {
				if _, err := c.Write(message(id, result(ldap.ApplicationExtendedResponse, ldap.LDAPResultUnwillingToPerform, "TLS not available"))); err != nil {
					return
				}
				continue
			}
			resp := result(ldap.ApplicationExtendedResponse, 0, "")
			resp.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.Tag(10), OIDStartTLS, "responseName"))
			if _, err := c.Write(message(id, resp)); err != nil {
				return
			}
			c = tls.Server(c, s.cfg)
			isTLS = true
		default:
			return
		}
	}
}

func (s *Server) handleBind(op *ber.Packet, isTLS bool, asDN *string) uint16 {
	if len(op.Children) < 3 {
		return ldap.LDAPResultProtocolError
	}
	dn := op.Children[1].Data.String()
	pw := op.Children[2].Data.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	code := uint16(0)
	switch e := s.entries[NormalizeDN(dn)]; {
	case s.failBind != 0:
		code = s.failBind
	case dn == "" && pw == "":
		// Anonymous bind.
	case pw == "":
		// RFC 4513 section 5.1.2: an unauthenticated bind "succeeds". The real client must
		// never send one; the record shows whether it did.
	case e == nil || e.password == "" || e.password != pw:
		code = ldap.LDAPResultInvalidCredentials
	}
	s.binds = append(s.binds, BindRecord{DN: dn, Password: pw, TLS: isTLS, Code: code})
	if code == 0 && pw != "" {
		*asDN = dn
	}
	return code
}

func (s *Server) handleSearch(c net.Conn, id int64, op *ber.Packet, isTLS bool, asDN string) bool {
	if len(op.Children) < 8 {
		return false
	}
	base := op.Children[0].Data.String()
	scope, _ := op.Children[1].Value.(int64)
	sizeLimit, _ := op.Children[3].Value.(int64)
	filterText, err := ldap.DecompileFilter(op.Children[6])
	if err != nil {
		return false
	}
	var attrs []string
	for _, a := range op.Children[7].Children {
		attrs = append(attrs, a.Data.String())
	}
	s.mu.Lock()
	s.searches = append(s.searches, SearchRecord{Base: base, Scope: int(scope), Filter: filterText, Attrs: attrs, SizeLimit: int(sizeLimit), TLS: isTLS, AsDN: asDN})
	var hits []*entry
	nb := NormalizeDN(base)
	for _, e := range s.entries {
		ne := NormalizeDN(e.dn)
		in := false
		switch scope {
		case 0:
			in = ne == nb
		case 1:
			in = strings.HasSuffix(ne, ","+nb) && !strings.Contains(strings.TrimSuffix(ne, ","+nb), ",")
		default:
			in = ne == nb || strings.HasSuffix(ne, ","+nb) || nb == ""
		}
		if in && match(op.Children[6], e) {
			hits = append(hits, e)
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].dn < hits[j].dn })
	code := uint16(0)
	if sizeLimit > 0 && int64(len(hits)) > sizeLimit {
		hits, code = hits[:sizeLimit], ldap.LDAPResultSizeLimitExceeded
	}
	var out [][]byte
	for _, e := range hits {
		out = append(out, message(id, entryPacket(e, attrs)))
	}
	s.mu.Unlock()
	for _, b := range out {
		if _, err := c.Write(b); err != nil {
			return false
		}
	}
	_, err = c.Write(message(id, result(ldap.ApplicationSearchResultDone, code, "")))
	return err == nil
}

func entryPacket(e *entry, want []string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldap.ApplicationSearchResultEntry), nil, "entry")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, "dn"))
	list := ber.NewSequence("attributes")
	all := len(want) == 0
	for _, w := range want {
		all = all || w == "*"
	}
	names := make([]string, 0, len(e.attrs))
	for l := range e.attrs {
		names = append(names, l)
	}
	sort.Strings(names)
	for _, l := range names {
		wanted := all
		for _, w := range want {
			wanted = wanted || strings.EqualFold(w, l)
		}
		if !wanted {
			continue
		}
		a := ber.NewSequence("attribute")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.names[l], "type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		for _, v := range e.attrs[l] {
			set.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(v), "val"))
		}
		a.AppendChild(set)
		list.AppendChild(a)
	}
	p.AppendChild(list)
	return p
}

// match evaluates a filter packet against an entry.
func match(f *ber.Packet, e *entry) bool {
	if f.ClassType != ber.ClassContext {
		return false
	}
	vals := func(attr string) [][]byte { return e.attrs[strings.ToLower(attr)] }
	switch f.Tag {
	case 0: // and
		for _, c := range f.Children {
			if !match(c, e) {
				return false
			}
		}
		return true
	case 1: // or
		for _, c := range f.Children {
			if match(c, e) {
				return true
			}
		}
		return false
	case 2: // not
		return len(f.Children) == 1 && !match(f.Children[0], e)
	case 3, 8: // equality, approx
		if len(f.Children) != 2 {
			return false
		}
		want := f.Children[1].Data.String()
		for _, v := range vals(f.Children[0].Data.String()) {
			if strings.EqualFold(string(v), want) {
				return true
			}
		}
		return false
	case 7: // present
		return len(vals(f.Data.String())) > 0
	case 4: // substrings
		if len(f.Children) != 2 {
			return false
		}
		for _, v := range vals(f.Children[0].Data.String()) {
			if substrings(strings.ToLower(string(v)), f.Children[1].Children) {
				return true
			}
		}
		return false
	}
	return false // greater/less/extensible match: not supported by the fake
}

func substrings(v string, parts []*ber.Packet) bool {
	for _, p := range parts {
		s := strings.ToLower(p.Data.String())
		switch p.Tag {
		case 0:
			if !strings.HasPrefix(v, s) {
				return false
			}
			v = v[len(s):]
		case 1:
			i := strings.Index(v, s)
			if i < 0 {
				return false
			}
			v = v[i+len(s):]
		case 2:
			if !strings.HasSuffix(v, s) {
				return false
			}
		}
	}
	return true
}

func message(id int64, op *ber.Packet) []byte {
	p := ber.NewSequence("LDAPMessage")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "messageID"))
	p.AppendChild(op)
	return p.Bytes()
}

func result(tag int, code uint16, diag string) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(tag), nil, "result")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), "resultCode"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diag, "diagnosticMessage"))
	return op
}

// String describes the server for failure messages.
func (s *Server) String() string { return fmt.Sprintf("testldap %s", s.URL()) }
