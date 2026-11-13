// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// netpolicy.go: where a webhook may connect (SSRF defence, plan 4.7) and the
// resolve-filter-dial step that enforces it at connection time.
//
// Why our own dial step: if a hostname is handed to net.Dialer, the resolver
// picks the address after any check we did, and a DNS answer that changes
// between the check and the connect (rebinding) wins. So the transport's
// DialContext resolves the name itself, drops every answer the policy blocks,
// and dials the survivors as IP literals. A second layer, Dialer.ControlContext,
// checks the socket address once more and catches any path that bypassed the
// first. Each new connection resolves again.
//
// The policy cannot know every provider's or network's internal services; it
// blocks what is certain (link-local, metadata endpoints, unspecified,
// multicast, loopback unless allowed) and lets the operator add networks
// (deny_networks) or turn private networks off. An egress firewall remains the
// stronger control (docs/alerts.md).
//
// NOT decoded (known gap, plan A3): NAT64 (64:ff9b::/96) and other embedded-IPv4
// forms of a blocked IPv4 address. IPv4-mapped (::ffff:a.b.c.d) is handled by Unmap.
package alert

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// Policy decides which destination addresses a webhook may reach.
type Policy struct {
	// AllowPrivate allows RFC 1918, 100.64.0.0/10 and fc00::/7. It also governs
	// plaintext to private addresses (decision 19): off means https to public
	// addresses only, plus loopback when AllowLoopback is on.
	AllowPrivate bool
	// AllowLoopback allows 127.0.0.0/8, ::1 and the localhost names.
	AllowLoopback bool
	// DenyNetworks are extra prefixes that are always blocked.
	DenyNetworks []netip.Prefix
}

var (
	// alwaysBlockedPrefixes: never reachable, whatever the switches say.
	// 192.0.0.0/24 is IANA special-purpose (it holds an old Oracle Cloud
	// metadata address, 192.0.0.192). Link-local is covered by IsLinkLocalUnicast.
	alwaysBlockedPrefixes = []netip.Prefix{
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("255.255.255.255/32"),
	}
	// metadataAddrs are cloud metadata and platform endpoints that fall OUTSIDE
	// link-local, so the link-local rule does not catch them [plan A12]:
	//   100.100.100.200  Alibaba Cloud metadata (inside CGNAT)
	//   fd00:ec2::254    AWS IMDS over IPv6 (inside ULA)
	//   168.63.129.16    Azure WireServer / platform DNS (a public address)
	// 169.254.169.254 (most providers) and 169.254.170.2 (AWS ECS) are link-local.
	metadataAddrs = []netip.Addr{
		netip.MustParseAddr("100.100.100.200"),
		netip.MustParseAddr("fd00:ec2::254"),
		netip.MustParseAddr("168.63.129.16"),
	}
	cgnat = netip.MustParsePrefix("100.64.0.0/10")
)

// isPrivate covers RFC 1918, fc00::/7 and the carrier-grade NAT range.
func isPrivate(a netip.Addr) bool { return a.IsPrivate() || cgnat.Contains(a) }

// normalize strips the IPv4-mapped form and any zone, so ::ffff:127.0.0.1 is
// judged as 127.0.0.1.
func normalize(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

// CheckAddr returns nil when a webhook may connect to a, otherwise a
// *PermanentError with code "blocked" whose text names the reason. The text
// may name the address: it is only ever shown to admins.
func (p Policy) CheckAddr(a netip.Addr) error {
	a = normalize(a)
	blocked := func(why string) error {
		return &PermanentError{Code: "blocked", Msg: "address " + a.String() + " " + why}
	}
	switch {
	case !a.IsValid():
		return &PermanentError{Code: "blocked", Msg: "address is not valid"}
	case a.IsUnspecified():
		return blocked("is unspecified and is always blocked")
	case a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast():
		return blocked("is link-local (cloud metadata lives here) and is always blocked")
	case a.IsMulticast() || a.IsInterfaceLocalMulticast():
		return blocked("is multicast and is always blocked")
	}
	for _, pf := range alwaysBlockedPrefixes {
		if pf.Contains(a) {
			return blocked("is in " + pf.String() + " (special-purpose) and is always blocked")
		}
	}
	for _, m := range metadataAddrs {
		if a == m {
			return blocked("is a cloud metadata or platform endpoint and is always blocked")
		}
	}
	for _, pf := range p.DenyNetworks {
		if pf.Contains(a) {
			return blocked("is in " + pf.String() + " (alert.webhook.deny_networks)")
		}
	}
	if a.IsLoopback() {
		if !p.AllowLoopback {
			return blocked("is loopback; set alert.webhook.allow_loopback to allow it")
		}
		return nil
	}
	if isPrivate(a) && !p.AllowPrivate {
		return blocked("is a private address; set alert.webhook.allow_private to allow it")
	}
	return nil
}

// CheckPlaintext applies decision 19 to an address: plaintext (http, SMTP
// without TLS) only to loopback and private addresses, never to a public one.
func CheckPlaintext(a netip.Addr) error {
	a = normalize(a)
	if a.IsLoopback() || isPrivate(a) {
		return nil
	}
	return &PermanentError{Code: "plaintext", Msg: "address " + a.String() + " is public: plaintext connections are only allowed to loopback and private addresses, use https"}
}

// Resolver is the part of net.Resolver the dial step needs; tests script it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialFunc connects to an address. net.Dialer.DialContext fits.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// ControlFunc returns the ControlContext of the second layer: it checks the
// address the socket is about to connect to, once more, against the policy
// (and the plaintext rule when plaintext is set).
func ControlFunc(p Policy, plaintext bool) func(ctx context.Context, network, address string, c syscall.RawConn) error {
	return func(_ context.Context, _, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return &PermanentError{Code: "blocked", Msg: "cannot check the connection address"}
		}
		a, err := netip.ParseAddr(host)
		if err != nil {
			return &PermanentError{Code: "blocked", Msg: "the connection address is not an IP literal"}
		}
		if err := p.CheckAddr(a); err != nil {
			return err
		}
		if plaintext {
			return CheckPlaintext(a)
		}
		return nil
	}
}

// NetDialer builds the production dialer: connect timeout, and the policy as
// ControlContext (the second layer).
func NetDialer(p Policy, plaintext bool, timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, ControlContext: ControlFunc(p, plaintext)}
}

// SafeDialer is the resolve-filter-dial step.
type SafeDialer struct {
	Policy Policy
	// Plaintext: the connection carries no TLS, so decision 19 applies on top of
	// the policy (the dialled address must be loopback or private).
	Plaintext bool
	// Resolver resolves host names; nil means net.DefaultResolver.
	Resolver Resolver
	// Dial connects to a chosen IP literal; nil means NetDialer(...).DialContext.
	Dial DialFunc
	// Timeout is the whole dial budget, shared between the addresses.
	Timeout time.Duration
}

// DialContext resolves addr's host, drops every blocked answer and dials the
// rest in order as IP literals, IPv6 and IPv4 interleaved. No answer left is a
// permanent "blocked" error and NO connection is attempted.
func (d *SafeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, &PermanentError{Code: "blocked", Msg: "the destination address is not valid"}
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	var answers []netip.Addr
	if ip, perr := netip.ParseAddr(host); perr == nil {
		answers = []netip.Addr{ip}
	} else {
		r := d.Resolver
		if r == nil {
			r = net.DefaultResolver
		}
		if answers, err = r.LookupNetIP(ctx, "ip", host); err != nil {
			return nil, err
		}
	}

	var allowed []netip.Addr
	var firstBlock error
	for _, a := range answers {
		a = normalize(a)
		e := d.Policy.CheckAddr(a)
		if e == nil && d.Plaintext {
			e = CheckPlaintext(a)
		}
		if e != nil {
			if firstBlock == nil {
				firstBlock = e
			}
			continue
		}
		allowed = append(allowed, a)
	}
	if len(allowed) == 0 {
		if firstBlock == nil {
			return nil, &PermanentError{Code: "dns", Msg: "the host name resolved to no address"}
		}
		return nil, firstBlock
	}
	allowed = interleave(allowed)

	dial := d.Dial
	if dial == nil {
		dial = NetDialer(d.Policy, d.Plaintext, timeout).DialContext
	}
	share := max(timeout/time.Duration(len(allowed)), 500*time.Millisecond)
	var last error
	for _, a := range allowed {
		actx, cancel := context.WithTimeout(ctx, share)
		c, err := dial(actx, network, net.JoinHostPort(a.String(), port))
		cancel()
		if err == nil {
			return c, nil
		}
		var perm *PermanentError
		if errors.As(err, &perm) {
			return nil, err // the second layer refused: do not try further
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

// interleave alternates the address families, starting with the first answer's,
// keeping each family's order (a simple Happy Eyeballs ordering).
func interleave(in []netip.Addr) []netip.Addr {
	var v4, v6 []netip.Addr
	for _, a := range in {
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	first, second := v6, v4
	if in[0].Is4() {
		first, second = v4, v6
	}
	out := make([]netip.Addr, 0, len(in))
	for i := 0; i < len(first) || i < len(second); i++ {
		if i < len(first) {
			out = append(out, first[i])
		}
		if i < len(second) {
			out = append(out, second[i])
		}
	}
	return out
}

// isLocalhostName reports whether a host name is localhost, localhost. or
// *.localhost (RFC 6761: resolvers may map these to loopback).
func isLocalhostName(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}
