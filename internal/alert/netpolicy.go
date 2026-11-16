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
// Embedded IPv4 (milestone 6, plan 4.9): an IPv6 address that carries an IPv4
// address must not be a way round the IPv4 rules. classify decodes the forms it
// can (IPv4-mapped, the well-known NAT64 prefix 64:ff9b::/96 and any translation
// prefix the operator lists in alert.webhook.nat64_prefixes), blocks the forms
// that cannot be judged (6to4, Teredo, IPv4-compatible, SIIT, and the local-use
// NAT64 range 64:ff9b:1::/48 unless listed), and every check below runs on BOTH
// the address as dialled and the IPv4 inside it: the most restrictive result wins.
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
	// DenyNetworks are extra prefixes that are always blocked. They are matched
	// against the dialled address and against the IPv4 embedded in it.
	DenyNetworks []netip.Prefix
	// NAT64Prefixes are the operator's own translation prefixes (alert.webhook.
	// nat64_prefixes: /32, /40, /48, /56, /64 or /96, RFC 6052). An address under
	// one is decoded and judged by its IPv4. 64:ff9b::/96 needs no entry.
	NAT64Prefixes []netip.Prefix
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

var (
	wellKnownNAT64 = netip.MustParsePrefix("64:ff9b::/96")
	// localUseNAT64 (RFC 8215): the translator's prefix length is unknown, so the
	// IPv4 destination cannot be read from the address.
	localUseNAT64 = netip.MustParsePrefix("64:ff9b:1::/48")
	// deprecatedEmbedding lists forms that carry an IPv4 address in a way no
	// legitimate receiver needs: 6to4, Teredo and SIIT. IPv4-compatible (::/96) is
	// checked in classify because it must not catch :: and ::1.
	deprecatedEmbedding = []struct {
		pf   netip.Prefix
		name string
	}{
		{netip.MustParsePrefix("2002::/16"), "6to4 (2002::/16)"},
		{netip.MustParsePrefix("2001::/32"), "Teredo (2001::/32)"},
		{netip.MustParsePrefix("::ffff:0:0:0/96"), "SIIT (::ffff:0:0:0/96)"},
	}
	ipv4Compatible = netip.MustParsePrefix("::/96")
)

// ValidNAT64Length reports whether bits is a prefix length RFC 6052 allows.
func ValidNAT64Length(bits int) bool {
	switch bits {
	case 32, 40, 48, 56, 64, 96:
		return true
	}
	return false
}

// decodeRFC6052 reads the IPv4 address embedded in a under a prefix of the given
// length (RFC 6052 section 2.2: the address bits skip bits 64-71, the "u" octet,
// which must be zero). ok is false when the u octet is not zero.
func decodeRFC6052(a netip.Addr, bits int) (netip.Addr, bool) {
	b := a.As16()
	if b[8] != 0 {
		return netip.Addr{}, false
	}
	var v4 [4]byte
	switch bits {
	case 32:
		copy(v4[:], b[4:8])
	case 40:
		copy(v4[:3], b[5:8])
		v4[3] = b[9]
	case 48:
		copy(v4[:2], b[6:8])
		copy(v4[2:], b[9:11])
	case 56:
		v4[0] = b[7]
		copy(v4[1:], b[9:12])
	case 64:
		copy(v4[:], b[9:13])
	case 96:
		copy(v4[:], b[12:16])
	default:
		return netip.Addr{}, false
	}
	return netip.AddrFrom4(v4), true
}

// classify returns the forms of a that every rule is checked against: a itself,
// followed by the IPv4 address embedded in it when there is one. blocked is a
// non-empty reason when the address cannot be judged at all (a deprecated form, a
// local-use NAT64 address of an unknown translator, a bad u octet).
//
// Rule: IPv4-mapped (::ffff:a.b.c.d) is judged as a.b.c.d only, as it always was.
func classify(a netip.Addr, nat64 []netip.Prefix) (forms []netip.Addr, blocked string) {
	a = a.WithZone("")
	if !a.IsValid() {
		return nil, ""
	}
	if a.Is4In6() {
		return []netip.Addr{a.Unmap()}, ""
	}
	if a.Is4() {
		return []netip.Addr{a}, ""
	}
	for _, d := range deprecatedEmbedding {
		if d.pf.Contains(a) {
			return []netip.Addr{a}, "is a " + d.name + " address, which embeds an IPv4 address and is always blocked"
		}
	}
	if ipv4Compatible.Contains(a) && !a.IsUnspecified() && !a.IsLoopback() {
		return []netip.Addr{a}, "is an IPv4-compatible address (::/96), which embeds an IPv4 address and is always blocked"
	}
	// The operator's own prefixes first: they are more specific than the local-use range they may sit in.
	for _, pf := range nat64 {
		if pf.Contains(a) {
			v4, ok := decodeRFC6052(a, pf.Bits())
			if !ok {
				return []netip.Addr{a}, "is under the NAT64 prefix " + pf.String() + " but its bits 64-71 are not zero (RFC 6052), so the IPv4 address cannot be read"
			}
			return []netip.Addr{a, v4}, ""
		}
	}
	if wellKnownNAT64.Contains(a) {
		v4, _ := decodeRFC6052(a, 96)
		return []netip.Addr{a, v4}, ""
	}
	if localUseNAT64.Contains(a) {
		return []netip.Addr{a}, "is in the local-use NAT64 range 64:ff9b:1::/48 and its translator is not listed: the IPv4 destination cannot be known; list the translator's prefix in alert.webhook.nat64_prefixes"
	}
	return []netip.Addr{a}, ""
}

// Effective returns the address the rules judge a by: the IPv4 embedded in a
// translation address, otherwise a (unmapped). The error is the reason when a
// cannot be judged at all.
func (p Policy) Effective(a netip.Addr) (netip.Addr, error) {
	forms, why := classify(a, p.NAT64Prefixes)
	if why != "" {
		return netip.Addr{}, &PermanentError{Code: "blocked", Msg: "address " + a.WithZone("").String() + " " + why}
	}
	if len(forms) == 0 {
		return netip.Addr{}, &PermanentError{Code: "blocked", Msg: "address is not valid"}
	}
	return forms[len(forms)-1], nil
}

// CheckAddr returns nil when a webhook may connect to a, otherwise a
// *PermanentError with code "blocked" whose text names the reason. The text
// may name the address: it is only ever shown to admins.
//
// Every rule applies to every form of the address (see classify); the loopback
// and private switches are judged on the embedded IPv4 when there is one, since
// the translation address itself is a global unicast address.
func (p Policy) CheckAddr(a netip.Addr) error {
	forms, why := classify(a, p.NAT64Prefixes)
	if len(forms) == 0 {
		return &PermanentError{Code: "blocked", Msg: "address is not valid"}
	}
	blocked := func(f netip.Addr, why string) error {
		msg := "address " + a.WithZone("").Unmap().String() + " "
		if f != a.WithZone("").Unmap() {
			msg += "(embedded IPv4 " + f.String() + ") "
		}
		return &PermanentError{Code: "blocked", Msg: msg + why}
	}
	if why != "" {
		return blocked(forms[0], why)
	}
	for _, f := range forms {
		switch {
		case f.IsUnspecified():
			return blocked(f, "is unspecified and is always blocked")
		case f.IsLinkLocalUnicast() || f.IsLinkLocalMulticast():
			return blocked(f, "is link-local (cloud metadata lives here) and is always blocked")
		case f.IsMulticast() || f.IsInterfaceLocalMulticast():
			return blocked(f, "is multicast and is always blocked")
		}
		for _, pf := range alwaysBlockedPrefixes {
			if pf.Contains(f) {
				return blocked(f, "is in "+pf.String()+" (special-purpose) and is always blocked")
			}
		}
		for _, m := range metadataAddrs {
			if f == m {
				return blocked(f, "is a cloud metadata or platform endpoint and is always blocked")
			}
		}
		for _, pf := range p.DenyNetworks {
			if pf.Contains(f) {
				return blocked(f, "is in "+pf.String()+" (alert.webhook.deny_networks)")
			}
		}
	}
	judged := forms[len(forms)-1]
	if judged.IsLoopback() {
		if !p.AllowLoopback {
			return blocked(judged, "is loopback; set alert.webhook.allow_loopback to allow it")
		}
		return nil
	}
	if isPrivate(judged) && !p.AllowPrivate {
		return blocked(judged, "is a private address; set alert.webhook.allow_private to allow it")
	}
	return nil
}

// CheckPlaintext applies decision 19 to an address: plaintext (http, SMTP
// without TLS) only to loopback and private addresses, never to a public one.
// It judges a translation address by the IPv4 inside it, so a NAT64 form of a
// public address is public.
func (p Policy) CheckPlaintext(a netip.Addr) error {
	j, err := p.Effective(a)
	if err != nil {
		return err
	}
	if j.IsLoopback() || isPrivate(j) {
		return nil
	}
	return &PermanentError{Code: "plaintext", Msg: "address " + a.WithZone("").Unmap().String() + " is public: plaintext connections are only allowed to loopback and private addresses, use https"}
}

// CheckPlaintext is Policy{}.CheckPlaintext: for callers that have no translation prefixes.
func CheckPlaintext(a netip.Addr) error { return Policy{}.CheckPlaintext(a) }

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
			return p.CheckPlaintext(a)
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
		a = a.WithZone("").Unmap()
		e := d.Policy.CheckAddr(a)
		if e == nil && d.Plaintext {
			e = d.Policy.CheckPlaintext(a)
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
