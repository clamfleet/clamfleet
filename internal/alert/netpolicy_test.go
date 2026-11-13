// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package alert

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func defaultPolicy() Policy { return Policy{AllowPrivate: true} }

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// The address table of 6.1. Mutations 24 (no Unmap) and 25 (metadata entries
// dropped) fail here.
func TestPolicyCheckAddr(t *testing.T) {
	cases := []struct {
		addr string
		p    Policy
		ok   bool
	}{
		// Blocked by default.
		{"127.0.0.1", defaultPolicy(), false}, {"127.9.9.9", defaultPolicy(), false}, {"::1", defaultPolicy(), false},
		{"::ffff:127.0.0.1", defaultPolicy(), false}, {"0.0.0.0", defaultPolicy(), false}, {"::", defaultPolicy(), false},
		{"169.254.169.254", defaultPolicy(), false}, {"169.254.170.2", defaultPolicy(), false}, {"fe80::1", defaultPolicy(), false},
		{"224.0.0.1", defaultPolicy(), false}, {"ff02::1", defaultPolicy(), false}, {"255.255.255.255", defaultPolicy(), false},
		{"192.0.0.192", defaultPolicy(), false}, {"::ffff:169.254.169.254", defaultPolicy(), false},
		// Metadata outside link-local: blocked even with allow_private.
		{"100.100.100.200", defaultPolicy(), false}, {"fd00:ec2::254", defaultPolicy(), false}, {"168.63.129.16", defaultPolicy(), false},
		{"::ffff:100.100.100.200", defaultPolicy(), false}, {"::ffff:168.63.129.16", defaultPolicy(), false},
		// ...and with every switch on.
		{"169.254.169.254", Policy{AllowPrivate: true, AllowLoopback: true}, false},
		{"100.100.100.200", Policy{AllowPrivate: true, AllowLoopback: true}, false},
		// Private: allowed by default, blocked with allow_private=false.
		{"10.1.2.3", defaultPolicy(), true}, {"172.16.0.1", defaultPolicy(), true}, {"192.168.1.1", defaultPolicy(), true},
		{"100.64.0.1", defaultPolicy(), true}, {"100.100.100.199", defaultPolicy(), true}, {"fc00::1", defaultPolicy(), true},
		{"fd00:ec2::253", defaultPolicy(), true}, {"::ffff:10.0.0.5", defaultPolicy(), true},
		{"10.1.2.3", Policy{}, false}, {"100.64.0.1", Policy{}, false}, {"fc00::1", Policy{}, false}, {"192.168.1.1", Policy{}, false},
		// Loopback with its switch.
		{"127.0.0.1", Policy{AllowLoopback: true}, true}, {"::1", Policy{AllowLoopback: true}, true},
		{"::ffff:127.0.0.1", Policy{AllowLoopback: true}, true},
		// Public.
		{"203.0.113.5", defaultPolicy(), true}, {"8.8.8.8", Policy{}, true}, {"2606:4700::1111", Policy{}, true},
		// deny_networks blocks an otherwise allowed private address.
		{"10.9.9.9", Policy{AllowPrivate: true, DenyNetworks: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")}}, false},
		{"10.8.9.9", Policy{AllowPrivate: true, DenyNetworks: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")}}, true},
		{"203.0.113.5", Policy{DenyNetworks: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}, false},
	}
	for _, c := range cases {
		err := c.p.CheckAddr(mustAddr(c.addr))
		if (err == nil) != c.ok {
			t.Errorf("%s with %+v: err=%v, want ok=%v", c.addr, c.p, err, c.ok)
		}
		if err != nil {
			var perm *PermanentError
			if !errors.As(err, &perm) || perm.Code != "blocked" {
				t.Errorf("%s: want a permanent 'blocked' error, got %v", c.addr, err)
			}
		}
	}
	if err := (Policy{}).CheckAddr(mustAddr("127.0.0.1")); err == nil || !strings.Contains(err.Error(), "allow_loopback") {
		t.Errorf("the reason must name the switch: %v", err)
	}
}

// Decision 19: plaintext only to loopback or private addresses.
func TestCheckPlaintext(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1": true, "::1": true, "10.0.0.5": true, "192.168.0.9": true, "100.64.1.1": true, "fd12::1": true,
		"::ffff:10.0.0.5": true, "203.0.113.5": false, "8.8.8.8": false, "2606:4700::1111": false, "::ffff:8.8.8.8": false,
	} {
		if err := CheckPlaintext(mustAddr(addr)); (err == nil) != ok {
			t.Errorf("%s: %v, want ok=%v", addr, err, ok)
		}
	}
}

// URL validation (6.1). No error may contain the URL: a marker in the path is
// absent from every error string.
func TestValidateWebhookURL(t *testing.T) {
	const marker = "TOKEN-MARKER"
	long := "https://hooks.example/" + strings.Repeat("a", 2049-len("https://hooks.example/"))
	cases := []struct {
		name, url string
		p         Policy
		ok        bool
	}{
		{"https hostname", "https://hooks.example/T/" + marker, defaultPolicy(), true},
		{"https with port", "https://hooks.example:8443/x/" + marker, defaultPolicy(), true},
		{"http private literal", "http://10.0.0.5:8080/" + marker, defaultPolicy(), true},
		{"http hostname (checked at dial)", "http://receiver.lan/" + marker, defaultPolicy(), true},
		{"https public literal", "https://203.0.113.5/" + marker, defaultPolicy(), true},
		{"userinfo", "https://user:pw@hooks.example/" + marker, defaultPolicy(), false},
		{"userinfo name only", "https://" + marker + "@hooks.example/", defaultPolicy(), false},
		{"ftp", "ftp://hooks.example/" + marker, defaultPolicy(), false},
		{"no scheme", "hooks.example/" + marker, defaultPolicy(), false},
		{"no host", "https:///" + marker, defaultPolicy(), false},
		{"fragment", "https://hooks.example/x?" + marker + "#frag", defaultPolicy(), false},
		{"empty fragment", "https://hooks.example/x/" + marker + "#", defaultPolicy(), false},
		{"2049 bytes", long, defaultPolicy(), false},
		{"space", "https://hooks.example/a b/" + marker, defaultPolicy(), false},
		{"control char", "https://hooks.example/\x01" + marker, defaultPolicy(), false},
		{"localhost", "http://localhost:8080/" + marker, defaultPolicy(), false},
		{"LOCALHOST.", "http://LOCALHOST./" + marker, defaultPolicy(), false},
		{"api.localhost", "http://api.localhost/" + marker, defaultPolicy(), false},
		{"localhost allowed with allow_loopback", "http://localhost:8080/" + marker, Policy{AllowLoopback: true}, true},
		{"loopback literal", "http://127.0.0.1/" + marker, defaultPolicy(), false},
		{"loopback literal allowed", "http://127.0.0.1:9/" + marker, Policy{AllowLoopback: true}, true},
		{"metadata link-local", "http://169.254.169.254/latest/" + marker, defaultPolicy(), false},
		{"metadata alibaba", "https://100.100.100.200/" + marker, defaultPolicy(), false},
		{"public plaintext literal", "http://203.0.113.5/" + marker, defaultPolicy(), false},
		{"private literal with allow_private off", "https://10.0.0.5/" + marker, Policy{}, false},
		{"ipv6 loopback", "http://[::1]:80/" + marker, defaultPolicy(), false},
	}
	for _, c := range cases {
		v, err := ValidateWebhookURL(c.url, c.p)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
			continue
		}
		if err != nil && strings.Contains(err.Error(), marker) {
			t.Errorf("%s: the error contains the URL: %v", c.name, err)
		}
		if err == nil && (strings.Contains(v.Display, marker) || !strings.HasSuffix(v.Display, "/…")) {
			t.Errorf("%s: display form %q leaks the path", c.name, v.Display)
		}
	}
	if v, _ := ValidateWebhookURL("http://10.0.0.5:8080/p", defaultPolicy()); !v.Plaintext || v.Display != "http://10.0.0.5:8080/…" {
		t.Errorf("%+v", v)
	}
	if v, _ := ValidateWebhookURL("https://hooks.example/p", defaultPolicy()); v.Plaintext {
		t.Errorf("%+v", v)
	}
}

func TestInterleaveAlternatesFamilies(t *testing.T) {
	got := interleave([]netip.Addr{mustAddr("fd00::1"), mustAddr("fd00::2"), mustAddr("10.0.0.1"), mustAddr("10.0.0.2")})
	want := []string{"fd00::1", "10.0.0.1", "fd00::2", "10.0.0.2"}
	for i, a := range got {
		if a.String() != want[i] {
			t.Fatalf("%v", got)
		}
	}
	if got := interleave([]netip.Addr{mustAddr("10.0.0.1"), mustAddr("fd00::1")}); got[0].String() != "10.0.0.1" {
		t.Fatalf("the first answer's family goes first: %v", got)
	}
}

func TestSigningKey(t *testing.T) {
	k, err := NewSigningKey()
	if err != nil || !strings.HasPrefix(k, "whsec_") {
		t.Fatalf("%q %v", k, err)
	}
	b, err := DecodeSigningKey(k)
	if err != nil || len(b) != 32 {
		t.Fatalf("%d %v", len(b), err)
	}
	k2, _ := NewSigningKey()
	if k == k2 {
		t.Fatal("keys must be random")
	}
	for _, bad := range []string{"", "whsec_", "abc", "whsec_!!!!", "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"} {
		if _, err := DecodeSigningKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	sec := WebhookSecret{URL: "https://x/y", SigningKey: k}
	raw, _ := sec.Marshal()
	if got, err := ParseWebhookSecret(raw); err != nil || got != sec {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := ParseWebhookSecret([]byte(`{"url":"x"}`)); err == nil {
		t.Fatal("a secret without a key was accepted")
	}
}
