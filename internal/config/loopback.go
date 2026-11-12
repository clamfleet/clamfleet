// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// loopback.go: the one definition of "loopback" shared by the server
// (plaintext listen address) and the agent (plaintext server URL).

package config

import (
	"net"
	"strings"
)

// IsLoopbackHost reports whether host (no port) is "localhost" or a loopback
// IP literal. No DNS lookup is made: a name that merely resolves to 127.0.0.1
// today could resolve elsewhere tomorrow, and the point of the rule is that
// plaintext never leaves the machine. An empty host (":8443", all interfaces)
// is not loopback.
func IsLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// IsLoopbackAddr is IsLoopbackHost for a "host:port" address. An address that
// does not parse is not loopback.
func IsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return IsLoopbackHost(host)
}
