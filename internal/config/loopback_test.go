// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package config

import "testing"

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8443": true, "127.0.0.1:0": true, "[::1]:8443": true, "localhost:8443": true, "LOCALHOST:1": true,
		"127.1.2.3:80": true,
		":8443":        false, "0.0.0.0:8443": false, "[::]:8443": false, "10.0.0.1:8443": false,
		"example.com:443": false, "127.0.0.1": false, "": false, "localhost.example.com:1": false,
	} {
		if got := IsLoopbackAddr(addr); got != want {
			t.Errorf("IsLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
	if IsLoopbackHost("") || !IsLoopbackHost("[::1]") || IsLoopbackHost("::") {
		t.Error("IsLoopbackHost")
	}
}
