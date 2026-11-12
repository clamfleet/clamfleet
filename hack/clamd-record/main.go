// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Command clamd-record sends a fixed list of commands to a clamd unix socket
// and writes the raw request and reply bytes of each to <outdir>/<name>.req
// and <name>.resp. The agent tests replay these recordings.
//
// It deliberately imports nothing from internal/agent: it is an independent
// oracle, so a bug in the agent's client cannot also corrupt the recordings.
// It is cross-compiled and run inside the test container by
// deploy/test/capture-fixtures.sh.
//
// Usage: clamd-record <socket> <outdir>
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

// commands are sent one per connection. "unknown" is deliberately invalid, to
// record how clamd answers a command it does not know.
var commands = []struct{ name, req string }{
	{"ping", "zPING\x00"},
	{"version", "zVERSION\x00"},
	{"stats", "zSTATS\x00"},
	{"unknown", "zFOO\x00"},
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: clamd-record <socket> <outdir>")
		os.Exit(2)
	}
	socket, outdir := os.Args[1], os.Args[2]
	if err := os.MkdirAll(outdir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, c := range commands {
		resp, err := exchange(socket, c.req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", c.name, err)
			os.Exit(1)
		}
		for ext, data := range map[string]string{".req": c.req, ".resp": resp} {
			if err := os.WriteFile(filepath.Join(outdir, c.name+ext), []byte(data), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
	}
}

// exchange sends req on a fresh connection and reads until clamd closes it.
func exchange(socket, req string) (string, error) {
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, req); err != nil {
		return "", err
	}
	b, err := io.ReadAll(conn)
	return string(b), err
}
