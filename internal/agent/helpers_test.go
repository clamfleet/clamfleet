// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// shortTempDir returns a short directory: unix socket paths are limited to
// 108 bytes and t.TempDir() paths can exceed that.
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "cf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// reply decides what the fake clamd does with one request.
type reply func(conn net.Conn)

func send(b []byte) reply {
	return func(c net.Conn) { _, _ = c.Write(b) }
}

// fakeClamd listens on a unix socket and answers by exact request bytes.
// A request not in the table fails the test: that is what catches a missing
// "z" prefix or NUL terminator. conns counts accepted connections.
type fakeClamd struct {
	Path  string
	conns atomic.Int32
	wg    sync.WaitGroup
}

func startFakeClamd(t *testing.T, table map[string]reply) *fakeClamd {
	t.Helper()
	f := &fakeClamd{Path: filepath.Join(shortTempDir(t), "s")}
	ln, err := net.Listen("unix", f.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); f.wg.Wait() })
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.conns.Add(1)
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var req []byte
				buf := make([]byte, 1)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
					req = append(req, buf[0])
					if buf[0] == 0 {
						break
					}
				}
				h, ok := table[string(req)]
				if !ok {
					t.Errorf("fake clamd: unexpected request %q", req)
					return
				}
				h(c)
			}()
		}
	}()
	return f
}

// recordedSession replays the recording of testdata/clamd, asserting the
// request bytes equal the recorded ones.
func recordedSession(t *testing.T) map[string]reply {
	t.Helper()
	tbl := map[string]reply{}
	for _, n := range []string{"ping", "version", "stats", "unknown"} {
		tbl[string(fixture(t, "clamd/"+n+".req"))] = send(fixture(t, "clamd/"+n+".resp"))
	}
	return tbl
}

// logRun builds a freshclam log run for hand-made tests.
func logRun(ctime string, lines ...string) string {
	return "ClamAV update process started at " + ctime + "\n" + strings.Join(lines, "\n") + "\n"
}
