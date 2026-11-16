// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"crypto/tls"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/testtls"
)

func serialSeen(t *testing.T, addr string) *big.Int {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber
}

func replaceFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to+".new", b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(to+".new", to); err != nil {
		t.Fatal(err)
	}
}

// SIGHUP to the real process re-reads the certificate: a new handshake sees the
// new serial; a broken pair logs an error and the old certificate stays.
// Mutation: SIGHUP not wired (the default action would also kill the process,
// so the test sends it only to a running server and expects it to survive).
func TestTLSReloadOnSIGHUP(t *testing.T) {
	a, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	live := t.TempDir()
	cert, key := filepath.Join(live, "cert.pem"), filepath.Join(live, "key.pem")
	replaceFile(t, a.Cert, cert)
	replaceFile(t, a.Key, key)
	db, _ := newDB(t)
	srv := startServe(t, testtls.Bundle{Cert: cert, Key: key}, db)

	serialA := serialSeen(t, srv.addr)
	replaceFile(t, b.Cert, cert)
	replaceFile(t, b.Key, key)
	if err := syscall.Kill(srv.pid, syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	var serialB *big.Int
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		serialB = serialSeen(t, srv.addr)
		if serialB.Cmp(serialA) != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still serving the old certificate after SIGHUP:\n%s", srv.stderr.String())
		}
	}
	if !strings.Contains(srv.stderr.String(), "tls certificate reloaded") {
		t.Fatalf("no reload line:\n%s", srv.stderr.String())
	}

	// A broken pair: the key of A with the certificate of B.
	replaceFile(t, a.Key, key)
	if err := syscall.Kill(srv.pid, syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(srv.stderr.String(), "tls reload failed"); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no error line for a broken pair:\n%s", srv.stderr.String())
		}
	}
	if got := serialSeen(t, srv.addr); got.Cmp(serialB) != 0 {
		t.Fatalf("a broken reload changed the served certificate")
	}
	// The process survived every SIGHUP (the default action would terminate it).
	if err := syscall.Kill(srv.pid, 0); err != nil {
		t.Fatalf("the server is gone: %v", err)
	}
}
