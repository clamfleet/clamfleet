// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/testtls"
)

type reloadEnv struct {
	addr   string
	cfg    Config
	reload chan struct{}
	logs   *syncBuf
	a, b   testtls.Bundle // two independent CAs and server certificates
}

func bundle(t *testing.T) testtls.Bundle {
	t.Helper()
	b, err := testtls.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readSerial(t *testing.T, path string) *big.Int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pemDecode(b)
	c, err := x509.ParseCertificate(blk)
	if err != nil {
		t.Fatal(err)
	}
	return c.SerialNumber
}

// startReload serves with certificate A (and, with mtls, client CA A) on files that the
// test then overwrites in place, like a certificate renewal does.
func startReload(t *testing.T, mtls bool) *reloadEnv {
	t.Helper()
	e := &reloadEnv{a: bundle(t), b: bundle(t), reload: make(chan struct{}, 1), logs: &syncBuf{}}
	live := t.TempDir()
	e.cfg = Config{Listen: "127.0.0.1:0", TLS: TLS{Cert: filepath.Join(live, "cert.pem"), Key: filepath.Join(live, "key.pem")}}
	if mtls {
		e.cfg.TLS.ClientCA = filepath.Join(live, "ca.pem")
	}
	e.install(t, e.a, true)
	ln, err := Listen(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	log := slog.New(slog.NewJSONHandler(e.logs, nil))
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	go func() { done <- ServeListenerReload(ctx, ln, e.cfg, h, log, e.reload) }()
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("server did not stop")
		}
	})
	return e
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	tmp := to + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, to); err != nil { // atomic, like a renewal tool
		t.Fatal(err)
	}
}

// install overwrites the live files with bundle b (the certificate pair, and the CA when mTLS is on).
func (e *reloadEnv) install(t *testing.T, b testtls.Bundle, pair bool) {
	t.Helper()
	if pair {
		copyFile(t, b.Cert, e.cfg.TLS.Cert)
		copyFile(t, b.Key, e.cfg.TLS.Key)
	}
	if e.cfg.TLS.ClientCA != "" {
		copyFile(t, b.CA, e.cfg.TLS.ClientCA)
	}
}

// handshake connects, optionally with a client certificate, completes a request
// round trip (TLS 1.3 reports a refused client certificate only on the first read)
// and returns the server certificate's serial.
func (e *reloadEnv) handshake(client *tls.Certificate, cache tls.ClientSessionCache) (*big.Int, error) {
	cfg := &tls.Config{InsecureSkipVerify: true, ClientSessionCache: cache} // the serial is what is checked
	if client != nil {
		cfg.Certificates = []tls.Certificate{*client}
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", e.addr, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	serial := conn.ConnectionState().PeerCertificates[0].SerialNumber
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
		return nil, err
	}
	if _, err := io.ReadAll(conn); err != nil {
		return nil, err
	}
	return serial, nil
}

func clientCert(t *testing.T, b testtls.Bundle) *tls.Certificate {
	t.Helper()
	c, err := tls.LoadX509KeyPair(b.ClientCert, b.ClientKey)
	if err != nil {
		t.Fatal(err)
	}
	return &c
}

func (e *reloadEnv) reloadAndWait(t *testing.T, until func() bool) {
	t.Helper()
	e.reload <- struct{}{}
	deadline := time.Now().Add(5 * time.Second)
	for !until() {
		if time.Now().After(deadline) {
			t.Fatalf("the reload did not take effect:\n%s", e.logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *reloadEnv) serialIs(want *big.Int, client *tls.Certificate) func() bool {
	return func() bool {
		got, err := e.handshake(client, nil)
		return err == nil && got.Cmp(want) == 0
	}
}

// The reload swaps the certificate: new handshakes see B's serial. A broken pair
// (a key that does not match) is refused with an error line, and handshakes keep
// seeing B. Mutations: SIGHUP unwired, or a swap that does not check the pair.
func TestTLSReloadSwapsAndRefusesABrokenPair(t *testing.T) {
	e := startReload(t, false)
	serialA, serialB := readSerial(t, e.a.Cert), readSerial(t, e.b.Cert)
	if got, err := e.handshake(nil, nil); err != nil || got.Cmp(serialA) != 0 {
		t.Fatalf("start: %v %v", got, err)
	}
	e.install(t, e.b, true)
	e.reloadAndWait(t, e.serialIs(serialB, nil))
	if !strings.Contains(e.logs.String(), `"msg":"tls certificate reloaded"`) || !strings.Contains(e.logs.String(), "not_after") {
		t.Fatalf("no reload line with the expiry:\n%s", e.logs.String())
	}

	// Certificate of A with the key of B: does not match.
	copyFile(t, e.a.Cert, e.cfg.TLS.Cert)
	e.reload <- struct{}{}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(e.logs.String(), "tls reload failed") {
		if time.Now().After(deadline) {
			t.Fatal("no error line for a broken pair")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		if got, err := e.handshake(nil, nil); err != nil || got.Cmp(serialB) != 0 {
			t.Fatalf("after a failed reload the old certificate must stay: %v %v", got, err)
		}
	}
}

// All or nothing: a good new certificate with an unparseable client CA swaps
// nothing (the old serial is served, the old CA still accepted), and so does a
// deleted client_ca file.
func TestTLSReloadIsAllOrNothing(t *testing.T) {
	e := startReload(t, true)
	serialA := readSerial(t, e.a.Cert)
	clientA := clientCert(t, e.a)
	if got, err := e.handshake(clientA, nil); err != nil || got.Cmp(serialA) != 0 {
		t.Fatalf("start: %v %v", got, err)
	}
	failed := func(n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for strings.Count(e.logs.String(), "tls reload failed") < n {
			if time.Now().After(deadline) {
				t.Fatalf("want %d failed reloads:\n%s", n, e.logs.String())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	copyFile(t, e.b.Cert, e.cfg.TLS.Cert)
	copyFile(t, e.b.Key, e.cfg.TLS.Key)
	if err := os.WriteFile(e.cfg.TLS.ClientCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.reload <- struct{}{}
	failed(1)
	if got, err := e.handshake(clientA, nil); err != nil || got.Cmp(serialA) != 0 {
		t.Fatalf("a partial swap: serial %v, err %v (the old certificate and CA must stay)", got, err)
	}

	if err := os.Remove(e.cfg.TLS.ClientCA); err != nil {
		t.Fatal(err)
	}
	e.reload <- struct{}{}
	failed(2)
	if got, err := e.handshake(clientA, nil); err != nil || got.Cmp(serialA) != 0 {
		t.Fatalf("a deleted client_ca must fail the reload and keep the old state: %v %v", got, err)
	}
}

// The settings survive a reload: TLS 1.2 minimum and, under mTLS, a client without a
// certificate is still refused. A new client CA is applied: a client of the old CA is
// refused and one of the new CA accepted.
func TestTLSReloadKeepsSettingsAndAppliesTheNewClientCA(t *testing.T) {
	e := startReload(t, true)
	serialB := readSerial(t, e.b.Cert)
	clientA, clientB := clientCert(t, e.a), clientCert(t, e.b)
	if _, err := e.handshake(clientA, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.handshake(clientB, nil); err == nil {
		t.Fatal("a client of another CA was accepted before the reload")
	}
	e.install(t, e.b, true)
	e.reloadAndWait(t, e.serialIs(serialB, clientB))
	if _, err := e.handshake(clientA, nil); err == nil {
		t.Fatal("a client certificate of the OLD CA is still accepted after the reload")
	}
	if _, err := e.handshake(nil, nil); err == nil {
		t.Fatal("a client without a certificate was accepted after the reload: ClientAuth was lost")
	}
	// A handshake limited to TLS 1.1 cannot be done by a Go client any more, so the
	// minimum version is read from the config the next handshake would use.
	rl, err := newTLSReloader(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := rl.config().GetConfigForClient(nil)
	if got.MinVersion != tls.VersionTLS12 || got.ClientAuth != tls.RequireAndVerifyClientCert || !got.SessionTicketsDisabled {
		t.Fatalf("settings of the per-client config: min %x auth %v tickets-off %v", got.MinVersion, got.ClientAuth, got.SessionTicketsDisabled)
	}
	plain, err := newTLSReloader(Config{TLS: TLS{Cert: e.cfg.TLS.Cert, Key: e.cfg.TLS.Key}})
	if err != nil {
		t.Fatal(err)
	}
	if g, _ := plain.config().GetConfigForClient(nil); g.SessionTicketsDisabled {
		t.Fatal("without mTLS session tickets stay on")
	}
}

// Resumption: a client that completed a handshake reconnects with its session
// cache after the client CA was replaced by one that does not sign its
// certificate: refused (every handshake is a full one under mTLS).
func TestTLSResumptionCannotOutliveAClientCAChange(t *testing.T) {
	e := startReload(t, true)
	clientA := clientCert(t, e.a)
	cache := tls.NewLRUClientSessionCache(8)
	if _, err := e.handshake(clientA, cache); err != nil {
		t.Fatal(err)
	}
	if _, err := e.handshake(clientA, cache); err != nil { // would resume if tickets were on
		t.Fatal(err)
	}
	copyFile(t, e.b.CA, e.cfg.TLS.ClientCA) // the certificate pair stays: same server name and session context
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.reload <- struct{}{}
		time.Sleep(50 * time.Millisecond)
		if _, err := e.handshake(clientA, cache); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a session resumed after the client CA was replaced")
		}
	}
}

// 50 reloads while 8 goroutines handshake continuously (run with -race): no
// handshake fails and every handshake sees the old or the new certificate.
func TestTLSReloadUnderLoad(t *testing.T) {
	e := startReload(t, false)
	serials := []*big.Int{readSerial(t, e.a.Cert), readSerial(t, e.b.Cert)}
	var stop atomic.Bool
	var wg sync.WaitGroup
	var bad atomic.Int64
	var firstErr atomic.Value
	var handshakes atomic.Int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				got, err := e.handshake(nil, nil)
				handshakes.Add(1)
				if err != nil {
					bad.Add(1)
					firstErr.Store(err.Error())
					continue
				}
				if got.Cmp(serials[0]) != 0 && got.Cmp(serials[1]) != 0 {
					bad.Add(1)
					firstErr.Store("an unknown certificate was served")
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		b := e.a
		if i%2 == 0 {
			b = e.b
		}
		e.install(t, b, true)
		e.reload <- struct{}{}
		time.Sleep(5 * time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d of %d handshakes failed during reloads: %v", bad.Load(), handshakes.Load(), firstErr.Load())
	}
	if handshakes.Load() < 50 {
		t.Fatalf("only %d handshakes ran", handshakes.Load())
	}
}

// An open keep-alive connection made before a reload keeps working (the old
// handshake stays), as the docs say; a new connection sees the new certificate.
func TestTLSReloadKeepsExistingConnections(t *testing.T) {
	e := startReload(t, false)
	serialB := readSerial(t, e.b.Cert)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	get := func() (reused bool) {
		req, _ := http.NewRequest("GET", "https://"+e.addr+"/", nil)
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return reused
	}
	if get() {
		t.Fatal("the first request reused a connection")
	}
	e.install(t, e.b, true)
	e.reloadAndWait(t, e.serialIs(serialB, nil))
	if !get() {
		t.Fatal("the connection made before the reload was dropped")
	}
}

func pemDecode(b []byte) ([]byte, []byte) {
	blk, rest := pem.Decode(b)
	if blk == nil {
		return nil, rest
	}
	return blk.Bytes, rest
}
