// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Command alertsink is a loopback webhook and SMTP receiver for the container
// e2e (docs/testing.md): it appends one JSON line per webhook request or
// accepted message to a file, so a test can read exactly what the server sent.
//
// TEST TOOL. It binds loopback addresses only and refuses anything else; it
// answers every webhook with 204 and accepts every message. The SMTP side is
// internal/testsmtp (plaintext, no auth), matching smtp.tls: none in
// deploy/test/server.yaml.
//
//	alertsink --http 127.0.0.1:9100 --smtp 127.0.0.1:2525 --out /run/alertsink/sink.jsonl
//
// Each line is {"kind":"webhook","path":...,"header":{...},"body":"..."} or
// {"kind":"email","from":...,"to":[...],"data":"..."}. After listening it prints
// "READY <http addr> <smtp addr>" on stdout (the addresses matter with port 0).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/clamfleet/clamfleet/internal/testsmtp"
)

type sink struct {
	mu  sync.Mutex
	out io.Writer
}

func (s *sink) write(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out.Write(append(b, '\n'))
}

func loopbackOnly(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%q is not a loopback address: the sink binds 127.0.0.1 or ::1 only", addr)
	}
	return nil
}

// run starts both listeners and blocks until ctx ends. ready receives the real
// addresses.
func run(ctx context.Context, httpAddr, smtpAddr string, out io.Writer, ready func(httpAddr, smtpAddr string)) error {
	for _, a := range []string{httpAddr, smtpAddr} {
		if err := loopbackOnly(a); err != nil {
			return err
		}
	}
	s := &sink{out: out}
	smtp, err := testsmtp.Listen(smtpAddr, testsmtp.Options{OnMessage: func(m testsmtp.Message) {
		s.write(map[string]any{"kind": "email", "from": m.From, "to": m.To, "data": m.Data})
	}})
	if err != nil {
		return err
	}
	defer smtp.Close()
	ln, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return err
	}
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		s.write(map[string]any{"kind": "webhook", "path": r.URL.Path, "header": r.Header, "body": string(body)})
		w.WriteHeader(http.StatusNoContent)
	})}
	go srv.Serve(ln)
	ready(ln.Addr().String(), smtp.Addr)
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

func main() {
	httpAddr := flag.String("http", "127.0.0.1:9100", "webhook listen address (loopback only)")
	smtpAddr := flag.String("smtp", "127.0.0.1:2525", "SMTP listen address (loopback only)")
	outPath := flag.String("out", "", "file to append JSON lines to (required)")
	flag.Parse()
	if *outPath == "" {
		fmt.Fprintln(os.Stderr, "alertsink: --out is required")
		os.Exit(2)
	}
	f, err := os.OpenFile(*outPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "alertsink:", err)
		os.Exit(1)
	}
	defer f.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = run(ctx, *httpAddr, *smtpAddr, f, func(h, s string) { fmt.Printf("READY %s %s\n", h, s) })
	if err != nil {
		fmt.Fprintln(os.Stderr, "alertsink:", err)
		os.Exit(1)
	}
}
