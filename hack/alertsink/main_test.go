// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"testing"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func TestSinkRecordsAWebhookAndAnEmail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	out := &lockedBuf{}
	ready := make(chan [2]string, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, "127.0.0.1:0", "127.0.0.1:0", out, func(h, s string) { ready <- [2]string{h, s} })
	}()
	addrs := <-ready

	resp, err := http.Post("http://"+addrs[0]+"/hook", "application/json", strings.NewReader(`{"schema":1}`))
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("%v %v", resp, err)
	}
	resp.Body.Close()
	if err := smtp.SendMail(addrs[1], nil, "from@x.example", []string{"to@x.example"}, []byte("Subject: hi\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var kinds []string
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("not a JSON line: %q", sc.Text())
		}
		kinds = append(kinds, m["kind"].(string))
		if m["kind"] == "webhook" && (m["path"] != "/hook" || m["body"] != `{"schema":1}`) {
			t.Fatalf("%v", m)
		}
		if m["kind"] == "email" && !strings.Contains(m["data"].(string), "Subject: hi") {
			t.Fatalf("%v", m)
		}
	}
	if strings.Join(kinds, ",") != "webhook,email" {
		t.Fatalf("%v", kinds)
	}
}

func TestSinkRefusesANonLoopbackAddress(t *testing.T) {
	for _, bad := range [][2]string{{"0.0.0.0:0", "127.0.0.1:0"}, {"127.0.0.1:0", ":2525"}, {"10.0.0.5:80", "127.0.0.1:0"}} {
		err := run(context.Background(), bad[0], bad[1], &lockedBuf{}, func(string, string) { t.Error("started on a non-loopback address") })
		if err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Errorf("%v: %v", bad, err)
		}
	}
}
