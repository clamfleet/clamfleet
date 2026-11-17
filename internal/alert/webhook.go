// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// webhook.go: the webhook sender and its Standard Webhooks signature
// (M4 decision 7).
//
// Request: POST, JSON body, headers webhook-id (the alert id), webhook-timestamp
// (unix seconds from the injected clock at send time, fresh on every retry) and
// webhook-signature ("v1," + base64 HMAC-SHA256 over "id.timestamp.body", the
// HMAC key being the base64-DECODED bytes of the whsec_ key).
//
// Transport rules, each one a defence: no proxy (a proxy would make the dial
// check see the proxy, not the target), no redirects (a 302 to an internal
// address would skip the check), no keep-alive (every attempt resolves and is
// checked again, so DNS rebinding between attempts is filtered), TLS 1.2 or
// later with verification always on, and the response body is read up to 64 KiB
// and DISCARDED: nothing of it is stored, shown or logged, so a test send cannot
// be used to read an internal page.
package alert

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxDiscardBytes is how much of a response body is read (and thrown away) so
// the connection ends cleanly.
const maxDiscardBytes = 64 << 10

// Sign returns the webhook-signature value for one attempt.
func Sign(key []byte, id string, ts int64, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(id))
	m.Write([]byte{'.'})
	m.Write([]byte(strconv.FormatInt(ts, 10)))
	m.Write([]byte{'.'})
	m.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// VerifySignature reports whether header (space-separated "v1,<b64>" entries)
// holds a valid signature of the attempt. It is the receiver's check, kept here
// so tests verify with code that shares nothing with Sign except the format.
func VerifySignature(key []byte, id string, ts int64, body []byte, header string) bool {
	want := Sign(key, id, ts, body)
	for _, got := range strings.Fields(header) {
		if hmac.Equal([]byte(got), []byte(want)) {
			return true
		}
	}
	return false
}

// WebhookSender delivers one payload to one webhook URL.
type WebhookSender struct {
	Policy Policy
	// Timeout bounds one attempt (dial, TLS, request, response).
	Timeout time.Duration
	// Resolver and Dial are injectable for tests; nil means the real ones.
	Resolver Resolver
	Dial     DialFunc
	// RootCAs adds trust anchors; nil means the system roots.
	RootCAs *x509.CertPool
	// Now is the injected clock.
	Now func() time.Time
	// Version is put in the User-Agent.
	Version string
}

// Send posts body to the secret's URL and classifies the answer. It never
// returns an error: every failure is a Result (the sender's contract with the
// dispatcher). The URL is re-validated here, so a row that was edited in the
// database cannot bypass the save-time rules.
func (w *WebhookSender) Send(ctx context.Context, sec WebhookSecret, alertID string, body []byte) Result {
	start := w.Now()
	done := func(r Result) Result { r.Duration = w.Now().Sub(start); return r }

	v, err := ValidateWebhookURL(sec.URL, w.Policy)
	if err != nil {
		var perm *PermanentError
		if errors.As(err, &perm) { // a policy refusal keeps its own code ("blocked", "plaintext")
			return done(ClassifyError(err))
		}
		return done(Result{Outcome: OutcomePermanent, Code: "invalid", Text: "the stored webhook URL is not valid: " + err.Error()})
	}
	key, err := DecodeSigningKey(sec.SigningKey)
	if err != nil {
		return done(Result{Outcome: OutcomePermanent, Code: "invalid", Text: "the stored signing key is not valid"})
	}

	timeout := w.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &SafeDialer{Policy: w.Policy, Plaintext: v.Plaintext, Resolver: w.Resolver, Dial: w.Dial, Timeout: 5 * time.Second}
	tr := &http.Transport{
		Proxy:                 nil, // never the environment: see the file header
		DialContext:           dialer.DialContext,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: w.RootCAs},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.URL.String(), strings.NewReader(string(body)))
	if err != nil {
		return done(Result{Outcome: OutcomePermanent, Code: "invalid", Text: "the webhook request could not be built"})
	}
	ts := w.Now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ClamFleet/"+w.Version)
	req.Header.Set("webhook-id", alertID)
	req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("webhook-signature", Sign(key, alertID, ts, body))

	resp, err := client.Do(req)
	if err != nil {
		return done(ClassifyError(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDiscardBytes))
	return done(ClassifyHTTP(resp.StatusCode, resp.Header.Get("Retry-After"), w.Now()))
}

// Compile-time check that net.Resolver satisfies Resolver.
var _ Resolver = (*net.Resolver)(nil)
