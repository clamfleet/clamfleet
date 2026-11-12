// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// send.go: the HTTP client side of the agent: POST a JSON body to the server
// with the bearer token.
//
// Responsibilities: read the token file on every send (a rotation needs no
// restart), build the request, classify the outcome (SendError), and return
// the bounded response body. It is the only place that ever holds the token
// or builds the Authorization header, and it never logs or returns it: errors
// name the token file path, never its content.
//
// Redirects are not followed: Go would re-send the Authorization header to a
// same-host redirect, and a server that redirects an API call is
// misconfigured, not something to chase with a secret.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

// Class says why a send failed, so the loop can log something an operator can act on.
type Class string

const (
	// ClassToken: the token file is missing, empty or malformed (nothing was sent).
	ClassToken Class = "token"
	// ClassNetwork: no HTTP response (DNS, connect, TLS, timeout).
	ClassNetwork Class = "network"
	// ClassUnauthorized: HTTP 401, the server does not accept the token.
	ClassUnauthorized Class = "unauthorized"
	// ClassRejected: another 4xx (or an unexpected 3xx): the server refused the
	// payload; Message is the server's "error" text.
	ClassRejected Class = "rejected"
	// ClassServer: 5xx: the server is unwell; retrying later is right.
	ClassServer Class = "server"
)

// SendError is the typed failure of Sender.Send. It never contains the token.
type SendError struct {
	Class   Class
	Status  int    // HTTP status, 0 when there was no response
	Message string // the server's "error" text for ClassRejected
	Err     error  // underlying cause (network, token file)
}

func (e *SendError) Error() string {
	msg := string(e.Class)
	if e.Status != 0 {
		msg += fmt.Sprintf(" (HTTP %d)", e.Status)
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *SendError) Unwrap() error { return e.Err }

// maxResponseBytes bounds what the agent reads back from a server.
const maxResponseBytes = 1 << 20

// requestTimeout bounds one send, so a cancelled loop stops within it.
const requestTimeout = 30 * time.Second

// Sender posts JSON to the server.
type Sender struct {
	// Server is the base URL (a path prefix is kept: a reverse proxy may mount the API under one).
	Server *url.URL
	// TokenFile is read, trimmed, on every Send.
	TokenFile string
	Client    *http.Client
	// UserAgent is sent as the User-Agent header.
	UserAgent string
	// Log receives the world-readable-token-file warning; nil discards it.
	Log *slog.Logger

	warnedMode atomic.Bool
}

// NewSender builds a Sender from a validated Config (ValidateRun).
//
// TLS: the system trust store (a private CA via SSL_CERT_FILE/SSL_CERT_DIR),
// minimum TLS 1.2. The client certificate, when configured, is re-read from
// disk at every handshake, so a renewed certificate needs no restart either.
func NewSender(cfg Config, userAgent string, log *slog.Logger) (*Sender, error) {
	u, err := url.Parse(cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("server URL: %w", err)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLS.ClientCert != "" {
		certFile, keyFile := cfg.TLS.ClientCert, cfg.TLS.ClientKey
		// Fail at start, not at the first handshake, when the pair is unusable.
		if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
			return nil, fmt.Errorf("tls.client_cert/tls.client_key: %w", err)
		}
		tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("tls.client_cert/tls.client_key: %w", err)
			}
			return &c, nil
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tc
	return &Sender{
		Server: u, TokenFile: cfg.TokenFile, UserAgent: userAgent, Log: log,
		Client: &http.Client{
			Transport: tr,
			Timeout:   requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// readToken reads the token file. The error names the path, never the content.
func (s *Sender) readToken() (string, error) {
	raw, err := os.ReadFile(s.TokenFile)
	if err != nil {
		return "", &SendError{Class: ClassToken, Err: fmt.Errorf("cannot read token_file %s: %w", s.TokenFile, errors.Unwrap(err))}
	}
	if fi, err := os.Stat(s.TokenFile); err == nil && fi.Mode().Perm()&0o004 != 0 && s.Log != nil && !s.warnedMode.Swap(true) {
		s.Log.Warn("token_file is world-readable: any local user can impersonate this host; chmod it to 0640 or 0600", "path", s.TokenFile)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", &SendError{Class: ClassToken, Err: fmt.Errorf("token_file %s is empty", s.TokenFile)}
	}
	// A token with whitespace or control characters inside could split or
	// corrupt the header; it is certainly not a token we were given.
	if strings.IndexFunc(tok, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || r > unicode.MaxASCII }) >= 0 {
		return "", &SendError{Class: ClassToken, Err: fmt.Errorf("token_file %s does not contain a single-line token", s.TokenFile)}
	}
	return tok, nil
}

// Send POSTs body (JSON) to path (e.g. "v1/report") under the server URL and
// returns the response body (at most 1 MiB; clients ignore unknown keys, the
// hook for server tasks later). Any 2xx is success. Errors are *SendError.
//
// Side effects: reads TokenFile; one HTTPS request.
func (s *Sender) Send(ctx context.Context, path string, body []byte) ([]byte, error) {
	token, err := s.readToken()
	if err != nil {
		return nil, err
	}
	target := s.Server.JoinPath(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, &SendError{Class: ClassNetwork, Err: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", s.UserAgent)
	resp, err := s.Client.Do(req)
	if err != nil {
		// url.Error repeats the URL (no credentials: ValidateRun forbids them), not headers.
		return nil, &SendError{Class: ClassNetwork, Err: err}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, &SendError{Class: ClassNetwork, Status: resp.StatusCode, Err: err}
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return data, nil
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, &SendError{Class: ClassUnauthorized, Status: resp.StatusCode, Err: errors.New("the server does not accept the token (wrong, revoked or rotated)")}
	case resp.StatusCode >= 500:
		return nil, &SendError{Class: ClassServer, Status: resp.StatusCode, Message: serverMessage(data)}
	default:
		return nil, &SendError{Class: ClassRejected, Status: resp.StatusCode, Message: serverMessage(data)}
	}
}

// serverMessage extracts the envelope's "error" text, bounded, for the log.
func serverMessage(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	if len(e.Error) > 300 {
		return e.Error[:300] + "..."
	}
	return e.Error
}
