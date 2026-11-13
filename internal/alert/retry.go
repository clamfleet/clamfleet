// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// retry.go: the retry schedule and the classification of delivery results
// (docs/plans/milestone-4.md 4.4). Pure: no clock and no randomness of its
// own; the caller passes "now" and a jitter source.
//
// Schedule (decision 5): at most 5 attempts per delivery, at planning and then
// +1, +5, +15 and +60 minutes after the previous attempt FINISHED (about 81
// minutes in all), each with +-10% jitter. A Retry-After from the receiver
// raises the delay (never lowers it), capped at 60 minutes.
package alert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

// MaxAttempts is the attempt budget of a delivery. It is the store's constant:
// the crash path (the store) and the normal path (here) must agree.
const MaxAttempts = store.MaxAlertAttempts

// backoff[i] is the base delay after attempt i+1 failed.
var backoff = [MaxAttempts - 1]time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 60 * time.Minute}

// MaxRetryAfter caps what a receiver can ask for.
const MaxRetryAfter = 60 * time.Minute

// jitterFraction is the +- share of random spread on a delay.
const jitterFraction = 0.10

// NextDelay returns the wait before attempt attempt+1 after attempt `attempt`
// (1-based) failed, and false when the budget is spent. jitter returns a value
// in [0, 1) (0.5 = no change); retryAfter is 0 when the receiver sent none.
func NextDelay(attempt int, retryAfter time.Duration, jitter func() float64) (time.Duration, bool) {
	if attempt < 1 || attempt >= MaxAttempts {
		return 0, false
	}
	base := backoff[attempt-1]
	f := 1 + (jitter()*2-1)*jitterFraction
	d := time.Duration(float64(base) * f)
	if retryAfter > MaxRetryAfter {
		retryAfter = MaxRetryAfter
	}
	if retryAfter > d {
		d = retryAfter
	}
	return d, true
}

// ParseRetryAfter reads a Retry-After header: whole seconds or an HTTP date.
// Garbage, a negative value or a date in the past gives 0; the result is
// capped at MaxRetryAfter.
func ParseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs < 0 {
			return 0
		}
		if secs > int64(MaxRetryAfter/time.Second) {
			return MaxRetryAfter
		}
		d = time.Duration(secs) * time.Second
	} else if at, err := http.ParseTime(v); err == nil {
		d = at.Sub(now)
	} else {
		return 0
	}
	if d < 0 {
		return 0
	}
	return min(d, MaxRetryAfter)
}

// Outcome is the class of one delivery attempt.
type Outcome int

// Outcomes. The zero value is deliberately not Sent: a Result nobody filled in
// must never count as delivered.
const (
	OutcomeRetry Outcome = iota
	OutcomeSent
	OutcomePermanent
)

// Result is what a sender reports for one attempt. Code is a short class
// ("HTTP 503", "SMTP 550", "blocked", "timeout", "tls", "dns", ...), Text is
// our own words: never a response body, never a URL path or a secret.
type Result struct {
	Outcome    Outcome
	Code       string
	Text       string
	RetryAfter time.Duration
	Duration   time.Duration
}

// ClassifyHTTP maps a receiver's status to a Result (the 4.4 table). The body
// is never looked at.
func ClassifyHTTP(status int, retryAfterHeader string, now time.Time) Result {
	code := "HTTP " + strconv.Itoa(status)
	switch {
	case status >= 200 && status < 300:
		return Result{Outcome: OutcomeSent, Code: code}
	case status == 408 || status == 425 || status == 429 || status >= 500:
		return Result{Outcome: OutcomeRetry, Code: code, Text: "the receiver answered " + code,
			RetryAfter: ParseRetryAfter(retryAfterHeader, now)}
	case status >= 300 && status < 400:
		return Result{Outcome: OutcomePermanent, Code: code, Text: "the receiver answered " + code + "; redirects are not followed, use the final URL"}
	default:
		return Result{Outcome: OutcomePermanent, Code: code, Text: "the receiver answered " + code + " (configuration error)"}
	}
}

// ClassifySMTPReply maps a reply code received BEFORE the final DATA reply to
// a Result: 4xx retries, 5xx is permanent. (A 2xx there is the normal flow and
// never reaches this.) The final DATA reply is the commit point and is decided
// in the sender.
func ClassifySMTPReply(code int, stage string) Result {
	c := "SMTP " + strconv.Itoa(code)
	if code >= 400 && code < 500 {
		return Result{Outcome: OutcomeRetry, Code: c, Text: "the mail server answered " + c + " at " + stage}
	}
	return Result{Outcome: OutcomePermanent, Code: c, Text: "the mail server answered " + c + " at " + stage}
}

// PermanentError marks an error that no retry can fix (blocked address,
// plaintext to a public address, secret that cannot be opened, ...). Senders
// return it; ClassifyError turns it into a permanent Result.
type PermanentError struct {
	Code string
	Msg  string
}

func (e *PermanentError) Error() string { return e.Msg }

// ClassifyError maps a transport error to a Result with our own text. The
// error's own text is never copied: it can hold a URL or an address.
func ClassifyError(err error) Result {
	var perm *PermanentError
	if errors.As(err, &perm) {
		return Result{Outcome: OutcomePermanent, Code: perm.Code, Text: perm.Msg}
	}
	var (
		dns     *net.DNSError
		unknown x509.UnknownAuthorityError
		hostErr x509.HostnameError
		invalid x509.CertificateInvalidError
		verify  *tls.CertificateVerificationError
		rec     tls.RecordHeaderError
		op      *net.OpError
	)
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return retry("connection refused", "the connection was refused")
	case errors.Is(err, syscall.ECONNRESET):
		return retry("connection reset", "the connection was reset")
	case errors.As(err, &dns):
		return retry("dns", "the host name could not be resolved")
	case errors.As(err, &unknown):
		return retry("tls", "TLS: certificate signed by an unknown authority")
	case errors.As(err, &hostErr):
		return retry("tls", "TLS: the certificate does not match the host name")
	case errors.As(err, &invalid):
		return retry("tls", "TLS: the certificate is not valid (expired or not yet valid)")
	case errors.As(err, &verify):
		return retry("tls", "TLS: the certificate could not be verified")
	case errors.As(err, &rec):
		return retry("tls", "TLS: the server did not speak TLS")
	case isTimeout(err):
		return retry("timeout", "the attempt timed out")
	case errors.As(err, &op):
		return retry("network", "network error while "+op.Op)
	}
	return retry("error", "the attempt failed")
}

func retry(code, text string) Result { return Result{Outcome: OutcomeRetry, Code: code, Text: text} }

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}
