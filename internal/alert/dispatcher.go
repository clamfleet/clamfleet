// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// dispatcher.go: plans, claims, sends and retries alerts.
//
// A pass: (1) if anything is flagged, held, due or expired, (2) release expired
// leases, (3) plan, (4) claim AS MANY due deliveries as there are idle workers
// and start each at once: state alerts first, then detections and summaries on
// the workers that remain, never more than workers-1 of them at a time (one
// worker is reserved for state alerts) and at most two per target. Nothing is claimed that is not already being sent, so
// there are no queued claims that burn attempts without being tried and none to
// lose in a crash.
//
// Every attempt has a hard deadline that starts at the claim, and its lease is
// longer than that deadline (deadline + 30 s), so a healthy attempt finishes, or
// is cut off by its own deadline, before its lease ends. The result is recorded
// only while the claim token still matches (the store's FinishAttempt), so a late
// result cannot overwrite a newer claim or a cancellation.
//
// At-least-once: a crash after the receiver accepted but before FinishAttempt
// leaves the lease to expire and the delivery is retried; receivers deduplicate
// on the alert id. A crash on the last attempt ends the delivery as failed (the
// store does that atomically), so a delivery that crashes the process cannot be
// retried forever.
//
// Dependencies: internal/store (AlertStore), the senders of this package, an
// injected clock, jitter source and secret opener. Nothing here reads the wall
// clock or the environment.
package alert

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/clamfleet/clamfleet/internal/store"
)

// Defaults of the dispatcher.
const (
	// DefaultWorkers is the number of concurrent sends.
	DefaultWorkers = 4
	// MaxDetectionsPerTarget caps detection sends in flight to one target, so a
	// dead receiver cannot occupy every worker (milestone 5, section 4.12).
	MaxDetectionsPerTarget = 2
	// leaseMargin is added to an attempt's hard deadline to form its lease.
	leaseMargin = 30 * time.Second
	// MaxTestSend caps a synchronous test send. The console answers it inside
	// one HTTP request whose WriteTimeout is 30 s (internal/server); a send that
	// outlived it would lose its result fragment, so the cap stays below that
	// whatever alert.webhook.timeout or smtp.timeout say (up to 120 s).
	MaxTestSend = 25 * time.Second
	// testSendGap is the minimum time between two test sends to one target.
	testSendGap = 10 * time.Second
)

// ErrTestRateLimited: a test send to this target is in flight or happened less
// than 10 seconds ago. It contains the use of the test send as a port scanner by
// a stolen admin session.
var ErrTestRateLimited = errors.New("test send rate limited")

// WebhookSend delivers one payload to a webhook (implemented by *WebhookSender).
type WebhookSend interface {
	Send(ctx context.Context, sec WebhookSecret, alertID string, body []byte) Result
}

// MailSend delivers one rendered message (implemented by *SMTPSender).
type MailSend interface {
	Send(ctx context.Context, msg EmailMessage) Result
}

// OpenFunc opens a sealed target secret (purpose alert-target, AAD = target id).
type OpenFunc func(blob []byte, targetID int64) ([]byte, error)

// NewAlertID returns a fresh public alert id: 128 random bits as hex.
func NewAlertID() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		panic(err) // the system random source is gone; nothing sensible can continue
	}
	return hex.EncodeToString(b)
}

// testState tracks the test sends of one target.
type testState struct {
	busy  bool
	start time.Time
}

// Dispatcher runs the alert pipeline. Construct it with the exported fields set
// and call Start once, then Run (or Pass/RunOnce in tests).
type Dispatcher struct {
	Store store.AlertStore
	// Webhook and Mail are the senders (production: *WebhookSender, *SMTPSender).
	// Mail is nil and MailFrom empty while email is not configured.
	Webhook WebhookSend
	Mail    MailSend
	// MailFrom is the envelope and header sender; empty = email is off.
	MailFrom string
	// WebhookTimeout and MailTimeout are the hard deadlines of one attempt; the
	// lease is the longer of them plus 30 s.
	WebhookTimeout, MailTimeout time.Duration
	// Open opens sealed secrets; nil means no key file (webhook deliveries fail
	// permanently with "secret cannot be opened").
	Open     OpenFunc
	Planner  Planner
	Cooldown time.Duration
	Now      func() time.Time
	// Jitter returns [0,1); nil means math/rand.
	Jitter func() float64
	Log    *slog.Logger
	// Workers is the number of concurrent sends (default 4).
	Workers int
	// TestBudget overrides MaxTestSend (tests); zero means MaxTestSend.
	TestBudget time.Duration

	mu        sync.Mutex
	inflight  int
	inflightD int // of inflight, detections and summaries (the reserve counts these)
	wg        sync.WaitGroup
	wake      chan struct{}
	testing   map[int64]*testState
}

// testTimeout is the budget of one test send: the target type's own timeout,
// but never more than the cap.
func (d *Dispatcher) testTimeout(typ string) time.Duration {
	cap := MaxTestSend
	if d.TestBudget > 0 {
		cap = d.TestBudget
	}
	return min(d.timeoutFor(typ), cap)
}

func (d *Dispatcher) workers() int {
	if d.Workers > 0 {
		return d.Workers
	}
	return DefaultWorkers
}

func (d *Dispatcher) jitter() float64 {
	if d.Jitter != nil {
		return d.Jitter()
	}
	return rand.Float64()
}

func (d *Dispatcher) wakeCh() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.wake == nil {
		d.wake = make(chan struct{}, 1)
	}
	return d.wake
}

// timeoutFor is the hard deadline of one attempt for a target type.
func (d *Dispatcher) timeoutFor(typ string) time.Duration {
	if typ == store.TargetTypeEmail {
		if d.MailTimeout > 0 {
			return d.MailTimeout
		}
		return 30 * time.Second
	}
	if d.WebhookTimeout > 0 {
		return d.WebhookTimeout
	}
	return 10 * time.Second
}

// Lease is how long a claim is held: longer than the longest attempt deadline.
func (d *Dispatcher) Lease() time.Duration {
	return max(d.timeoutFor(store.TargetTypeEmail), d.timeoutFor(store.TargetTypeWebhook)) + leaseMargin
}

// Start releases every claim at start-up: the server is single-instance (spec
// 2), so every claim found now belongs to a dead process. Its delivery is due at
// once, unless that was its last attempt, in which case it ends as failed.
func (d *Dispatcher) Start(ctx context.Context) error {
	expired, exhausted, err := d.Store.ExpireLeases(ctx, d.Now(), true)
	if err != nil {
		return fmt.Errorf("release alert claims: %w", err)
	}
	if expired+exhausted > 0 {
		d.Log.Warn("alert deliveries were interrupted by a restart", "requeued", expired, "gave_up", exhausted)
	}
	return nil
}

// Run does a pass at once, then on every tick and whenever a worker becomes
// idle, until ctx ends; it then waits for the workers (they stop with ctx).
func (d *Dispatcher) Run(ctx context.Context, tick <-chan time.Time) {
	wake := d.wakeCh()
	for {
		if err := d.Pass(ctx); err != nil && ctx.Err() == nil {
			d.Log.Error("alert pass failed", "err", err)
		}
		select {
		case <-ctx.Done():
			d.wg.Wait()
			return
		case <-tick:
		case <-wake:
		}
	}
}

// RunOnce does one pass and waits for the sends it started (tests).
func (d *Dispatcher) RunOnce(ctx context.Context) error {
	err := d.Pass(ctx)
	d.wg.Wait()
	return err
}

// Wake asks Run for a pass now, without waiting for the next tick. It never
// blocks and is safe from any goroutine: ingest calls it after a new
// detection, and the binary after each health evaluation, so an alert starts
// within milliseconds of its cause.
func (d *Dispatcher) Wake() {
	select {
	case d.wakeCh() <- struct{}{}:
	default:
	}
}

// Wait blocks until every started send has finished (tests).
func (d *Dispatcher) Wait() { d.wg.Wait() }

// Inflight is the number of sends running now.
func (d *Dispatcher) Inflight() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.inflight
}

// Pass runs one pass without waiting for the sends it starts.
func (d *Dispatcher) Pass(ctx context.Context) error {
	now := d.Now()
	work, err := d.Store.HasAlertWork(ctx, now, d.Cooldown)
	if err != nil {
		return fmt.Errorf("check for alert work: %w", err)
	}
	if !work {
		return nil
	}
	if expired, exhausted, err := d.Store.ExpireLeases(ctx, now, false); err != nil {
		return fmt.Errorf("expire alert leases: %w", err)
	} else if expired+exhausted > 0 {
		d.Log.Warn("alert attempts did not finish before their lease ended", "requeued", expired, "gave_up", exhausted)
	}
	res, err := d.Store.PlanAlerts(ctx, now, d.Cooldown, d.Planner.Plan)
	if err != nil {
		return fmt.Errorf("plan alerts: %w", err)
	}
	d.logPlan(res)

	d.mu.Lock()
	idle := d.workers() - d.inflight
	// Rule: one worker is kept for state alerts. Detections and summaries may
	// hold at most workers-1 workers, whatever is idle, so a flood of detections
	// (or a dead detection receiver hanging to its deadline) never delays a CRIT
	// by more than the next pass, which a state transition's wake starts at once.
	detections := max(d.workers()-1-d.inflightD, 0)
	d.mu.Unlock()
	if idle <= 0 {
		return nil
	}
	claimed, err := d.Store.ClaimDeliveries(ctx, now, d.Lease(), store.ClaimLimits{
		Total: idle, Detections: detections, PerTarget: MaxDetectionsPerTarget,
	})
	if err != nil {
		return fmt.Errorf("claim alert deliveries: %w", err)
	}
	for _, c := range claimed {
		detection := c.Kind != store.DeliveryStateChange
		d.mu.Lock()
		d.inflight++
		if detection {
			d.inflightD++
		}
		d.mu.Unlock()
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			defer func() {
				d.mu.Lock()
				d.inflight--
				if detection {
					d.inflightD--
				}
				d.mu.Unlock()
				select { // a worker is idle: let Run claim again
				case d.wakeCh() <- struct{}{}:
				default:
				}
			}()
			d.deliver(ctx, c)
		}()
	}
	return nil
}

// logPlan writes one info line per planned alert (so journald forwarders see
// alerts too, M4 decision 17) and one warn line per detection no target matched.
func (d *Dispatcher) logPlan(res store.PlanResult) {
	seen := map[string]bool{}
	for _, nd := range res.Deliveries {
		if seen[nd.AlertID] {
			continue
		}
		seen[nd.AlertID] = true
		var p struct {
			Kind string  `json:"kind"`
			Host string  `json:"host"`
			From *string `json:"from"`
			To   string  `json:"to"`
		}
		_ = json.Unmarshal(nd.Payload, &p)
		attrs := []any{"kind", p.Kind, "host", p.Host, "alert_id", nd.AlertID}
		if p.Kind == KindStateChange {
			from := "none"
			if p.From != nil {
				from = *p.From
			}
			attrs = append(attrs, "from", from, "to", p.To)
		}
		d.Log.Info("alert", attrs...)
	}
	for _, u := range res.Unrouted {
		d.Log.Warn("detection matched no alert target", "host", u.Host, "event_id", u.EventID)
	}
}

// deliver sends one claimed delivery and records the outcome.
func (d *Dispatcher) deliver(ctx context.Context, c store.ClaimedDelivery) {
	// The deadline starts HERE, at the claim: Pass starts this goroutine
	// immediately for every claim it makes.
	actx, cancel := context.WithTimeout(ctx, d.timeoutFor(c.Target.Type))
	defer cancel()
	r := d.send(actx, c)
	if ctx.Err() != nil {
		// Shutting down: record nothing. The lease expires, the next start turns
		// the attempt into 'interrupted' and the delivery is retried.
		return
	}

	now := d.Now()
	ar := store.AttemptResult{Code: r.Code, Error: r.Text, Duration: r.Duration}
	switch r.Outcome {
	case OutcomeSent:
		ar.Status = store.AlertLogSent
	case OutcomePermanent:
		ar.Status = store.AlertLogFailed
	default:
		delay, ok := NextDelay(c.Attempt, r.RetryAfter, d.jitter)
		if ok {
			ar.Status, ar.RetryAt = store.AlertLogRetrying, now.Add(delay)
		} else {
			ar.Status = store.AlertLogFailed
			ar.Error = fmt.Sprintf("%s; giving up after %d attempts", r.Text, MaxAttempts)
		}
	}
	// A fresh context: the attempt's own deadline may have just passed, and the
	// outcome must still be written.
	fctx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer fcancel()
	err := d.Store.FinishAttempt(fctx, c, ar, now)
	attrs := []any{"target", c.Target.Name, "host", c.HostName, "kind", c.Kind, "alert_id", c.AlertID, "attempt", c.Attempt, "code", r.Code}
	switch {
	case errors.Is(err, store.ErrLeaseLost):
		d.Log.Warn("alert attempt finished after its claim was lost; the result was not recorded as the delivery's", append(attrs, "outcome", ar.Status)...)
	case err != nil:
		d.Log.Error("recording an alert attempt failed", append(attrs, "err", err)...)
	case ar.Status == store.AlertLogSent:
		d.Log.Info("alert delivered", attrs...)
	case ar.Status == store.AlertLogRetrying:
		d.Log.Warn("alert attempt failed, will retry", append(attrs, "error", ar.Error, "retry_at", ar.RetryAt)...)
	default:
		d.Log.Error("alert delivery failed", append(attrs, "error", ar.Error)...)
	}
}

// send runs the sender of the delivery's target type.
func (d *Dispatcher) send(ctx context.Context, c store.ClaimedDelivery) Result {
	switch c.Target.Type {
	case store.TargetTypeWebhook:
		sec, res, ok := d.openWebhook(c.Target)
		if !ok {
			return res
		}
		return d.Webhook.Send(ctx, sec, c.AlertID, c.Payload)
	case store.TargetTypeEmail:
		if d.Mail == nil || d.MailFrom == "" {
			return Result{Outcome: OutcomePermanent, Code: "not configured", Text: "email is not configured (smtp.host)"}
		}
		m, err := RenderEmail(d.MailFrom, c.Recipient, c.Target.ID, c.Payload, d.Now())
		if err != nil {
			return Result{Outcome: OutcomePermanent, Code: "invalid", Text: "the alert could not be rendered as an email"}
		}
		return d.Mail.Send(ctx, m)
	}
	return Result{Outcome: OutcomePermanent, Code: "invalid", Text: "unknown target type"}
}

// openWebhook opens and parses a webhook target's sealed secret. ok is false
// with a permanent Result when it cannot be opened (no key file, an unknown or
// retired key, a blob that belongs to another target: the AAD is the target id).
func (d *Dispatcher) openWebhook(t store.AlertTarget) (sec WebhookSecret, res Result, ok bool) {
	fail := Result{Outcome: OutcomePermanent, Code: "secret", Text: "the webhook secret cannot be opened (key file missing or key retired); enter the URL again and rotate the key"}
	if d.Open == nil || len(t.Sealed) == 0 {
		return sec, fail, false
	}
	plain, err := d.Open(t.Sealed, t.ID)
	if err != nil {
		return sec, fail, false
	}
	sec, err = ParseWebhookSecret(plain)
	if err != nil {
		return sec, fail, false
	}
	return sec, Result{}, true
}

// TestSend delivers a kind "test" payload to a saved target, synchronously,
// through the same senders and policy as real alerts. It bypasses the queue,
// cooldown, filters and retry. An email target gets one message per recipient in
// turn, within one overall timeout. At most one test is in flight per target and
// one per 10 seconds (ErrTestRateLimited), on the injected clock.
//
// It returns one record per recipient ("" for a webhook); the caller writes them
// with store.RecordTestSend.
func (d *Dispatcher) TestSend(ctx context.Context, t store.AlertTarget) ([]store.TestSendRecord, error) {
	now := d.Now()
	d.mu.Lock()
	if d.testing == nil {
		d.testing = map[int64]*testState{}
	}
	st := d.testing[t.ID]
	if st == nil {
		st = &testState{}
		d.testing[t.ID] = st
	}
	if st.busy || (!st.start.IsZero() && now.Sub(st.start) < testSendGap) {
		d.mu.Unlock()
		return nil, ErrTestRateLimited
	}
	st.busy, st.start = true, now
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		st.busy = false // the 10 s gap is measured from the start, which stays
		d.mu.Unlock()
	}()

	id := NewAlertID()
	body, err := Marshal(TestPayload{Schema: SchemaVersion, ID: id, Kind: KindTest, Target: t.Name, TS: FormatTime(now), URL: RootURL(d.Planner.PublicURL)})
	if err != nil {
		return nil, err
	}
	toRecord := func(recipient string, r Result) store.TestSendRecord {
		ar := store.AttemptResult{Code: r.Code, Error: r.Text, Duration: r.Duration, Status: store.AlertLogFailed}
		if r.Outcome == OutcomeSent {
			ar.Status = store.AlertLogSent
		}
		return store.TestSendRecord{Recipient: recipient, Result: ar}
	}
	switch t.Type {
	case store.TargetTypeWebhook:
		actx, cancel := context.WithTimeout(ctx, d.testTimeout(t.Type))
		defer cancel()
		sec, res, ok := d.openWebhook(t)
		if !ok {
			return []store.TestSendRecord{toRecord("", res)}, nil
		}
		return []store.TestSendRecord{toRecord("", d.Webhook.Send(actx, sec, id, body))}, nil
	case store.TargetTypeEmail:
		actx, cancel := context.WithTimeout(ctx, d.testTimeout(t.Type))
		defer cancel()
		to, err := Recipients(t.Config)
		if err != nil || len(to) == 0 {
			return []store.TestSendRecord{toRecord("", Result{Outcome: OutcomePermanent, Code: "invalid", Text: "the target has no readable recipients"})}, nil
		}
		var out []store.TestSendRecord
		for _, r := range to {
			if d.Mail == nil || d.MailFrom == "" {
				out = append(out, toRecord(r, Result{Outcome: OutcomePermanent, Code: "not configured", Text: "email is not configured (smtp.host)"}))
				continue
			}
			m, err := RenderEmail(d.MailFrom, r, t.ID, body, now)
			if err != nil {
				out = append(out, toRecord(r, Result{Outcome: OutcomePermanent, Code: "invalid", Text: "the test could not be rendered"}))
				continue
			}
			out = append(out, toRecord(r, d.Mail.Send(actx, m)))
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown target type %q", t.Type)
}
