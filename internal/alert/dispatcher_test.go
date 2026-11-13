// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package alert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
	"github.com/clamfleet/clamfleet/internal/store"
	"github.com/clamfleet/clamfleet/internal/store/sqlite"
	"github.com/clamfleet/clamfleet/internal/testsmtp"
)

var cliActor = store.Audit{Kind: store.ActorCLI, Actor: "tester"}

// ------------------------------------------------------------------ harness

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Set(t time.Time)     { c.mu.Lock(); c.t = t; c.mu.Unlock() }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// lockedBuf is a log sink that tolerates concurrent writers.
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

// fakeWebhook scripts the webhook sender.
type fakeWebhook struct {
	mu    sync.Mutex
	calls []string // alert ids, in call order
	fn    func(call int, alertID string, body []byte, ctx context.Context) Result
}

func (f *fakeWebhook) Send(ctx context.Context, sec WebhookSecret, alertID string, body []byte) Result {
	f.mu.Lock()
	f.calls = append(f.calls, alertID)
	n := len(f.calls)
	f.mu.Unlock()
	if f.fn == nil {
		return Result{Outcome: OutcomeSent, Code: "HTTP 204"}
	}
	return f.fn(n, alertID, body, ctx)
}

func (f *fakeWebhook) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

type dispEnv struct {
	t     *testing.T
	path  string
	clk   *clock
	logs  *lockedBuf
	wh    *fakeWebhook
	mail  MailSend
	st    *sqlite.Store
	d     *Dispatcher
	cool  time.Duration
	idseq int
}

func newDispEnv(t *testing.T) *dispEnv {
	t.Helper()
	e := &dispEnv{t: t, path: filepath.Join(t.TempDir(), "d.db"), clk: &clock{t: t0}, logs: &lockedBuf{}, wh: &fakeWebhook{}, cool: 15 * time.Minute}
	e.open()
	if err := e.st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e
}

// open (re)opens the store and builds a fresh dispatcher on the same file: a
// process restart.
func (e *dispEnv) open() {
	e.t.Helper()
	if e.st != nil {
		e.st.Close()
	}
	st, err := sqlite.Open(context.Background(), e.path)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { st.Close() })
	e.st = st
	e.d = e.newDispatcher()
}

func (e *dispEnv) newDispatcher() *Dispatcher {
	return &Dispatcher{
		Store: e.st, Webhook: e.wh, Mail: e.mail, MailFrom: func() string {
			if e.mail != nil {
				return "clamfleet@test.example"
			}
			return ""
		}(),
		WebhookTimeout: 10 * time.Second, MailTimeout: 30 * time.Second,
		Open: func(blob []byte, id int64) ([]byte, error) {
			if string(blob) != fmt.Sprintf("sealed-%d", id) { // the AAD stands in as the id inside the blob
				return nil, errors.New("decrypt")
			}
			return json.Marshal(WebhookSecret{URL: "https://hooks.example/x", SigningKey: "whsec_" + vecSecret})
		},
		Planner:  Planner{PublicURL: "https://cf.example", NewID: func() string { e.idseq++; return fmt.Sprintf("alert%04d", e.idseq) }},
		Cooldown: e.cool, Now: e.clk.Now, Jitter: func() float64 { return 0.5 },
		Log: slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
}

func (e *dispEnv) host(name string) int64 {
	e.t.Helper()
	sum := sha256.Sum256([]byte(name))
	h, err := e.st.CreateHost(context.Background(), name, sum[:], e.clk.Now(), cliActor)
	if err != nil {
		e.t.Fatal(err)
	}
	return h.ID
}

func (e *dispEnv) webhook(name string, edit func(*store.NewAlertTarget)) store.AlertTarget {
	e.t.Helper()
	nt := store.NewAlertTarget{Name: name, Type: store.TargetTypeWebhook, Config: []byte(`{"url_display":"https://hooks.example/…"}`),
		MinSeverity: "WARN", SendStateChanges: true, SendDetections: true, Enabled: true}
	if edit != nil {
		edit(&nt)
	}
	tg, err := e.st.CreateAlertTarget(context.Background(), nt, func(id int64) ([]byte, error) { return []byte(fmt.Sprintf("sealed-%d", id)), nil }, e.clk.Now(), cliActor)
	if err != nil {
		e.t.Fatal(err)
	}
	return tg
}

func (e *dispEnv) email(name string, to ...string) store.AlertTarget {
	e.t.Helper()
	cfg, _ := json.Marshal(EmailConfig{To: to})
	tg, err := e.st.CreateAlertTarget(context.Background(), store.NewAlertTarget{Name: name, Type: store.TargetTypeEmail, Config: cfg,
		MinSeverity: "WARN", SendStateChanges: true, SendDetections: true, Enabled: true}, nil, e.clk.Now(), cliActor)
	if err != nil {
		e.t.Fatal(err)
	}
	return tg
}

// state moves the given hosts (nil = all) to state at the current clock time.
func (e *dispEnv) state(state string, ids ...int64) {
	e.t.Helper()
	var sel []int64
	if len(ids) > 0 {
		sel = ids
	}
	if _, err := e.st.EvaluateHosts(context.Background(), e.clk.Now(), sel, func(store.HealthInput) store.HealthOutcome {
		return store.HealthOutcome{State: state, Reasons: json.RawMessage(`[{"rule":"r","severity":"` + state + `","msg":"m"}]`)}
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *dispEnv) once() {
	e.t.Helper()
	if err := e.d.RunOnce(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *dispEnv) q(query string, args ...any) int {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+e.path+"?mode=ro")
	if err != nil {
		e.t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *dispEnv) statuses(status string) int {
	return e.q(`SELECT count(*) FROM alert_deliveries WHERE status = ?`, status)
}

func (e *dispEnv) logRows(status string) int {
	return e.q(`SELECT count(*) FROM alert_log WHERE status = ?`, status)
}

// ------------------------------------------------------------------- tests

func TestNoRedeliveryAfterSuccess(t *testing.T) {
	e := newDispEnv(t)
	e.host("a")
	e.webhook("t1", nil)
	e.webhook("t2", nil)
	e.state("CRIT")
	for range 5 {
		e.once()
	}
	if n := e.q(`SELECT count(*) FROM alert_deliveries`); n != 2 || e.statuses("sent") != 2 {
		t.Fatalf("%d deliveries, %d sent", n, e.statuses("sent"))
	}
	if n := e.logRows("sent"); n != 2 {
		t.Fatalf("%d sent log rows", n)
	}
	if e.wh.count() != 2 {
		t.Fatalf("%d sends: nothing may go out twice in the absence of failures", e.wh.count())
	}
	// One info line "alert" for the planned alert (shared by both targets).
	if n := strings.Count(e.logs.String(), `"msg":"alert"`); n != 1 {
		t.Fatalf("%d alert lines:\n%s", n, e.logs.String())
	}
}

// Mutation 11 (a fixed batch instead of the idle workers) and 12 (a deadline
// that starts later than the claim, or a lease shorter than it).
func TestClaimsMatchCapacity(t *testing.T) {
	e := newDispEnv(t)
	for i := range 20 {
		e.host(fmt.Sprintf("h%02d", i))
	}
	e.webhook("t", nil)
	e.state("CRIT")
	release := make(chan struct{}, 64)
	e.wh.fn = func(_ int, _ string, _ []byte, ctx context.Context) Result {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return Result{Outcome: OutcomeSent, Code: "HTTP 204"}
	}
	if err := e.d.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := e.q(`SELECT count(*) FROM alert_deliveries WHERE attempts = 1 AND claim_token IS NOT NULL`); n != 4 {
		t.Fatalf("%d claimed rows after the first pass, want exactly 4", n)
	}
	if n := e.q(`SELECT count(*) FROM alert_deliveries WHERE attempts = 0 AND claim_token IS NULL`); n != 16 {
		t.Fatalf("%d untouched rows, want 16", n)
	}
	// The lease is longer than the attempt's hard deadline, and is what the claim stored.
	if e.d.Lease() <= e.d.timeoutFor(store.TargetTypeWebhook) || e.d.Lease() <= e.d.timeoutFor(store.TargetTypeEmail) {
		t.Fatalf("lease %v must exceed every attempt deadline", e.d.Lease())
	}
	if n := e.q(`SELECT count(*) FROM alert_deliveries WHERE claim_token IS NOT NULL AND next_attempt_at = ?`, t0.Add(e.d.Lease()).Unix()); n != 4 {
		t.Fatalf("%d rows hold the lease expiry now+lease", n)
	}
	// Releasing one lets exactly one more be claimed.
	release <- struct{}{}
	waitFor(t, func() bool { return e.d.Inflight() == 3 })
	if err := e.d.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := e.q(`SELECT count(*) FROM alert_deliveries WHERE attempts >= 1`); n != 5 {
		t.Fatalf("%d rows claimed after one release, want 5", n)
	}
	for range 40 {
		release <- struct{}{}
	}
	e.d.Wait()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 2000 {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// With 4 sends blocked and the dispatcher abandoned, only those 4 were charged
// an attempt; after the start-up expiry every delivery goes out.
func TestCrashBeforeQueuedClaimsStart(t *testing.T) {
	e := newDispEnv(t)
	for i := range 20 {
		e.host(fmt.Sprintf("h%02d", i))
	}
	e.webhook("t", nil)
	e.state("CRIT")
	e.wh.fn = func(_ int, _ string, _ []byte, ctx context.Context) Result {
		<-ctx.Done() // never returns on its own: the process "crashes"
		return Result{Outcome: OutcomeRetry, Code: "timeout"}
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := e.d.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	e.d.Wait()
	if n := e.q(`SELECT count(*) FROM alert_deliveries WHERE attempts = 1`); n != 4 {
		t.Fatalf("%d rows were charged an attempt, want 4", n)
	}
	e.open()
	e.wh.fn = nil
	if err := e.d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		e.once()
	}
	if e.statuses("sent") != 20 {
		t.Fatalf("%d sent of 20", e.statuses("sent"))
	}
	if n := e.q(`SELECT count(*) FROM alert_deliveries WHERE attempts = 2`); n != 4 {
		t.Fatalf("%d rows with 2 attempts, want the 4 that really started twice", n)
	}
	if n := e.q(`SELECT count(*) FROM alert_deliveries WHERE attempts = 1`); n != 16 {
		t.Fatalf("%d rows with 1 attempt", n)
	}
	if n := e.logRows("interrupted"); n != 4 {
		t.Fatalf("%d interrupted rows", n)
	}
}

// Mutation 13 at the dispatcher level: a late result must not overwrite a
// newer claim's result.
func TestLateFinishCannotOverwrite(t *testing.T) {
	e := newDispEnv(t)
	e.host("a")
	e.webhook("t", nil)
	e.state("CRIT")
	unblock := make(chan struct{})
	e.wh.fn = func(n int, _ string, _ []byte, ctx context.Context) Result {
		if n == 1 {
			<-unblock
			return Result{Outcome: OutcomePermanent, Code: "HTTP 400", Text: "late failure"}
		}
		return Result{Outcome: OutcomeSent, Code: "HTTP 204"}
	}
	if err := e.d.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return e.wh.count() == 1 })
	e.clk.Add(e.d.Lease() + time.Second) // the lease ends
	if err := e.d.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return e.statuses("sent") == 1 })
	close(unblock)
	e.d.Wait()
	if e.statuses("sent") != 1 || e.statuses("failed") != 0 {
		t.Fatalf("the late failure overwrote the newer claim: sent=%d failed=%d", e.statuses("sent"), e.statuses("failed"))
	}
	if !strings.Contains(e.logs.String(), "claim was lost") {
		t.Fatalf("no warning for the lost lease:\n%s", e.logs.String())
	}
	if n := e.logRows("interrupted"); n != 1 {
		t.Fatalf("%d interrupted rows", n)
	}
}

// Mutation 15: backoff not applied, or 6 attempts.
func TestRetryScheduleAndLogRows(t *testing.T) {
	e := newDispEnv(t)
	e.host("a")
	e.webhook("t", nil)
	e.state("CRIT")
	e.wh.fn = func(n int, _ string, _ []byte, _ context.Context) Result {
		if n <= 4 {
			return Result{Outcome: OutcomeRetry, Code: "HTTP 503", Text: "the receiver answered HTTP 503"}
		}
		return Result{Outcome: OutcomeSent, Code: "HTTP 204"}
	}
	e.once() // attempt 1 at t0
	for i, delay := range []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 60 * time.Minute} {
		before := e.wh.count()
		e.clk.Add(delay - time.Second)
		e.once()
		if e.wh.count() != before {
			t.Fatalf("attempt %d was sent %v after the previous one, one second early", i+2, delay)
		}
		e.clk.Add(time.Second)
		e.once()
		if e.wh.count() != before+1 {
			t.Fatalf("attempt %d was not sent after %v", i+2, delay)
		}
	}
	if e.statuses("sent") != 1 || e.logRows("retrying") != 4 || e.logRows("sent") != 1 {
		t.Fatalf("sent=%d retrying rows=%d sent rows=%d", e.statuses("sent"), e.logRows("retrying"), e.logRows("sent"))
	}
	if n := e.q(`SELECT count(*) FROM alert_log WHERE status = 'retrying' AND code = 'HTTP 503'`); n != 4 {
		t.Fatalf("%d", n)
	}
}

func TestExhaustionEndsAtFiveAttempts(t *testing.T) {
	e := newDispEnv(t)
	e.host("a")
	e.webhook("t", nil)
	e.state("CRIT")
	e.wh.fn = func(int, string, []byte, context.Context) Result {
		return Result{Outcome: OutcomeRetry, Code: "HTTP 500", Text: "the receiver answered HTTP 500"}
	}
	for range 5 {
		e.once()
		e.clk.Add(61 * time.Minute)
	}
	e.once()
	e.clk.Add(24 * time.Hour)
	e.once()
	if e.statuses("failed") != 1 || e.wh.count() != 5 {
		t.Fatalf("failed=%d, %d attempts, want 1 and 5", e.statuses("failed"), e.wh.count())
	}
	if n := e.q(`SELECT count(*) FROM alert_log WHERE delivery_id IS NOT NULL`); n != 5 {
		t.Fatalf("%d log rows, want 5 (one per attempt)", n)
	}
	if !strings.Contains(e.logs.String(), "giving up after 5 attempts") || !strings.Contains(e.logs.String(), `"level":"ERROR"`) {
		t.Fatalf("the final failure must be logged at error:\n%s", e.logs.String())
	}
}

func TestPermanentFailureIsOneAttempt(t *testing.T) {
	e := newDispEnv(t)
	e.host("a")
	e.webhook("t", nil)
	e.state("CRIT")
	e.wh.fn = func(int, string, []byte, context.Context) Result {
		return Result{Outcome: OutcomePermanent, Code: "HTTP 404", Text: "the receiver answered HTTP 404 (configuration error)"}
	}
	e.once()
	e.clk.Add(48 * time.Hour)
	e.once()
	if e.statuses("failed") != 1 || e.wh.count() != 1 {
		t.Fatalf("failed=%d attempts=%d", e.statuses("failed"), e.wh.count())
	}
}

// Review finding 2: a delivery that crashes the process ends after 5 starts,
// and the terminal row no longer blocks later alerts for the pair.
func TestRepeatedCrashesEndAtFiveAttempts(t *testing.T) {
	e := newDispEnv(t)
	e.cool = 0
	e.host("a")
	e.webhook("t", nil)
	e.state("CRIT")
	hang := func(_ int, _ string, _ []byte, ctx context.Context) Result {
		<-ctx.Done()
		return Result{Outcome: OutcomeRetry, Code: "timeout"}
	}
	for i := 1; i <= 5; i++ {
		e.open()
		e.d.Cooldown = 0
		e.wh.fn = hang
		if err := e.d.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		if err := e.d.Pass(ctx); err != nil {
			t.Fatal(err)
		}
		waitFor(t, func() bool { return e.d.Inflight() == 1 })
		cancel() // the process dies mid-send
		e.d.Wait()
		if n := e.q(`SELECT attempts FROM alert_deliveries`); n != i {
			t.Fatalf("after crash %d the delivery shows %d attempts", i, n)
		}
		e.clk.Add(e.d.Lease() + time.Second)
	}
	e.open()
	e.d.Cooldown = 0
	e.wh.fn = nil
	if err := e.d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.statuses("failed") != 1 || e.logRows("interrupted") != 5 || e.logRows("failed") != 1 {
		t.Fatalf("failed=%d interrupted rows=%d failed rows=%d", e.statuses("failed"), e.logRows("interrupted"), e.logRows("failed"))
	}
	before := e.wh.count()
	e.once()
	if e.wh.count() != before {
		t.Fatal("a sixth claim happened")
	}
	// The recovery for the same (target, host) is planned and delivered.
	e.clk.Add(time.Minute)
	e.state("OK")
	e.once()
	if e.statuses("sent") != 1 || e.wh.count() != before+1 {
		t.Fatalf("the failed row blocks the pair: sent=%d", e.statuses("sent"))
	}
}

func TestRestartDeliversWhatWasPlanned(t *testing.T) {
	e := newDispEnv(t)
	e.host("a")
	e.webhook("t", nil)
	e.state("CRIT")
	if _, err := e.st.PlanAlerts(context.Background(), e.clk.Now(), e.cool, e.d.Planner.Plan); err != nil {
		t.Fatal(err)
	}
	e.open() // restart: nothing in memory
	if err := e.d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.once()
	if e.statuses("sent") != 1 {
		t.Fatal("a planned alert was lost by the restart")
	}
	// A transition recorded while no dispatcher runs is delivered on the first pass.
	e.clk.Add(time.Hour)
	e.state("OK")
	e.open()
	e.once()
	if e.statuses("sent") != 2 {
		t.Fatalf("sent=%d", e.statuses("sent"))
	}
}

func startSMTPServer(t *testing.T, o testsmtp.Options) *testsmtp.Server {
	t.Helper()
	s, err := testsmtp.Listen("127.0.0.1:0", o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func (e *dispEnv) useSMTP(srv *testsmtp.Server) {
	s := smtpSender(srv, SMTPNone)
	s.Now = e.clk.Now
	e.mail = s
	e.d = e.newDispatcher()
}

// Review finding 3: a mixed outcome across recipients survives a restart.
func TestMixedRecipientsAcrossRestart(t *testing.T) {
	e := newDispEnv(t)
	e.host("a")
	srv := startSMTPServer(t, testsmtp.Options{RcptReplies: map[string]string{"b@x.example": "450 later", "c@x.example": "550 no such user"}})
	e.useSMTP(srv)
	e.email("mail", "a@x.example", "b@x.example", "c@x.example")
	e.state("CRIT")
	e.once()
	st := func(r string) string {
		db, _ := sql.Open("sqlite", "file:"+e.path+"?mode=ro")
		defer db.Close()
		var s string
		db.QueryRow(`SELECT status FROM alert_deliveries WHERE recipient = ?`, r).Scan(&s)
		return s
	}
	if st("a@x.example") != "sent" || st("b@x.example") != "pending" || st("c@x.example") != "failed" {
		t.Fatalf("a=%s b=%s c=%s", st("a@x.example"), st("b@x.example"), st("c@x.example"))
	}
	srv.Update(func(o *testsmtp.Options) { delete(o.RcptReplies, "b@x.example") })
	e.open()
	e.useSMTP(srv)
	if err := e.d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.clk.Add(time.Minute)
	e.once()
	if st("b@x.example") != "sent" {
		t.Fatalf("b = %s", st("b@x.example"))
	}
	perRecipient := map[string]int{}
	for _, m := range srv.Messages() {
		perRecipient[m.To[0]]++
	}
	if perRecipient["a@x.example"] != 1 || perRecipient["b@x.example"] != 1 || perRecipient["c@x.example"] != 0 {
		t.Fatalf("messages per recipient %v: a must never be re-sent, c never retried", perRecipient)
	}
	rcptC := 0
	for _, ev := range srv.Events() {
		if ev == "RCPT c@x.example" {
			rcptC++
		}
	}
	if rcptC != 1 {
		t.Fatalf("c was tried %d times", rcptC)
	}
}

// Review finding 4: the commit point across a restart.
func TestSMTPCommitPointAcrossRestart(t *testing.T) {
	e := newDispEnv(t)
	e.host("a")
	srv := startSMTPServer(t, testsmtp.Options{DropAtFinalDot: true})
	e.useSMTP(srv)
	e.email("mail", "a@x.example")
	e.state("CRIT")
	e.once()
	if e.statuses("pending") != 1 || e.logRows("retrying") != 1 || len(srv.Unacked()) != 1 {
		t.Fatalf("pending=%d retrying=%d unacked=%d", e.statuses("pending"), e.logRows("retrying"), len(srv.Unacked()))
	}
	srv.Update(func(o *testsmtp.Options) { o.DropAtFinalDot, o.DropAfterFinalReply = false, true })
	e.open()
	e.useSMTP(srv)
	if err := e.d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.clk.Add(time.Minute)
	e.once()
	if e.statuses("sent") != 1 {
		t.Fatalf("a 250 followed by a drop before QUIT must be sent: sent=%d", e.statuses("sent"))
	}
	for range 3 {
		e.open()
		e.useSMTP(srv)
		e.clk.Add(24 * time.Hour)
		e.once()
	}
	if len(srv.Messages()) != 1 {
		t.Fatalf("%d acknowledged messages after a restart and days of passes, want 1", len(srv.Messages()))
	}
}

// A webhook target answering 500 does not hold up the email target.
func TestWebhookOutageDoesNotDelayEmail(t *testing.T) {
	e := newDispEnv(t)
	e.host("a")
	srv := startSMTPServer(t, testsmtp.Options{})
	e.useSMTP(srv)
	e.webhook("hook", nil)
	e.email("mail", "a@x.example")
	e.wh.fn = func(int, string, []byte, context.Context) Result {
		return Result{Outcome: OutcomeRetry, Code: "HTTP 500", Text: "x"}
	}
	e.state("CRIT")
	e.once()
	if len(srv.Messages()) != 1 {
		t.Fatalf("the email was delayed by the failing webhook")
	}
}

// Mutation 10 at the dispatcher level: the recovery is not sent before the
// CRIT that is still being retried.
func TestOrderPerTargetAndHost(t *testing.T) {
	e := newDispEnv(t)
	e.cool = 0
	e.d.Cooldown = 0
	e.host("a")
	e.webhook("t", nil)
	var mu sync.Mutex
	var order []string
	e.wh.fn = func(n int, _ string, body []byte, _ context.Context) Result {
		var p struct{ To string }
		json.Unmarshal(body, &p)
		mu.Lock()
		order = append(order, p.To)
		mu.Unlock()
		if n == 1 {
			return Result{Outcome: OutcomeRetry, Code: "HTTP 503", Text: "x"}
		}
		return Result{Outcome: OutcomeSent, Code: "HTTP 204"}
	}
	e.state("CRIT")
	e.once() // CRIT fails, retrying
	e.clk.Add(10 * time.Second)
	e.state("OK")
	e.clk.Add(10 * time.Second)
	e.once()
	mu.Lock()
	if len(order) != 1 {
		t.Fatalf("the recovery was sent before the CRIT finished: %v", order)
	}
	mu.Unlock()
	e.clk.Add(time.Minute)
	e.once() // CRIT retried and sent
	e.once() // now the recovery
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(order, ",") != "CRIT,CRIT,OK" {
		t.Fatalf("order %v", order)
	}
}

func TestUnreadableSecretFailsPermanentlyWithoutSending(t *testing.T) {
	e := newDispEnv(t)
	e.host("a")
	tg := e.webhook("t", nil)
	e.state("CRIT")
	// Another target's blob in this row: the AAD (target id) does not match.
	if _, err := e.st.UpdateAlertTarget(context.Background(), "t", store.AlertTargetUpdate{Config: tg.Config, MinSeverity: "WARN", SendStateChanges: true, SendDetections: true, Enabled: true},
		func(int64) ([]byte, error) { return []byte("sealed-999"), nil }, e.clk.Now(), cliActor); err != nil {
		t.Fatal(err)
	}
	e.once()
	if e.statuses("failed") != 1 || e.wh.count() != 0 {
		t.Fatalf("failed=%d sends=%d", e.statuses("failed"), e.wh.count())
	}
	if n := e.q(`SELECT count(*) FROM alert_log WHERE status = 'failed' AND code = 'secret' AND error LIKE '%cannot be opened%'`); n != 1 {
		t.Fatal("the failure text must say the secret cannot be opened")
	}
	// No key file at all: the same.
	e2 := newDispEnv(t)
	e2.host("a")
	e2.webhook("t", nil)
	e2.d.Open = nil
	e2.state("CRIT")
	e2.once()
	if e2.statuses("failed") != 1 || e2.wh.count() != 0 {
		t.Fatal("no key file: the delivery must fail permanently without sending")
	}
}

func TestEmailNotConfiguredFailsPermanently(t *testing.T) {
	e := newDispEnv(t)
	e.host("a")
	e.email("mail", "a@x.example")
	e.state("CRIT")
	e.once()
	if e.statuses("failed") != 1 || e.q(`SELECT count(*) FROM alert_log WHERE error LIKE '%smtp.host%'`) != 1 {
		t.Fatal("email without smtp.host must fail permanently with a clear text")
	}
}

// Mutation 38 at the dispatcher level: an unrouted detection is logged.
func TestUnroutedDetectionIsLogged(t *testing.T) {
	e := newDispEnv(t)
	id := e.host("a")
	e.webhook("t", func(n *store.NewAlertTarget) { n.TagFilter = []string{"prod"} })
	if _, err := e.st.RecordEvent(context.Background(), store.EventRecord{HostID: id, ReceivedAt: e.clk.Now(),
		Event: protoEvent(e.clk.Now())}); err != nil {
		t.Fatal(err)
	}
	e.once()
	if !strings.Contains(e.logs.String(), `"msg":"detection matched no alert target"`) || !strings.Contains(e.logs.String(), `"host":"a"`) {
		t.Fatalf("no warning:\n%s", e.logs.String())
	}
	if e.q(`SELECT count(*) FROM events WHERE alert_pending = 1`) != 0 || e.q(`SELECT count(*) FROM events`) != 1 {
		t.Fatal("the flag must be cleared and the event kept")
	}
}

func TestPruneRunsOncePerDayOfTheInjectedClock(t *testing.T) {
	e := newDispEnv(t)
	e.host("a")
	e.webhook("t", nil)
	old := e.clk.Now().Add(-Retention - time.Hour).Unix()
	if _, err := e.st.PruneAlertHistory(context.Background(), e.clk.Now(), 10); err != nil {
		t.Fatal(err)
	}
	seed := func() {
		db, _ := sql.Open("sqlite", "file:"+e.path)
		defer db.Close()
		db.Exec(`INSERT INTO alert_log (ts, target_name, status) VALUES (?, 't', 'sent')`, old)
	}
	e.state("CRIT") // work, so the pass is not skipped
	e.once()        // first pass: prunes (lastPrune was zero)
	seed()
	e.clk.Add(time.Hour)
	e.state("OK")
	e.once() // inside 24 h: no prune
	if e.q(`SELECT count(*) FROM alert_log WHERE ts = ?`, old) != 1 {
		t.Fatal("pruned twice inside a day")
	}
	e.clk.Add(24 * time.Hour)
	e.state("CRIT")
	e.once()
	if e.q(`SELECT count(*) FROM alert_log WHERE ts = ?`, old) != 0 {
		t.Fatal("not pruned after a day")
	}
}

func TestTestSendThroughTheSendersAndRateLimit(t *testing.T) {
	e := newDispEnv(t)
	tg := e.webhook("t", nil)
	var seen []byte
	e.wh.fn = func(_ int, _ string, body []byte, _ context.Context) Result {
		seen = body
		return Result{Outcome: OutcomeSent, Code: "HTTP 204", Duration: 140 * time.Millisecond}
	}
	recs, err := e.d.TestSend(context.Background(), tg)
	if err != nil || len(recs) != 1 || recs[0].Result.Status != store.AlertLogSent || recs[0].Result.Code != "HTTP 204" {
		t.Fatalf("%+v %v", recs, err)
	}
	var p TestPayload
	if err := json.Unmarshal(seen, &p); err != nil || p.Kind != KindTest || p.Target != "t" || p.TS != FormatTime(t0) || p.URL == nil || *p.URL != "https://cf.example" {
		t.Fatalf("%+v %v %s", p, err, seen)
	}
	// Mutation 40: the rate limit. A second test inside 10 s is refused; after 10 s it is allowed.
	if _, err := e.d.TestSend(context.Background(), tg); !errors.Is(err, ErrTestRateLimited) {
		t.Fatalf("%v", err)
	}
	e.clk.Add(11 * time.Second)
	if _, err := e.d.TestSend(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	// Failures come back as records too, with our text.
	e.clk.Add(time.Minute)
	e.wh.fn = func(int, string, []byte, context.Context) Result {
		return Result{Outcome: OutcomePermanent, Code: "blocked", Text: "address 127.0.0.1 is loopback"}
	}
	recs, _ = e.d.TestSend(context.Background(), tg)
	if recs[0].Result.Status != store.AlertLogFailed || recs[0].Result.Code != "blocked" {
		t.Fatalf("%+v", recs)
	}
}

func TestTestSendEmailOneRecordPerRecipient(t *testing.T) {
	e := newDispEnv(t)
	srv := startSMTPServer(t, testsmtp.Options{RcptReplies: map[string]string{"b@x.example": "550 nope"}})
	e.useSMTP(srv)
	tg := e.email("mail", "a@x.example", "b@x.example")
	recs, err := e.d.TestSend(context.Background(), tg)
	if err != nil || len(recs) != 2 || recs[0].Result.Status != store.AlertLogSent || recs[1].Result.Status != store.AlertLogFailed || recs[1].Recipient != "b@x.example" {
		t.Fatalf("%+v %v", recs, err)
	}
	if ms := srv.Messages(); len(ms) != 1 || !strings.Contains(ms[0].Data, "[ClamFleet] test") {
		t.Fatalf("%+v", ms)
	}
}

func protoEvent(at time.Time) proto.Event {
	return proto.Event{Schema: 1, Host: "a", TS: at, Path: "/p", Signature: "S", Source: "scan"}
}
