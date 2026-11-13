// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// drain.go: sends the spool's items to the server, in two lanes.
//
// Responsibilities:
//   - the EVENT lane: detections younger than a minute first (newest first),
//     so a fresh EICAR test is not stuck behind a backlog after an outage
//     (decision 14), then the backlog oldest first;
//   - the REPORT lane: the newest heartbeat first, then the older ones marked
//     replay=true (history only for the server) and paced at 2 per second;
//   - delivery rules: delete only after a 2xx, quarantine what the server calls
//     invalid (400, 413), keep everything else and back off 1 s doubling to 30 s;
//   - every item is validated and re-encoded before it is sent (validate.go).
//
// The lanes are independent goroutines with their own backoff and request
// timeout, so a slow report ingest never holds up a detection.
//
// Logging: never a path. The first failure of a streak is logged, then only a
// change of class or every 5 minutes, then one recovery line.
// Dependencies: the Queue, validate.go and proto. Time and sleeping are injected.

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Paths of the ingest endpoints, relative to the server URL.
const (
	eventPath = "v1/event"
)

// Lane constants (milestone 5, sections 4.3 and 4.4).
const (
	freshEventAge       = time.Minute
	eventListOldest     = 256
	eventListFresh      = 64
	backoffStart        = time.Second
	backoffMax          = 30 * time.Second
	eventRequestTimeout = 10 * time.Second
	// replayInterval paces replayed heartbeats to 2 per second, so a long
	// outage does not become a burst against a server that just came back.
	replayInterval = 500 * time.Millisecond
	// streakLogEvery re-logs an unchanged failure streak.
	streakLogEvery = 5 * time.Minute
	eaccesLogEvery = time.Minute
	defaultPoll    = time.Second
	recountEvery   = time.Second
	sweepEvery     = time.Minute
)

// itemResult is what happened to one item in a pass.
type itemResult int

const (
	itemSent    itemResult = iota // delivered and deleted
	itemGone                      // removed or quarantined without sending
	itemSkipped                   // not ready or unreadable; try again next pass
	itemFailed                    // the server could not take it; stop the pass and back off
)

// lane is the state of one lane.
type lane struct {
	name       string
	backoff    time.Duration
	until      time.Time
	failing    bool
	class      string
	lastLog    time.Time
	failures   int
	lastNewest string // events: the newest fresh name seen, to reset backoff on a new arrival
	lastSent   string // reports: the newest name delivered
	lastEACCES time.Time
}

// Drainer delivers spooled items.
type Drainer struct {
	Q *Queue
	// Send posts a body to a path (Sender.Send).
	Send func(ctx context.Context, path string, body []byte) ([]byte, error)
	Now  func() time.Time
	Log  *slog.Logger
	// MaxEventAge is spool.max_event_days.
	MaxEventAge time.Duration
	// ReportTimeout is the report lane's request timeout (the sender's 30 s by default).
	ReportTimeout time.Duration
	// Poll is how often an idle lane looks at the spool (default 1 s).
	Poll time.Duration
	// Sleep pauses, returning early when ctx is cancelled (default: a timer).
	Sleep func(ctx context.Context, d time.Duration)

	once        sync.Once
	ev, rp      lane
	wakeEvents  chan struct{}
	wakeReports chan struct{}
	lastRecount time.Time
	lastSweep   time.Time
	// dirty: something was deleted or moved since the last recount. Set by both
	// lanes, read by the event lane.
	dirty atomic.Bool
}

// init fills the defaults once; both lanes call it.
func (d *Drainer) init() { d.once.Do(d.setup) }

func (d *Drainer) setup() {
	if d.wakeEvents == nil {
		d.wakeEvents = make(chan struct{}, 1)
		d.wakeReports = make(chan struct{}, 1)
	}
	d.ev.name, d.rp.name = "event", "report"
	if d.Poll == 0 {
		d.Poll = defaultPoll
	}
	if d.ReportTimeout == 0 {
		d.ReportTimeout = 30 * time.Second
	}
	if d.Sleep == nil {
		d.Sleep = func(ctx context.Context, dur time.Duration) {
			t := time.NewTimer(dur)
			defer t.Stop()
			select {
			case <-ctx.Done():
			case <-t.C:
			}
		}
	}
}

// WakeReports makes the report lane look at the spool now.
func (d *Drainer) WakeReports() {
	d.init()
	select {
	case d.wakeReports <- struct{}{}:
	default:
	}
}

// Run starts both lanes and returns when ctx is cancelled and both have stopped.
func (d *Drainer) Run(ctx context.Context) {
	d.init()
	done := make(chan struct{}, 2)
	go func() { d.loop(ctx, d.wakeEvents, d.EventPass); done <- struct{}{} }()
	go func() { d.loop(ctx, d.wakeReports, d.ReportPass); done <- struct{}{} }()
	<-done
	<-done
}

func (d *Drainer) loop(ctx context.Context, wake chan struct{}, pass func(context.Context) int) {
	for ctx.Err() == nil {
		pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-time.After(d.Poll):
		}
	}
}

// ----- the event lane -----

// EventPass makes one pass over spool/events and returns how many events it
// delivered. It stops at the first server failure and starts a backoff; a
// fresh detection arriving during the backoff cancels it.
func (d *Drainer) EventPass(ctx context.Context) (delivered int) {
	d.init()
	l := &d.ev
	spec := listSpec{oldest: eventListOldest, newest: eventListFresh, freshAge: freshEventAge}
	tried := map[string]bool{}
	for ctx.Err() == nil {
		list, err := d.Q.List(dirEvents, spec)
		if err != nil {
			d.Log.Error("cannot read the spool", "dir", dirEvents, "error", err.Error())
			return delivered
		}
		d.junk(dirEvents, list.Junk)
		// A fresh detection resets the backoff: a flapping server must not delay
		// the newest alert by up to 30 s on top of the outage.
		if len(list.Newest) > 0 && list.Newest[0] > l.lastNewest {
			l.lastNewest = list.Newest[0]
			l.backoff, l.until = 0, time.Time{}
		}
		if d.Now().Before(l.until) {
			break
		}
		var order []string
		for _, n := range list.Newest { // newest first
			if !tried[n] {
				order = append(order, n)
			}
		}
		for _, n := range list.Oldest { // then the backlog, oldest first
			if !tried[n] && !contains(list.Newest, n) {
				order = append(order, n)
			}
		}
		if len(order) == 0 {
			break
		}
		// With a small directory re-listing after every item is cheap and keeps
		// "fresh first" exact; with a big one it is re-listed at most once a second.
		small := list.Total <= readDirChunk
		start := d.Now()
		failed := false
		for _, name := range order {
			tried[name] = true
			switch d.eventItem(ctx, name) {
			case itemSent:
				delivered++
			case itemFailed:
				failed = true
			}
			if failed || ctx.Err() != nil || small || d.Now().Sub(start) >= time.Second {
				break
			}
		}
		if failed {
			break
		}
	}
	d.maintain(delivered > 0)
	return delivered
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// eventItem reads, validates and sends one event.
func (d *Drainer) eventItem(ctx context.Context, name string) itemResult {
	l := &d.ev
	raw, id, ok := d.read(l, dirEvents, name, maxEventFileBytes)
	if !ok {
		return itemSkipped
	}
	m := itemName.FindStringSubmatch(name)
	ev, err := ValidateEvent(raw, m[2], d.Now(), d.MaxEventAge)
	switch {
	case errors.Is(err, errExpired):
		if d.Q.Delete(dirEvents, name, id) == nil {
			d.dirty.Store(true)
			d.Log.Warn("a spooled event expired and was deleted", "signature", ev.Signature, "ts", ev.TS.Format(time.RFC3339), "max_event_days", int(d.MaxEventAge/(24*time.Hour)))
		}
		return itemGone
	case err != nil:
		d.quarantine(dirEvents, name, id, "invalid event: "+err.Error())
		return itemGone
	}
	body, err := json.Marshal(ev)
	if err != nil {
		d.quarantine(dirEvents, name, id, "cannot encode event")
		return itemGone
	}
	return d.send(ctx, l, eventRequestTimeout, eventPath, body, dirEvents, name, id)
}

// ----- the report lane -----

// ReportPass makes one pass over spool/reports: the newest heartbeat first
// (replay=false), then the older ones oldest first with replay=true, paced.
func (d *Drainer) ReportPass(ctx context.Context) (delivered int) {
	d.init()
	l := &d.rp
	tried := map[string]bool{}
	replays := 0
	for ctx.Err() == nil {
		list, err := d.Q.List(dirReports, listSpec{oldest: eventListOldest, newest: 1})
		if err != nil {
			d.Log.Error("cannot read the spool", "dir", dirReports, "error", err.Error())
			return delivered
		}
		d.junk(dirReports, list.Junk)
		if d.Now().Before(l.until) || len(list.Newest) == 0 {
			break
		}
		newest := list.Newest[0]
		var name string
		replay := true
		switch {
		case newest > l.lastSent && !tried[newest]:
			// The only report that is not history: the newest one held that is
			// newer than anything already delivered. Everything else is a replay,
			// including what is left after this one has been sent.
			name, replay = newest, false
		default:
			for _, n := range list.Oldest {
				if !tried[n] {
					name = n
					break
				}
			}
		}
		if name == "" {
			break
		}
		tried[name] = true
		if replay {
			if replays > 0 {
				d.Sleep(ctx, replayInterval)
			}
			replays++
		}
		res := d.reportItem(ctx, name, replay)
		if res == itemSent {
			delivered++
			if name > l.lastSent {
				l.lastSent = name
			}
		}
		if res == itemFailed {
			break
		}
	}
	return delivered
}

func (d *Drainer) reportItem(ctx context.Context, name string, replay bool) itemResult {
	l := &d.rp
	raw, id, ok := d.read(l, dirReports, name, maxReportFileBytes)
	if !ok {
		return itemSkipped
	}
	r, err := ValidateReport(raw)
	if err != nil {
		d.quarantine(dirReports, name, id, "invalid report: "+err.Error())
		return itemGone
	}
	// Set at send time, never stored: only the agent knows whether this report
	// is the newest one it holds right now.
	r.Replay = replay
	body, err := json.Marshal(r)
	if err != nil {
		d.quarantine(dirReports, name, id, "cannot encode report")
		return itemGone
	}
	return d.send(ctx, l, d.ReportTimeout, reportPath, body, dirReports, name, id)
}

// ----- shared -----

// read reads an item and maps the reader's outcomes. ok is false when the item
// must be left for a later pass (or was removed).
func (d *Drainer) read(l *lane, dir, name string, limit int) (raw []byte, id fileID, ok bool) {
	raw, id, err := d.Q.ReadItem(dir, name, limit)
	switch {
	case err == nil:
		return raw, id, true
	case errors.Is(err, errTooLarge):
		d.quarantine(dir, name, id, fmt.Sprintf("item larger than %d bytes", limit))
	case errors.Is(err, errNotOwned):
		d.quarantine(dir, name, id, "item not owned by the agent user")
	case errors.Is(err, fs.ErrPermission):
		// The agent user is not in clamd's group, or the item has a mode we
		// cannot read. Not the item's fault: never quarantined.
		if d.Now().Sub(l.lastEACCES) >= eaccesLogEvery {
			l.lastEACCES = d.Now()
			d.Log.Error("cannot read a spooled item: permission denied (is the agent user in clamd's group?)", "dir", dir)
		}
	case errors.Is(err, errNonRegular):
		d.dirty.Store(true)
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, errSkip), errors.Is(err, errChanged):
	default:
		d.Log.Warn("cannot read a spooled item", "dir", dir, "error", err.Error())
	}
	return nil, fileID{}, false
}

func (d *Drainer) quarantine(dir, name string, id fileID, why string) {
	if err := d.Q.Quarantine(dir, name, id); err != nil {
		if !errors.Is(err, errReplaced) {
			d.Log.Error("cannot quarantine a spooled item", "dir", dir, "error", err.Error())
		}
		return
	}
	d.dirty.Store(true)
	d.Log.Warn("item moved to quarantine: "+why, "dir", dir)
}

// junk moves entries with unexpected names aside.
func (d *Drainer) junk(dir string, names []string) {
	moved := 0
	for _, n := range names {
		if d.Q.QuarantineJunk(dir, n) == nil {
			moved++
		}
	}
	if moved > 0 {
		d.dirty.Store(true)
		d.Log.Warn("entries with unexpected names moved to quarantine", "dir", dir, "count", moved)
	}
}

// send posts body and applies the delivery table: 2xx deletes; 400 and 413
// quarantine (the server says the item is bad, retrying cannot help); anything
// else keeps it and backs the lane off.
func (d *Drainer) send(ctx context.Context, l *lane, timeout time.Duration, path string, body []byte, dir, name string, id fileID) itemResult {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, err := d.Send(rctx, path, body)
	if err == nil {
		d.noteOK(l)
		if derr := d.Q.Delete(dir, name, id); derr != nil && !errors.Is(derr, errReplaced) {
			d.Log.Error("cannot delete a delivered item", "dir", dir, "error", derr.Error())
		}
		d.dirty.Store(true)
		return itemSent
	}
	if ctx.Err() != nil {
		return itemFailed // shutting down: not a failure of the server
	}
	var se *SendError
	if errors.As(err, &se) && se.Class == ClassRejected && (se.Status == http.StatusBadRequest || se.Status == http.StatusRequestEntityTooLarge) {
		d.quarantine(dir, name, id, fmt.Sprintf("the server rejected it (HTTP %d): %s", se.Status, se.Message))
		return itemGone
	}
	d.noteFailure(l, err)
	return itemFailed
}

// noteFailure starts or extends the lane's backoff and logs the streak.
func (d *Drainer) noteFailure(l *lane, err error) {
	switch {
	case l.backoff == 0:
		l.backoff = backoffStart
	case l.backoff < backoffMax:
		l.backoff = min(l.backoff*2, backoffMax)
	}
	now := d.Now()
	l.until = now.Add(l.backoff)
	class, status := "collect", 0
	var se *SendError
	if errors.As(err, &se) {
		class, status = string(se.Class), se.Status
	}
	l.failures++
	if !l.failing || class != l.class || now.Sub(l.lastLog) >= streakLogEvery {
		l.failing, l.class, l.lastLog = true, class, now
		d.Log.Error(l.name+" not sent", "class", class, "status", status, "error", err.Error(), "retry_in", l.backoff.String())
	}
}

func (d *Drainer) noteOK(l *lane) {
	l.backoff, l.until = 0, time.Time{}
	if l.failing {
		d.Log.Info(l.name+"s are being sent again", "failed_attempts", l.failures)
		l.failing, l.failures, l.class = false, 0, ""
	}
}

// maintain runs the spool's housekeeping after an event pass: a recount when
// something changed (at most once a second) and the age-based sweep. Only the
// event lane calls it, so the lastRecount and lastSweep fields need no lock.
func (d *Drainer) maintain(changed bool) {
	now := d.Now()
	if (changed || d.dirty.Load() || d.usageDrifted()) && now.Sub(d.lastRecount) >= recountEvery {
		d.lastRecount = now
		d.dirty.Store(false)
		if err := d.Q.Recount(); err != nil {
			d.Log.Warn("cannot recount the spool", "error", err.Error())
		}
	}
	d.maintainSweep()
}

func (d *Drainer) maintainSweep() {
	now := d.Now()
	if now.Sub(d.lastSweep) < sweepEvery {
		return
	}
	d.lastSweep = now
	if r := d.Q.Sweep(); r.Temp+r.Reports+r.Quarantine > 0 {
		d.Log.Info("spool cleanup", "temp_files", r.Temp, "old_reports", r.Reports, "quarantine", r.Quarantine)
	}
}

// usageDrifted says whether `event` admitted something since the last recount.
func (d *Drainer) usageDrifted() bool {
	total, base, err := d.Q.Usage()
	return err != nil || total != base
}
