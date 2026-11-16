// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// freshclam.go: finds when freshclam last updated successfully and last failed.
//
// Responsibilities: parse freshclam output (journal text or log file) into
// runs, merge the runs of both sources, pick the newest OK and newest failed
// run, clean the error message (no credentials, bounded length), and fall back
// to the daily database mtime when no run is found.
// Dependencies: journalctl through the injected ExecFunc, the log file, the
// proto package. Log timestamps carry no zone, so the host zone is injected.

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

const (
	// freshclamTailBytes is how much of the log file is read: the end of it,
	// because the newest runs are what matters and the file can be large.
	freshclamTailBytes = 1 << 20
	// freshclamJournalLines bounds the journalctl output (about 15 lines per run).
	freshclamJournalLines = "1000"
	// maxErrMsg bounds last_error_msg in the report.
	maxErrMsg = 512

	runStartMarker = "ClamAV update process started at "
	// freshclam prints ctime(3) time: "Thu Nov 12 10:01:08 2026". The log has
	// NO time zone, so it is read in the host's local zone.
	ctimeLayout = "Mon Jan _2 15:04:05 2006"
)

// FreshclamRun is one update run found in a freshclam log or journal.
type FreshclamRun struct {
	// Start is when the run began, UTC.
	Start time.Time
	// OK: the run reported "is up-to-date" or "updated (version" and no error.
	OK bool
	// Failed: the run printed an ERROR line. ErrMsg is its cleaned first one.
	Failed bool
	ErrMsg string
}

var (
	// Credentials in URLs, e.g. a proxy "http://user:pass@proxy:3128". Greedy on
	// purpose: a password may contain a raw "@", so everything up to the LAST "@"
	// of the authority (before the first "/") is removed.
	urlCredsRE = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/\s]*@`)
	// freshclam sometimes interleaves two log lines, leaving "<ctime> -> " and
	// "ERROR:" fragments inside a message; strip them for readability.
	ctimeArrowRE = regexp.MustCompile(`[A-Z][a-z]{2} [A-Z][a-z]{2} [ 0-9]\d \d\d:\d\d:\d\d \d{4} -> `)
	spacesRE     = regexp.MustCompile(`\s+`)
)

// cleanErrorLine reduces a log line containing "ERROR:" to the message: the
// text after the first marker, without timestamps, repeated markers or URL
// credentials, at most maxErrMsg bytes.
func cleanErrorLine(line string) string {
	_, msg, _ := strings.Cut(line, "ERROR:")
	msg = ctimeArrowRE.ReplaceAllString(msg, "")
	msg = strings.ReplaceAll(msg, "ERROR:", "")
	msg = urlCredsRE.ReplaceAllString(msg, "$1")
	msg = spacesRE.ReplaceAllString(strings.TrimSpace(msg), " ")
	return truncate(msg, maxErrMsg)
}

// ParseFreshclamLog splits freshclam output (log file or journal text) into
// runs, oldest first. A run starts at a "ClamAV update process started at"
// line (assumption A10, confirmed: present with LogTime yes and no, and in
// the journal). Text before the first such line is discarded: it is either
// the header of the file or the cut-off start of a run when only the tail
// of a large file was read. Runs with no outcome line (still running, or cut)
// are returned with OK and Failed both false. loc is the zone of the ctime
// strings (the host's local zone).
func ParseFreshclamLog(data []byte, loc *time.Location) []FreshclamRun {
	var runs []FreshclamRun
	cur := -1
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, runStartMarker); i >= 0 {
			ts, err := time.ParseInLocation(ctimeLayout, strings.TrimSpace(line[i+len(runStartMarker):]), loc)
			if err != nil {
				cur = -1 // unparseable start: ignore this run rather than guess its time
				continue
			}
			runs = append(runs, FreshclamRun{Start: proto.UTC(ts)})
			cur = len(runs) - 1
			continue
		}
		if cur < 0 {
			continue
		}
		r := &runs[cur]
		switch {
		case strings.Contains(line, "ERROR:"):
			if !r.Failed {
				r.Failed, r.ErrMsg = true, cleanErrorLine(line)
			}
		case strings.Contains(line, "is up-to-date"), strings.Contains(line, "updated (version"):
			r.OK = true
		}
	}
	// A run with an error is failed even if another database updated fine.
	for i := range runs {
		if runs[i].Failed {
			runs[i].OK = false
		}
	}
	return runs
}

// summarizeRuns picks the newest ok run and the newest failed run.
func summarizeRuns(runs []FreshclamRun) (fc proto.Freshclam, complete bool) {
	for _, r := range runs {
		switch {
		case r.OK:
			t := r.Start
			if fc.LastOK == nil || t.After(*fc.LastOK) {
				fc.LastOK = &t
			}
		case r.Failed:
			t, m := r.Start, r.ErrMsg
			if fc.LastError == nil || t.After(*fc.LastError) {
				fc.LastError, fc.LastErrorMsg = &t, &m
			}
		}
	}
	return fc, fc.LastOK != nil || fc.LastError != nil
}

// hasCompleteRun reports whether runs holds an ok or a failed run, the two
// kinds summarizeRuns uses. A run that is neither (cut off, no verdict) says
// nothing about the host, so it does not make its source count.
func hasCompleteRun(runs []FreshclamRun) bool {
	for _, r := range runs {
		if r.OK || r.Failed {
			return true
		}
	}
	return false
}

// readTail returns the last max bytes of a file. When it had to cut, the
// first (partial) line is dropped.
func readTail(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	var off int64
	if st.Size() > max {
		off = st.Size() - max
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return nil, err
	}
	if off > 0 {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return b, nil
}

// runsFromLogFile reads runs from the log, and from "<log>.1" when the
// current file has no run yet (it was just rotated; Debian keeps .1
// uncompressed through delaycompress, assumption A11, from the logrotate
// config; not rotated live).
func runsFromLogFile(path string, loc *time.Location) ([]FreshclamRun, error) {
	b, err := readTail(path, freshclamTailBytes)
	if err != nil {
		return nil, err
	}
	runs := ParseFreshclamLog(b, loc)
	if _, ok := summarizeRuns(runs); ok {
		return runs, nil
	}
	if prev, perr := readTail(path+".1", freshclamTailBytes); perr == nil {
		runs = append(ParseFreshclamLog(prev, loc), runs...)
	}
	return runs, nil
}

// runsFromJournal reads the freshclam unit's journal entries (M1 Q8:
// the first source tried, because the log file is often unreadable by the
// agent user). The agent user must be in group systemd-journal; without it
// journalctl exits 0 with no output, which is treated as "no runs", not as a
// failure.
func runsFromJournal(ctx context.Context, exec ExecFunc, unit string, loc *time.Location) ([]FreshclamRun, error) {
	out, err := exec(ctx, "journalctl", "-u", unit, "-o", "cat", "--no-pager", "-q", "-n", freshclamJournalLines)
	if err != nil {
		return nil, err
	}
	return ParseFreshclamLog(out, loc), nil
}

// collectFreshclam finds the last successful and failed update. Runs are
// read from the systemd journal of the freshclam unit AND from the log file,
// then summarized once over all of them: the newest run of each kind wins,
// whichever source it came from. (Taking the first source with any run would
// let an old OK in the journal hide a newer failure in the log file.) Only
// when neither source has a run does it fall back to the modification time of
// the daily database, which can never show a failed update, so that case is
// reported as a Problem.
//
// The result's Source names the sources that supplied at least one complete
// run (ok or failed); see proto.Freshclam.
func (c *Collector) collectFreshclam(ctx context.Context) (proto.Freshclam, []Problem) {
	var why []string
	var all []FreshclamRun
	fromJournal, fromLog := false, false
	if unit := c.Cfg.Units.Freshclam; unit != "" {
		runs, err := runsFromJournal(ctx, c.Exec, unit, c.Loc)
		if err != nil {
			why = append(why, "journal: "+err.Error())
		}
		fromJournal = hasCompleteRun(runs)
		all = append(all, runs...)
	}
	runs, err := runsFromLogFile(c.Cfg.FreshclamLog, c.Loc)
	if err != nil {
		why = append(why, "log file: "+err.Error())
	}
	fromLog = hasCompleteRun(runs)
	all = append(all, runs...)
	if fc, ok := summarizeRuns(all); ok {
		// ok implies at least one of the two flags is set.
		src := proto.SourceJournal
		switch {
		case fromJournal && fromLog:
			src = proto.SourceJournalLog
		case fromLog:
			src = proto.SourceLog
		}
		fc.Source = &src
		return fc, nil
	}
	if len(why) == 0 {
		why = append(why, "no update runs found")
	}
	problem := Problem{"freshclam", fmt.Errorf("%s; using database file times, failed updates will not be visible", strings.Join(why, "; "))}
	if t, ok := dailyMTime(c.Cfg.DBDir); ok {
		t = proto.UTC(t)
		src := proto.SourceMtime
		return proto.Freshclam{LastOK: &t, Source: &src}, []Problem{problem}
	}
	return proto.Freshclam{}, []Problem{problem, {"freshclam", errors.New("daily database not found, nothing to fall back on")}}
}
