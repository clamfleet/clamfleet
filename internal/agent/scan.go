// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// scan.go: `clamfleet-agent scan`, the scheduled-scan wrapper (spec 6.4,
// milestone 6 plan 4.10). It runs `clamdscan --multiscan` on scan.paths and
// writes last_scan.json in the proto.LastScan shape the report already carries.
//
// Rules, each of which a test pins:
//   - It never starts clamd: it asks systemd whether the clamd unit is active
//     FIRST, and when it is not, it exits 2 without writing a summary and without
//     touching the socket (socket activation would otherwise start clamd). The M3
//     rule scan_missed then fires after scan_warn_hours.
//   - Output is streamed and bounded: clamdscan's stdout is read line by line with
//     constant memory whatever the number of files; stderr is kept to 4 KiB.
//   - No path is ever logged: a scanned path is personal data. Only counts, and the
//     class of a known failure ("clamd not reachable"), never raw stderr, are logged.
//   - Detections reach the server through VirusEvent, not through this wrapper.
//   - A timeout (scan.timeout) stops the whole process group and writes a summary
//     with exit 2 and the counts so far. An interrupted scan (SIGTERM, ctx
//     cancelled) is not a result: nothing is written.
//   - The summary is written atomically: temp file, fsync, rename, directory fsync.
//
// `scanned` is always 0, meaning "not reported by clamdscan": --multiscan prints one
// OK line per clean PATH ARGUMENT, not one per file inside a directory, and its
// summary has no file count (recorded fixtures, ClamAV 1.4 on Debian 13). Counting
// the OK lines would put the number of scan paths in a field that says files.
package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// Limits of the output reader.
const (
	// scanMaxLine is the longest stdout line that is examined. A longer line is
	// counted once, as an error, and skipped to its newline.
	scanMaxLine = 64 << 10
	// scanStderrMax is how much of stderr is kept to classify a failure.
	scanStderrMax = 4 << 10
	// scanKillGrace is how long a stopped process group has between SIGTERM and SIGKILL.
	scanKillGrace = 10 * time.Second
)

// Exit codes of `scan` (clamdscan's own convention): clean, infected, error.
const (
	ScanClean    = 0
	ScanInfected = 1
	ScanError    = 2
)

// ErrScanClamdInactive: the clamd unit is not active, so nothing was scanned
// and nothing was written.
var ErrScanClamdInactive = errors.New("the clamd unit is not active: nothing was scanned (the scan never starts clamd)")

// ErrScanInterrupted: the scan was stopped from outside (SIGTERM); not a result.
var ErrScanInterrupted = errors.New("the scan was interrupted: no summary was written")

// ScanCounts is what the stream parser keeps: counts only, never a path.
type ScanCounts struct {
	OK       int64
	Infected int64
	Errors   int64
	// SummaryInfected and SummaryErrors are clamdscan's own totals, -1 when absent.
	SummaryInfected, SummaryErrors int64
}

// ParseScanStream reads clamdscan's stdout line by line in constant memory.
// Per-file lines end in " OK", " FOUND" or " ERROR"; the summary has
// "Infected files: N" and "Total errors: N". A line longer than 64 KiB counts as
// one error and is skipped to its newline. Only counts are kept.
func ParseScanStream(r io.Reader) (ScanCounts, error) {
	c := ScanCounts{SummaryInfected: -1, SummaryErrors: -1}
	br := bufio.NewReaderSize(r, scanMaxLine)
	for {
		line, err := br.ReadSlice('\n')
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			c.Errors++
			for errors.Is(err, bufio.ErrBufferFull) { // skip the rest of the line
				_, err = br.ReadSlice('\n')
			}
		case err == nil || (errors.Is(err, io.EOF) && len(line) > 0):
			c.count(bytes.TrimRight(line, "\r\n"))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return c, nil
			}
			return c, err
		}
	}
}

func (c *ScanCounts) count(line []byte) {
	switch {
	case bytes.HasSuffix(line, []byte(" FOUND")):
		c.Infected++
	case bytes.HasSuffix(line, []byte(" ERROR")):
		c.Errors++
	case bytes.HasSuffix(line, []byte(": OK")):
		c.OK++
	case bytes.HasPrefix(line, []byte("Infected files: ")):
		if n, err := strconv.ParseInt(string(bytes.TrimSpace(line[len("Infected files: "):])), 10, 64); err == nil {
			c.SummaryInfected = n
		}
	case bytes.HasPrefix(line, []byte("Total errors: ")):
		if n, err := strconv.ParseInt(string(bytes.TrimSpace(line[len("Total errors: "):])), 10, 64); err == nil {
			c.SummaryErrors = n
		}
	}
}

// stderrClass names a known clamdscan failure without quoting it: raw stderr can
// hold paths. Order matters: the first match wins.
func stderrClass(b []byte) string {
	s := strings.ToLower(string(b))
	switch {
	case strings.TrimSpace(s) == "":
		return ""
	case strings.Contains(s, "could not connect to clamd") || strings.Contains(s, "can't connect to clamd"):
		return "clamd not reachable"
	case strings.Contains(s, "config file") || strings.Contains(s, "can't parse") || strings.Contains(s, "can't open/parse"):
		return "config file problem"
	case strings.Contains(s, "permission denied") || strings.Contains(s, "access denied"):
		return "permission denied"
	}
	return "unclassified"
}

// Scanner runs one scan. Every outside effect is a field, so tests need no
// clamd, systemd or wall clock.
type Scanner struct {
	Cfg Config
	// Bin is the clamdscan binary; "" means "clamdscan" on PATH.
	Bin string
	// Exec runs systemctl for the unit check.
	Exec ExecFunc
	// Now is the clock for the summary's times.
	Now func() time.Time
	// After returns a channel that fires after d: the scan timeout. Injected so a
	// test does not wait; nil means time.After.
	After func(d time.Duration) <-chan time.Time
	Log   *slog.Logger
	// beforeRename is a test hook: called after the temp file is synced and before
	// it is renamed, to prove a failure there leaves the old summary intact.
	beforeRename func() error
}

// unitActive reports whether the clamd unit is active. An empty unit name means
// clamd is not managed by systemd: no check (the same rule as the collector).
func (s *Scanner) unitActive(ctx context.Context) (bool, error) {
	unit := s.Cfg.Units.Clamd
	if unit == "" {
		return true, nil
	}
	ctx, cancel := context.WithTimeout(ctx, systemctlTimeout)
	defer cancel()
	out, err := s.Exec(ctx, "systemctl", "show", "--property=LoadState,ActiveState", "--", unit)
	if err != nil {
		return false, fmt.Errorf("cannot ask systemd about the clamd unit: %w", err)
	}
	state, ok := ParseSystemctlShow(out)
	if !ok {
		return false, errors.New("unexpected systemctl output for the clamd unit")
	}
	return state == "active", nil
}

// Run performs one scan and returns the exit code of `scan`: 0 clean, 1
// infected, 2 error. A non-nil error with code 2 means a refusal or failure; the
// summary file is written only when a scan ran to a result (including a timeout).
func (s *Scanner) Run(ctx context.Context) (int, error) {
	if len(s.Cfg.Scan.Paths) == 0 {
		return ScanError, errors.New("scan.paths is empty: nothing to scan")
	}
	// Rule: never touch clamd while its unit is not active (socket activation).
	active, err := s.unitActive(ctx)
	if err != nil {
		return ScanError, err
	}
	if !active {
		return ScanError, ErrScanClamdInactive
	}

	bin := s.Bin
	if bin == "" {
		bin = "clamdscan"
	}
	// No --fdpass: clamd reads the files as its own user, and so would a pass of
	// descriptors the agent user cannot open either (docs/detections.md).
	args := append([]string{"--config-file=" + s.Cfg.ClamdConf, "--multiscan", "--"}, s.Cfg.Scan.Paths...)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	// Its own process group, so a timeout can stop everything it started.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return ScanError, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return ScanError, err
	}
	started := s.Now().UTC()
	if err := cmd.Start(); err != nil {
		return ScanError, fmt.Errorf("cannot run %s: %w", filepath.Base(bin), err)
	}

	var errBuf bytes.Buffer
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		io.Copy(&errBuf, io.LimitReader(stderr, scanStderrMax))
		io.Copy(io.Discard, stderr) // keep draining: a full pipe would block the child
	}()
	type parsed struct {
		c   ScanCounts
		err error
	}
	parseDone := make(chan parsed, 1)
	go func() {
		c, err := ParseScanStream(stdout)
		io.Copy(io.Discard, stdout)
		parseDone <- parsed{c, err}
	}()
	after := s.After
	if after == nil {
		after = time.After
	}
	timedOut := false
	var res parsed
	select {
	case res = <-parseDone:
	case <-after(s.Cfg.Scan.Timeout):
		timedOut = true
		cancelKill := stopGroup(cmd)
		res = <-parseDone
		cancelKill()
	case <-ctx.Done():
		cancelKill := stopGroup(cmd)
		<-parseDone
		<-stderrDone
		cmd.Wait()
		cancelKill()
		return ScanError, ErrScanInterrupted
	}
	<-stderrDone
	waitErr := cmd.Wait()
	exit := ScanClean
	var ee *exec.ExitError
	switch {
	case waitErr == nil:
	case errors.As(waitErr, &ee):
		exit = ee.ExitCode()
	default:
		exit = ScanError
	}
	if res.err != nil {
		exit = ScanError
	}

	c := res.c
	sum := proto.LastScan{Started: started, Finished: s.Now().UTC(), Exit: exit}
	sum.Infected = max(c.Infected, c.SummaryInfected)
	sum.Errors = max(c.Errors, c.SummaryErrors)
	// Scanned stays 0: "not reported by clamdscan" (see the file comment).
	if timedOut {
		sum.Exit = ScanError
		exit = ScanError
		s.Log.Warn("scan timed out", "timeout", s.Cfg.Scan.Timeout.String(), "infected", sum.Infected, "errors", sum.Errors)
	}
	if class := stderrClass(errBuf.Bytes()); class != "" {
		s.Log.Warn("clamdscan reported a problem", "class", class)
	}
	if err := s.writeSummary(sum); err != nil {
		return ScanError, fmt.Errorf("cannot write the scan summary: %w", err)
	}
	s.Log.Info("scan finished", "exit", sum.Exit, "infected", sum.Infected, "errors", sum.Errors, "timed_out", timedOut)
	if timedOut {
		return ScanError, nil
	}
	return exit, nil
}

// stopGroup sends SIGTERM to the whole process group and SIGKILL after the grace
// period. It returns the function that cancels the SIGKILL once the caller has
// seen the pipes close (the group is gone).
func stopGroup(cmd *exec.Cmd) (cancel func()) {
	pgid := cmd.Process.Pid // Setpgid made the child its own group leader
	syscall.Kill(-pgid, syscall.SIGTERM)
	t := time.AfterFunc(scanKillGrace, func() { syscall.Kill(-pgid, syscall.SIGKILL) })
	return func() { t.Stop() }
}

// writeSummary writes the summary atomically: a temp file in the same directory,
// fsync, rename, directory fsync. One writer, so rename is enough (no link).
// Mode 0640: the agent's own group may read it.
func (s *Scanner) writeSummary(sum proto.LastScan) error {
	path := s.Cfg.Scan.Summary
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".last_scan-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // a no-op after a successful rename
	b, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if s.beforeRename != nil {
		if err := s.beforeRename(); err != nil {
			return err
		}
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
