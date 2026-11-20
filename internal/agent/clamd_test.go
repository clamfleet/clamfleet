// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testTimeout = 300 * time.Millisecond

func TestRecordedRequestsAreZPrefixedAndNulTerminated(t *testing.T) {
	// Guards the fixtures themselves: the agent's own bytes are compared to
	// these in every test below.
	for n, want := range map[string]string{"ping": "zPING\x00", "version": "zVERSION\x00", "stats": "zSTATS\x00"} {
		if got := string(fixture(t, "clamd/"+n+".req")); got != want {
			t.Errorf("%s.req = %q", n, got)
		}
	}
}

func TestCollectClamdRecordedSession(t *testing.T) {
	f := startFakeClamd(t, recordedSession(t))
	got := collectClamd(context.Background(), f.Path, testTimeout)
	if !got.Up || got.Error != nil {
		t.Fatalf("got %+v", got)
	}
	if got.Version == nil || *got.Version != "1.4.3" {
		t.Fatalf("version = %v", got.Version)
	}
	if got.Queue == nil || *got.Queue != 0 {
		t.Fatalf("queue = %v", got.Queue)
	}
	if f.conns.Load() != 3 {
		t.Fatalf("connections = %d, want 3 (one per command)", f.conns.Load())
	}
}

func TestCollectClamdMultiPoolQueueIsSummed(t *testing.T) {
	tbl := recordedSession(t)
	stats := string(fixture(t, "handmade/stats.two-pools.resp.txt"))
	tbl["zSTATS\x00"] = send([]byte(stats + "\x00"))
	f := startFakeClamd(t, tbl)
	got := collectClamd(context.Background(), f.Path, testTimeout)
	if got.Queue == nil || *got.Queue != 7 {
		t.Fatalf("queue = %v, want 7", got.Queue)
	}
}

func TestCollectClamdUnknownCommandReply(t *testing.T) {
	// Every command answered with the recorded "UNKNOWN COMMAND".
	unknown := send(fixture(t, "clamd/unknown.resp"))
	f := startFakeClamd(t, map[string]reply{"zPING\x00": unknown})
	got := collectClamd(context.Background(), f.Path, testTimeout)
	if got.Up || got.Error == nil || !strings.Contains(*got.Error, "unexpected reply") {
		t.Fatalf("got %+v", got)
	}
}

func TestCollectClamdVersionAndStatsFailKeepUp(t *testing.T) {
	unknown := send(fixture(t, "clamd/unknown.resp"))
	tbl := recordedSession(t)
	tbl["zVERSION\x00"] = unknown
	tbl["zSTATS\x00"] = func(c net.Conn) {} // closes without a reply
	f := startFakeClamd(t, tbl)
	got := collectClamd(context.Background(), f.Path, testTimeout)
	if !got.Up || got.Version != nil || got.Queue != nil || got.Error == nil {
		t.Fatalf("got %+v", got)
	}
	if !strings.Contains(*got.Error, "version:") || !strings.Contains(*got.Error, "stats:") {
		t.Fatalf("error = %q", *got.Error)
	}
}

// A clamd with EnableVersionCommand or EnableStatsCommand off answers
// "COMMAND UNAVAILABLE" (Ubuntu 22.04's ClamAV 1.5 package ships both off). The
// agent must stay Up, leave the field null and name the option to change.
func TestCollectClamdDisabledCommands(t *testing.T) {
	unavailable := func(c net.Conn) { _, _ = c.Write([]byte("COMMAND UNAVAILABLE\x00")) }
	cases := []struct {
		name, cmd, want string
		other           string // the other command stays healthy
	}{
		{"version", "zVERSION\x00", "clamd's VERSION command is disabled: set EnableVersionCommand yes in clamd.conf", "zSTATS\x00"},
		{"stats", "zSTATS\x00", "clamd's STATS command is disabled: set EnableStatsCommand yes in clamd.conf", "zVERSION\x00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tbl := recordedSession(t)
			tbl[tc.cmd] = unavailable
			f := startFakeClamd(t, tbl)
			got := collectClamd(context.Background(), f.Path, testTimeout)
			if !got.Up || got.Error == nil || !strings.Contains(*got.Error, tc.want) {
				t.Fatalf("got %+v", got)
			}
			if strings.Contains(*got.Error, "unexpected reply") {
				t.Fatalf("generic error leaked: %q", *got.Error)
			}
			if tc.name == "version" && (got.Version != nil || got.Queue == nil) {
				t.Fatalf("version off must leave the queue: %+v", got)
			}
			if tc.name == "stats" && (got.Queue != nil || got.Version == nil) {
				t.Fatalf("stats off must leave the version: %+v", got)
			}
		})
	}
}

func TestCollectClamdBothCommandsDisabled(t *testing.T) {
	unavailable := func(c net.Conn) { _, _ = c.Write([]byte("COMMAND UNAVAILABLE\x00")) }
	tbl := recordedSession(t)
	tbl["zVERSION\x00"], tbl["zSTATS\x00"] = unavailable, unavailable
	f := startFakeClamd(t, tbl)
	got := collectClamd(context.Background(), f.Path, testTimeout)
	if !got.Up || got.Error == nil || !strings.Contains(*got.Error, "EnableVersionCommand") || !strings.Contains(*got.Error, "EnableStatsCommand") {
		t.Fatalf("got %+v", got)
	}
}

func TestCollectClamdClosesWithoutReply(t *testing.T) {
	f := startFakeClamd(t, map[string]reply{"zPING\x00": func(c net.Conn) {}})
	got := collectClamd(context.Background(), f.Path, testTimeout)
	if got.Up || got.Error == nil || !strings.Contains(*got.Error, "without a reply") {
		t.Fatalf("got %+v", got)
	}
}

func TestCollectClamdStallHitsDeadline(t *testing.T) {
	// The handler holds the connection open (blocked in Read) until the client gives up and closes it.
	f := startFakeClamd(t, map[string]reply{"zPING\x00": func(c net.Conn) { _, _ = c.Read(make([]byte, 1)) }})
	start := time.Now()
	got := collectClamd(context.Background(), f.Path, testTimeout)
	if got.Up || got.Error == nil || !strings.Contains(*got.Error, "timeout") {
		t.Fatalf("got %+v", got)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %s, the deadline did not fire", d)
	}
}

func TestCollectClamdSocketMissing(t *testing.T) {
	got := collectClamd(context.Background(), filepath.Join(shortTempDir(t), "none"), testTimeout)
	if got.Up || got.Version != nil || got.Queue != nil || got.Error == nil || !strings.Contains(*got.Error, "not found") {
		t.Fatalf("got %+v", got)
	}
}

func TestCollectClamdSocketPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: socket permission bits do not apply to root")
	}
	f := startFakeClamd(t, recordedSession(t))
	if err := os.Chmod(f.Path, 0); err != nil {
		t.Fatal(err)
	}
	got := collectClamd(context.Background(), f.Path, testTimeout)
	if got.Up || got.Error == nil || !strings.Contains(*got.Error, "permission denied") {
		t.Fatalf("got %+v", got)
	}
}

func TestClamdReplyOverCapIsRejected(t *testing.T) {
	big := []byte(strings.Repeat("A", clamdMaxReply+10)) // no NUL
	f := startFakeClamd(t, map[string]reply{"zPING\x00": send(big)})
	_, err := clamdCommand(context.Background(), f.Path, "PING", testTimeout)
	if err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("err = %v", err)
	}
}

func TestClamdReplyEOFWithoutNulIsAccepted(t *testing.T) {
	f := startFakeClamd(t, map[string]reply{"zPING\x00": send([]byte("PONG"))})
	got, err := clamdCommand(context.Background(), f.Path, "PING", testTimeout)
	if err != nil || got != "PONG" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestParseVersionAndQueue(t *testing.T) {
	if v, ok := parseVersion("ClamAV 1.4.3/28181/Thu Nov 12 06:27:14 2026"); !ok || v != "1.4.3" {
		t.Fatalf("got %q %v", v, ok)
	}
	if _, ok := parseVersion("UNKNOWN COMMAND"); ok {
		t.Fatal("must reject a non-version reply")
	}
	if _, ok := parseQueue("POOLS: 1\nEND"); ok {
		t.Fatal("no QUEUE line must be reported as unknown, not as 0")
	}
}

func TestParseLocalSocket(t *testing.T) {
	cases := []struct {
		file, want string
		err        error
	}{
		{"debian13/clamd.conf", "/var/run/clamav/clamd.ctl", nil},
		{"handmade/clamd.rhel9.conf", "/run/clamd.scan/clamd.sock", nil},
		{"handmade/clamd.tcp-only.conf", "", ErrNoLocalSocket},
	}
	for _, c := range cases {
		got, err := ParseLocalSocket(fixture(t, c.file))
		if got != c.want || !errors.Is(err, c.err) {
			t.Errorf("%s: got %q, %v", c.file, got, err)
		}
	}
	if _, err := ParseLocalSocket([]byte("LocalSocket\n")); !errors.Is(err, ErrNoLocalSocket) {
		t.Errorf("empty value: %v", err)
	}
}

// Behaviour taken from ClamAV's own parser (common/optparser.c, optparse()),
// not from the manual page: the key and value are split at the first space OR
// tab, keys are case-SENSITIVE (strcmp), the first occurrence of a
// single-valued option wins, a value starting with '"' runs to the LAST '"',
// and '#' inside a value starts an inline comment.
func TestParseLocalSocketMatchesClamdParser(t *testing.T) {
	cases := []struct {
		name, conf, want string
		wantErr          bool // any error
	}{
		{"tab separator", "LocalSocket\t/a/b.sock\n", "/a/b.sock", false},
		{"mixed blanks around", " \t LocalSocket \t /a/b.sock \t\n", "/a/b.sock", false},
		{"keys are case-sensitive: clamd rejects localsocket", "localsocket /x/y.sock\n", "", true},
		{"first occurrence wins", "LocalSocket /first.sock\nLocalSocket /second.sock\n", "/first.sock", false},
		{"quoted value with a space", "LocalSocket \"/a b/c.sock\"\n", "/a b/c.sock", false},
		{"quote inside a quoted value: runs to the LAST quote", "LocalSocket \"/a\"b/c.sock\"\n", "/a\"b/c.sock", false},
		{"inline comment", "LocalSocket /a/b.sock # the socket\n", "/a/b.sock", false},
		{"unterminated quote", "LocalSocket \"/a/b.sock\n", "", true},
		{"no trailing newline", "LocalSocket /a/b.sock", "/a/b.sock", false},
	}
	for _, c := range cases {
		got, err := ParseLocalSocket([]byte(c.conf))
		if got != c.want || (err != nil) != c.wantErr {
			t.Errorf("%s: got %q, %v", c.name, got, err)
		}
	}
}
