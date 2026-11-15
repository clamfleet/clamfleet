// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

func TestEncodePath(t *testing.T) {
	long := strings.Repeat("a", 5000)
	for _, c := range []struct{ name, in, want string }{
		{"plain", "/srv/upload/a.zip", "/srv/upload/a.zip"},
		{"backslash doubled", `/a\b`, `/a\\b`},
		{"raw byte 0xff", "/a\xffb", `/a\xffb`},
		{"literal text backslash-x-ff is not the raw byte", `/a\xffb`, `/a\\xffb`},
		{"valid UTF-8 kept", "/srv/ünï/日本", "/srv/ünï/日本"},
		{"truncated UTF-8 sequence", "/a\xe2\x82", `/a\xe2\x82`},
		{"newline kept as is", "/a\nb", "/a\nb"},
		{"stream", "stream", "stream"},
		{"fd", "fd[5]", "fd[5]"},
		{"literal U+FFFD kept (3 bytes, valid)", "/a�b", "/a�b"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := EncodePath(c.in); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
	t.Run("raw and literal stay distinct", func(t *testing.T) {
		if EncodePath("\xff") == EncodePath(`\xff`) {
			t.Fatal("two different file names became one string")
		}
	})
	t.Run("exactly 4096 is kept", func(t *testing.T) {
		if got := EncodePath(long[:4096]); got != long[:4096] {
			t.Fatalf("len %d", len(got))
		}
	})
	t.Run("5000 bytes are cut to 4093 plus dots", func(t *testing.T) {
		got := EncodePath(long)
		if len(got) != 4096 || !strings.HasSuffix(got, "...") || strings.Trim(got[:4093], "a") != "" {
			t.Fatalf("len=%d tail=%q", len(got), got[len(got)-5:])
		}
	})
	t.Run("never cut inside an escape or a rune", func(t *testing.T) {
		// 4092 'a' then a backslash: the encoded unit is 2 bytes, which would end at 4094.
		for _, tail := range []string{`\`, "\xff", "é", "日", `\\`} {
			in := strings.Repeat("a", 4090) + strings.Repeat(tail, 20)
			got := EncodePath(in)
			if len(got) > 4096 || !strings.HasSuffix(got, "...") || !utf8.ValidString(got) {
				t.Fatalf("tail %q: len=%d valid=%v", tail, len(got), utf8.ValidString(got))
			}
			body := strings.TrimSuffix(got, "...")
			// A cut in the middle of "\xNN" or "\\" would leave a lone backslash or a
			// partial escape at the end of the body.
			if m := regexp.MustCompile(`(\\\\|\\x[0-9a-f]{2}|[^\\])$`).FindString(body); m == "" && body != "" {
				t.Fatalf("tail %q: body ends inside an escape: %q", tail, body[len(body)-4:])
			}
		}
	})
}

func TestSanitizeSignature(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"Win.Test.EICAR_HDB-1", "Win.Test.EICAR_HDB-1"},
		{"", "unknown"},
		{"a\x01b\x7fc\xffd", "a?b?c?d"},
		{"Wïn", "W??n"},
		{strings.Repeat("x", 300), strings.Repeat("x", 256)},
	} {
		if got := SanitizeSignature(c.in); got != c.want {
			t.Errorf("SanitizeSignature(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildEventUsesClockAndFreshIDs(t *testing.T) {
	now := time.Date(2031, 3, 4, 12, 0, 0, 999_000_000, time.UTC)
	a := BuildEvent(now, "app01", randomID(), "/srv/x", "Sig")
	b := BuildEvent(now, "app01", randomID(), "/srv/x", "Sig")
	if !isLowerHex32(*a.ID) || *a.ID == *b.ID {
		t.Fatalf("ids %q %q", *a.ID, *b.ID)
	}
	if !a.TS.Equal(time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC)) || a.Source != "clamd" || a.Schema != 1 || a.Host != "app01" {
		t.Fatalf("%+v", a)
	}
}

// eventFixture is a spool plus a config file for RunEvent, with recording seams.
type eventFixture struct {
	*testSpool
	Cfg    string
	Token  string
	Reads  []string
	Deps   EventDeps
	Stderr string
}

func newEventFixture(t *testing.T) *eventFixture {
	t.Helper()
	ts := newTestSpool(t)
	ts.OpenRun(t).Close()
	root := filepath.Dir(ts.Dir)
	f := &eventFixture{testSpool: ts, Cfg: filepath.Join(root, "agent.yaml"), Token: filepath.Join(root, "token")}
	if err := os.WriteFile(f.Token, []byte("secret-token"), 0o000); err != nil {
		t.Fatal(err)
	}
	yml := fmt.Sprintf("token_file: %s\nserver: https://clamfleet.example\nspool: {dir: %s, max_mb: 1}\n", f.Token, ts.Dir)
	if err := os.WriteFile(f.Cfg, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	f.Deps = EventDeps{
		Getenv: func(k string) (string, bool) {
			return map[string]string{EnvVirusFilename: "/srv/e2e/eicar.com", EnvVirusName: "Win.Test.EICAR_HDB-1"}[k], k == EnvVirusFilename || k == EnvVirusName
		},
		Now:        ts.Clock.Now,
		Hostname:   func() (string, error) { return "app01", nil },
		ConfigPath: f.Cfg,
		ReadFile:   func(p string) ([]byte, error) { f.Reads = append(f.Reads, p); return os.ReadFile(p) },
		FS:         ts.FS,
		After:      func(time.Duration) <-chan time.Time { return nil },
		Sleep:      ts.Clock.Advance,
	}
	return f
}

func TestRunEventSpoolsAValidEvent(t *testing.T) {
	f := newEventFixture(t)
	res := RunEvent(f.Deps)
	if res.Exit != EventSpooled {
		t.Fatalf("%+v", res)
	}
	names := f.names(t, dirEvents)
	if len(names) != 1 {
		t.Fatalf("events = %v", names)
	}
	raw, _ := os.ReadFile(filepath.Join(f.Dir, dirEvents, names[0]))
	m := itemName.FindStringSubmatch(names[0])
	ev, err := ValidateEvent(raw, m[2], f.Clock.Now(), 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Path != "/srv/e2e/eicar.com" || ev.Signature != "Win.Test.EICAR_HDB-1" || ev.Host != "app01" {
		t.Fatalf("%+v", ev)
	}
}

// The command cannot touch the token: it reads only the config, and the only
// other files it opens are under the spool. EventDeps has no Sender or dialer.
func TestRunEventNeverOpensTheToken(t *testing.T) {
	f := newEventFixture(t)
	if res := RunEvent(f.Deps); res.Exit != EventSpooled {
		t.Fatalf("%+v", res)
	}
	if len(f.Reads) != 1 || f.Reads[0] != f.Cfg {
		t.Fatalf("files read through the config seam: %v", f.Reads)
	}
	for _, c := range f.FS.Calls() {
		if strings.Contains(c, "token") {
			t.Fatalf("the token was touched: %s", c)
		}
	}
}

func TestRunEventUsageErrorWithoutVariables(t *testing.T) {
	f := newEventFixture(t)
	f.Deps.Getenv = func(string) (string, bool) { return "", false }
	if res := RunEvent(f.Deps); res.Exit != EventUsage {
		t.Fatalf("%+v", res)
	}
	if got := f.names(t, dirEvents); len(got) != 0 {
		t.Fatalf("spooled without variables: %v", got)
	}
}

// An unreadable config means nothing is spooled and the line names the file.
// No fallback: falling back to the default directory would write where `run`
// does not read, and the detection would vanish silently. The proof is that the
// spool is never even opened.
func TestRunEventUnreadableConfigDoesNotFallBack(t *testing.T) {
	f := newEventFixture(t)
	f.Deps.ReadFile = func(string) ([]byte, error) {
		return nil, &os.PathError{Op: "open", Path: f.Cfg, Err: syscall.EACCES}
	}
	f.FS.reset()
	res := RunEvent(f.Deps)
	if res.Exit != EventFailed || !strings.Contains(res.Message, "cannot read config "+f.Cfg+": permission denied") {
		t.Fatalf("%+v", res)
	}
	for _, c := range f.FS.Calls() {
		if c == "OpenRoot" {
			t.Fatal("a spool was opened after the config failed")
		}
	}
	if got := f.names(t, dirEvents); len(got) != 0 {
		t.Fatalf("spooled: %v", got)
	}
}

func TestRunEventFailuresAreFailuresWithOneLineAndNoPath(t *testing.T) {
	for name, setup := range map[string]func(f *eventFixture){
		"disk full": func(f *eventFixture) { f.FS.fail["Write"] = syscall.ENOSPC },
		"fsync":     func(f *eventFixture) { f.FS.fail["Sync"] = syscall.EIO },
		"spool full": func(f *eventFixture) {
			os.WriteFile(filepath.Join(f.Dir, fileUsage), []byte(`{"total":1048576,"base":0,"at":1}`), 0o660)
		},
		"sticky bit missing": func(f *eventFixture) { os.Chmod(filepath.Join(f.Dir, dirEvents), 0o770) },
		"corrupt config":     func(f *eventFixture) { os.WriteFile(f.Cfg, []byte("spool: [oops"), 0o644) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newEventFixture(t)
			setup(f)
			res := RunEvent(f.Deps)
			if res.Exit != EventFailed {
				t.Fatalf("exit %d: %+v", res.Exit, res)
			}
			if strings.Contains(res.Message, "eicar") || strings.Contains(res.Message, "/srv/e2e") {
				t.Fatalf("the path is in the message: %q", res.Message)
			}
			if got := f.names(t, dirEvents); len(got) != 0 {
				t.Fatalf("a file is left in events: %v", got)
			}
		})
	}
}

func TestRunEventDirectorySyncFailureIsReported(t *testing.T) {
	f := newEventFixture(t)
	f.FS.fail["SyncDir"] = syscall.EIO
	res := RunEvent(f.Deps)
	if res.Exit != EventFailed || !strings.HasPrefix(res.Message, "spooled; directory sync failed") {
		t.Fatalf("%+v", res)
	}
	if got := f.names(t, dirEvents); len(got) != 1 {
		t.Fatalf("the item must stay: %v", got)
	}
}

// The watchdog: a stalled disk makes the command give up at 10 s (on the
// injected timer), with one line, instead of leaving clamd waiting for the
// network or for us forever.
func TestRunEventWatchdog(t *testing.T) {
	f := newEventFixture(t)
	release := make(chan struct{})
	f.Deps.ReadFile = func(p string) ([]byte, error) { <-release; return os.ReadFile(p) }
	fired := make(chan time.Time, 1)
	fired <- time.Time{}
	f.Deps.After = func(d time.Duration) <-chan time.Time {
		if d != 10*time.Second {
			t.Errorf("watchdog = %v, want 10s", d)
		}
		return fired
	}
	res := RunEvent(f.Deps)
	close(release)
	if res.Exit != EventFailed || !strings.Contains(res.Message, "timed out") {
		t.Fatalf("%+v", res)
	}
}

// A slow fsync is waited for, once: no extra calls.
func TestRunEventSlowFsyncIsNotRetried(t *testing.T) {
	f := newEventFixture(t)
	f.FS.syncDelay = 200 * time.Millisecond
	f.FS.reset()
	start := time.Now()
	res := RunEvent(f.Deps)
	if res.Exit != EventSpooled || time.Since(start) < 200*time.Millisecond {
		t.Fatalf("%+v after %v", res, time.Since(start))
	}
	n := 0
	for _, c := range f.FS.Calls() {
		if c == "Sync(tmp)" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("file Sync called %d times", n)
	}
}

func TestEventItemIsJSONWithoutPathInName(t *testing.T) {
	f := newEventFixture(t)
	f.Deps.Getenv = func(k string) (string, bool) {
		return map[string]string{EnvVirusFilename: "/srv/MARKER-PATH/a\\b", EnvVirusName: "S"}[k], true
	}
	if res := RunEvent(f.Deps); res.Exit != EventSpooled {
		t.Fatalf("%+v", res)
	}
	n := f.names(t, dirEvents)[0]
	if strings.Contains(n, "MARKER") {
		t.Fatalf("the path is in the file name: %s", n)
	}
	raw, _ := os.ReadFile(filepath.Join(f.Dir, dirEvents, n))
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m["path"] != `/srv/MARKER-PATH/a\\b` {
		t.Fatalf("%v %s", err, raw)
	}
	_ = errors.New
}
