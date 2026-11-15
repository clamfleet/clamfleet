// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// event.go: the `clamfleet-agent event` command, run by clamd's VirusEvent.
//
// clamd runs `/bin/sh -c "<VirusEvent>"` as clamd's own user, with an
// environment of exactly PATH, CLAM_VIRUSEVENT_FILENAME and
// CLAM_VIRUSEVENT_VIRUSNAME, and WAITS for it to exit (ClamAV 1.4.3,
// clamd_others.c). So this command:
//   - writes the detection to the spool and nothing else: no network, no
//     token (clamd's user cannot read it), no run lock;
//   - never waits on the server, only on a local write (bounded: a 2 s lock
//     wait and a 10 s watchdog; a write stuck in the kernel cannot be bounded);
//   - reads its config with no fallback: if the config cannot be read, nothing
//     is spooled and it says so, rather than writing into a default directory
//     that `run` does not read and losing the event silently.
//
// Responsibilities: BuildEvent (id, path encoding, signature), RunEvent (the
// whole command with every outside effect injected).
// Dependencies: the spool, proto and config packages; deliberately no Sender.

package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/clamfleet/clamfleet/internal/config"
	"github.com/clamfleet/clamfleet/internal/proto"
)

// ClamAV's environment variables for VirusEvent.
const (
	EnvVirusFilename = "CLAM_VIRUSEVENT_FILENAME"
	EnvVirusName     = "CLAM_VIRUSEVENT_VIRUSNAME"
)

// eventWatchdog bounds the whole command: clamd waits for it.
const eventWatchdog = 10 * time.Second

// EncodePath applies the path convention of decision 16, so two different
// file names never become the same string:
//   - a backslash becomes two;
//   - each byte that is not part of valid UTF-8 becomes \xNN (lowercase hex);
//   - everything else is kept.
//
// After encoding, more than 4096 bytes are cut on a unit boundary (never
// inside an escape or a UTF-8 sequence) to at most 4093 bytes plus "...".
// "stream" (clamd's INSTREAM) and "fd[N]" pass through unchanged.
func EncodePath(raw string) string {
	var b strings.Builder
	var cutAt int // length of b at the last unit boundary that leaves room for "..."
	truncated := false
	const limit = maxEventPathBytes
	for i := 0; i < len(raw); {
		var unit string
		r, w := utf8.DecodeRuneInString(raw[i:])
		switch {
		case r == '\\':
			unit = `\\`
		case r == utf8.RuneError && w == 1:
			unit = fmt.Sprintf(`\x%02x`, raw[i])
		default:
			unit = raw[i : i+w]
		}
		i += w
		if b.Len()+len(unit) <= limit-3 {
			cutAt = b.Len() + len(unit)
		}
		if b.Len()+len(unit) > limit {
			truncated = true
			break
		}
		b.WriteString(unit)
	}
	if !truncated {
		return b.String()
	}
	return b.String()[:cutAt] + "..."
}

// SanitizeSignature keeps printable ASCII (0x20-0x7E), turns every other
// byte into '?', caps the length at 256 bytes, and calls an empty name
// "unknown". The server and the page treat it as untrusted text anyway; this
// keeps what we send within what ValidateEvent accepts.
func SanitizeSignature(s string) string {
	b := []byte(s)
	if len(b) > maxEventSignatureBytes {
		b = b[:maxEventSignatureBytes]
	}
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	if len(b) == 0 {
		return "unknown"
	}
	return string(b)
}

// BuildEvent builds the event for one VirusEvent invocation. now is the
// injected clock; id comes from the spool's id source (32 hex).
func BuildEvent(now time.Time, host, id, filename, virusname string) proto.Event {
	return proto.Event{
		Schema:    proto.SchemaVersion,
		ID:        &id,
		Host:      host,
		TS:        proto.UTC(now),
		Path:      EncodePath(filename),
		Signature: SanitizeSignature(virusname),
		Source:    "clamd",
	}
}

// EventDeps are every outside effect of the event command. There is no
// Sender, dialer or token reader here on purpose: a test pins that the
// command cannot reach the network or the token.
type EventDeps struct {
	// Getenv returns a variable and whether it is set.
	Getenv func(string) (string, bool)
	Now    func() time.Time
	// Hostname is os.Hostname.
	Hostname func() (string, error)
	// ConfigPath is the --config value ("" = the default path).
	ConfigPath string
	// ReadFile reads the config. Every other file the command opens goes
	// through FS, so the recorded opens show what was touched.
	ReadFile func(string) ([]byte, error)
	FS       spoolFS
	// After is time.After; tests inject it to trigger the watchdog.
	After func(time.Duration) <-chan time.Time
	// Sleep is the pause of the lock-wait loop.
	Sleep func(time.Duration)
	// NewID returns 32 hex characters.
	NewID func() string
}

// EventExit is the exit code of the command: 0 spooled durably, 1 not spooled
// (or spooled with an unconfirmed directory sync), 2 usage error.
type EventExit int

const (
	EventSpooled EventExit = 0
	EventFailed  EventExit = 1
	EventUsage   EventExit = 2
)

// EventResult says what happened. Message is the single line for stderr (clamd's
// journal) when Exit != 0; it holds the reason and never the path. Signature
// and SpoolDir are extra fields of that line.
type EventResult struct {
	Exit      EventExit
	Message   string
	Signature string
	SpoolDir  string
}

// RunEvent is the event command without the process: read the variables, load
// the config, admit and publish. It returns within the watchdog.
func RunEvent(d EventDeps) EventResult {
	filename, ok1 := d.Getenv(EnvVirusFilename)
	virusname, ok2 := d.Getenv(EnvVirusName)
	if !ok1 || !ok2 || filename == "" {
		return EventResult{Exit: EventUsage, Message: "event not spooled: " + EnvVirusFilename + " and " + EnvVirusName + " must be set (this command is run by clamd's VirusEvent)"}
	}
	sig := SanitizeSignature(virusname)
	done := make(chan EventResult, 1)
	go func() { done <- spoolEvent(d, filename, virusname) }()
	after := d.After
	if after == nil {
		after = time.After
	}
	select {
	case r := <-done:
		return r
	case <-after(eventWatchdog):
		return EventResult{Exit: EventFailed, Message: "event not spooled: timed out after 10 s (the spool disk may be stalled)", Signature: sig}
	}
}

func spoolEvent(d EventDeps, filename, virusname string) EventResult {
	sig := SanitizeSignature(virusname)
	fail := func(spool, format string, a ...any) EventResult {
		return EventResult{Exit: EventFailed, Message: "event not spooled: " + fmt.Sprintf(format, a...), Signature: sig, SpoolDir: spool}
	}
	// The environment is deliberately not consulted: clamd's environment has
	// none of ours, and a stray variable must not redirect the spool.
	cfgPath := d.ConfigPath
	if cfgPath == "" {
		cfgPath = DefaultConfigPath
	}
	// explicit=true: a missing file is an error here, never "use the defaults".
	cfg, _, err := LoadConfig(cfgPath, true, config.Options{
		LookupEnv: func(string) (string, bool) { return "", false },
		Environ:   func() []string { return nil },
		ReadFile:  d.ReadFile,
	})
	if err == nil {
		err = cfg.Validate()
	}
	if err != nil {
		var pe *fs.PathError
		switch {
		case errors.As(err, &pe):
			return fail("", "cannot read config %s: %s", cfgPath, describeFileErr(pe.Err))
		default:
			return fail("", "invalid config %s: %v", cfgPath, err)
		}
	}
	host, err := d.Hostname()
	if err != nil {
		return fail(cfg.Spool.Dir, "hostname: %v", err)
	}
	q, err := OpenSpoolForEvent(SpoolOptions{
		Dir: cfg.Spool.Dir, MaxBytes: int64(cfg.Spool.MaxMB) << 20,
		MaxEventAge: time.Duration(cfg.Spool.MaxEventDays) * 24 * time.Hour,
		AgentUID:    -1, Now: d.Now, FS: d.FS, Sleep: d.Sleep, NewID: d.NewID,
	})
	if err != nil {
		if errors.Is(err, ErrNotOurSpool) {
			return fail(cfg.Spool.Dir, "spool/events is not a directory owned by the agent")
		}
		return fail(cfg.Spool.Dir, "cannot open the spool: %s", describeSpoolErr(err))
	}
	defer q.Close()
	res, err := q.AddEvent(BuildEvent(d.Now(), host, q.o.NewID(), filename, virusname))
	switch {
	case errors.Is(err, ErrSpoolFull):
		return fail(cfg.Spool.Dir, "spool full")
	case errors.Is(err, ErrSpoolBusy):
		return fail(cfg.Spool.Dir, "spool busy (the usage lock was not free within 2 s)")
	case err != nil:
		return fail(cfg.Spool.Dir, "%s", describeSpoolErr(err))
	case res.SyncErr != nil:
		return EventResult{Exit: EventFailed, Message: "spooled; directory sync failed: " + describeSpoolErr(res.SyncErr), Signature: sig, SpoolDir: cfg.Spool.Dir}
	}
	return EventResult{Exit: EventSpooled}
}

// describeSpoolErr is the error text for the journal. Spool errors name only
// spool-relative item names (a time and a random id), never the detected path,
// which lives in the file's content and nowhere in a name.
func describeSpoolErr(err error) string { return err.Error() }
