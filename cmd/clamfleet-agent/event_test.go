// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/agent"
)

// clamdEnv is exactly what clamd gives VirusEvent: PATH and two variables.
func clamdEnv(filename, virus string) []string {
	return []string{"CLAM_VIRUSEVENT_FILENAME=" + filename, "CLAM_VIRUSEVENT_VIRUSNAME=" + virus}
}

type eventTree struct {
	Dir, Spool, Cfg, Token string
	Conns                  *atomic.Int32
}

// newEventTree builds a spool as `run` would, a config pointing at it, a token
// file that nobody can read, and a loopback listener that counts connections
// (the server address in the config), so a test can prove `event` never dials.
func newEventTree(t *testing.T, maxMB int) *eventTree {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("these tests need a non-root user: they rely on mode 0000 files being unreadable")
	}
	dir := t.TempDir()
	spool := filepath.Join(dir, "spool")
	if err := os.Mkdir(spool, 0o750); err != nil {
		t.Fatal(err)
	}
	q, err := agent.OpenSpoolForRun(agent.SpoolOptions{Dir: spool, MaxBytes: 1 << 20, AgentUID: os.Getuid(), Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	q.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conns := &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	tree := &eventTree{Dir: dir, Spool: spool, Cfg: filepath.Join(dir, "agent.yaml"), Token: filepath.Join(dir, "token"), Conns: conns}
	if err := os.WriteFile(tree.Token, []byte("tok"), 0o000); err != nil {
		t.Fatal(err)
	}
	yml := fmt.Sprintf("server: http://%s\ntoken_file: %s\nspool: {dir: %s, max_mb: %d}\n", ln.Addr(), tree.Token, spool, maxMB)
	if err := os.WriteFile(tree.Cfg, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	return tree
}

func (e *eventTree) events(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(e.Spool, "events"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, x := range ents {
		out = append(out, x.Name())
	}
	return out
}

func TestEventThroughTheBinary(t *testing.T) {
	tree := newEventTree(t, 1)
	res := runAgent(t, "/nonexistent", clamdEnv("/srv/e2e/eicar.com", "Win.Test.EICAR_HDB-1"), "event", "--config", tree.Cfg)
	if res.code != 0 || res.stderr != "" || res.stdout != "" {
		t.Fatalf("%+v", res)
	}
	names := tree.events(t)
	if len(names) != 1 {
		t.Fatalf("events: %v", names)
	}
	raw, _ := os.ReadFile(filepath.Join(tree.Spool, "events", names[0]))
	var ev map[string]any
	if err := json.Unmarshal(raw, &ev); err != nil || ev["path"] != "/srv/e2e/eicar.com" || ev["source"] != "clamd" {
		t.Fatalf("%v %s", err, raw)
	}
	// Zero connections to the configured server, and the unreadable token gave
	// no warning: event never reads or sends anything but the spool item.
	time.Sleep(100 * time.Millisecond)
	if n := tree.Conns.Load(); n != 0 {
		t.Fatalf("event connected to the server %d times", n)
	}
	if fi, _ := os.Stat(filepath.Join(tree.Spool, "events", names[0])); fi.Mode().Perm() != 0o640 {
		t.Fatalf("item mode %v, want 0640", fi.Mode().Perm())
	}
}

func TestEventWithoutVariablesIsUsageError(t *testing.T) {
	tree := newEventTree(t, 1)
	res := runAgent(t, "/nonexistent", nil, "event", "--config", tree.Cfg)
	if res.code != 2 || !strings.Contains(res.stderr, "CLAM_VIRUSEVENT_FILENAME") {
		t.Fatalf("%+v", res)
	}
	if len(tree.events(t)) != 0 {
		t.Fatal("something was spooled")
	}
}

// Unreadable config: exit 1, one line naming the file, nothing spooled.
func TestEventUnreadableConfigSpoolsNothing(t *testing.T) {
	tree := newEventTree(t, 1)
	if err := os.Chmod(tree.Cfg, 0); err != nil {
		t.Fatal(err)
	}
	res := runAgent(t, "/nonexistent", clamdEnv("/srv/MARKER-PATH", "Sig"), "event", "--config", tree.Cfg)
	if res.code != 1 {
		t.Fatalf("%+v", res)
	}
	lines := strings.Split(strings.TrimSpace(res.stderr), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "event not spooled: cannot read config "+tree.Cfg+": permission denied") {
		t.Fatalf("stderr: %q", res.stderr)
	}
	if strings.Contains(res.stderr, "MARKER") {
		t.Fatalf("the path is in the journal line: %q", res.stderr)
	}
	if len(tree.events(t)) != 0 {
		t.Fatal("something was spooled")
	}
	// The default config path does not exist here either: same refusal, no fallback.
	res = runAgent(t, "/nonexistent", clamdEnv("/srv/x", "Sig"), "event")
	if res.code != 1 || !strings.Contains(res.stderr, "cannot read config "+agent.DefaultConfigPath) {
		t.Fatalf("%+v", res)
	}
}

func TestEventUnwritableSpoolFailsWithOneLine(t *testing.T) {
	tree := newEventTree(t, 1)
	if err := os.Chmod(filepath.Join(tree.Spool, "events"), 0o750); err != nil {
		t.Fatal(err)
	}
	res := runAgent(t, "/nonexistent", clamdEnv("/srv/MARKER-PATH", "Sig"), "event", "--config", tree.Cfg)
	if res.code != 1 || strings.Count(strings.TrimSpace(res.stderr), "\n") != 0 || !strings.Contains(res.stderr, "spool/events is not a directory owned by the agent") || strings.Contains(res.stderr, "MARKER") {
		t.Fatalf("%+v", res)
	}
	if len(tree.events(t)) != 0 {
		t.Fatal("something was spooled")
	}
}

func TestEventRefusesSymlinkedEventsDir(t *testing.T) {
	tree := newEventTree(t, 1)
	elsewhere := filepath.Join(tree.Dir, "elsewhere")
	if err := os.Mkdir(elsewhere, 0o770|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	ev := filepath.Join(tree.Spool, "events")
	os.Remove(ev)
	if err := os.Symlink(elsewhere, ev); err != nil {
		t.Fatal(err)
	}
	res := runAgent(t, "/nonexistent", clamdEnv("/srv/x", "Sig"), "event", "--config", tree.Cfg)
	if res.code != 1 || !strings.Contains(res.stderr, "not a directory owned by the agent") {
		t.Fatalf("%+v", res)
	}
	if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
		t.Fatalf("written through the symlink: %v", ents)
	}
	// And a symlinked spool/ itself.
	os.Remove(ev)
	link := filepath.Join(tree.Dir, "spool-link")
	os.Symlink(tree.Spool, link)
	yml := fmt.Sprintf("token_file: %s\nspool: {dir: %s, max_mb: 1}\n", tree.Token, link)
	os.WriteFile(tree.Cfg, []byte(yml), 0o644)
	res = runAgent(t, "/nonexistent", clamdEnv("/srv/x", "Sig"), "event", "--config", tree.Cfg)
	if res.code != 1 {
		t.Fatalf("symlinked spool accepted: %+v", res)
	}
}

// Eight real processes at once, room for exactly one: the usage lock makes the
// count exact. Without it several read the same total and all pass.
func TestConcurrentEventAdmissionAtLimit(t *testing.T) {
	tree := newEventTree(t, 1)
	const capBytes = 1 << 20
	usage := fmt.Sprintf(`{"total":%d,"base":%d,"at":1}`, capBytes-4096, capBytes-4096)
	if err := os.WriteFile(filepath.Join(tree.Spool, "usage"), []byte(usage), 0o660); err != nil {
		t.Fatal(err)
	}
	const n = 8
	var wg sync.WaitGroup
	codes := make([]result, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes[i] = runAgent(t, "/nonexistent", clamdEnv(fmt.Sprintf("/srv/f%d", i), "Sig"), "event", "--config", tree.Cfg)
		}()
	}
	close(start)
	wg.Wait()
	ok, full := 0, 0
	for _, r := range codes {
		switch {
		case r.code == 0:
			ok++
		case r.code == 1 && strings.Contains(r.stderr, "spool full"):
			full++
		default:
			t.Fatalf("unexpected: %+v", r)
		}
	}
	if ok != 1 || full != n-1 || len(tree.events(t)) != 1 {
		t.Fatalf("admitted=%d full=%d items=%d, want 1, %d, 1", ok, full, len(tree.events(t)), n-1)
	}
}

// Another process holds the usage lock for 5 s: event gives up after about 2 s
// ("spool busy"), because clamd waits for it.
func TestEventLockWaitIsBounded(t *testing.T) {
	tree := newEventTree(t, 1)
	f, err := os.OpenFile(filepath.Join(tree.Spool, "usage"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res := runAgent(t, "/nonexistent", clamdEnv("/srv/x", "Sig"), "event", "--config", tree.Cfg)
	took := time.Since(start)
	if res.code != 1 || !strings.Contains(res.stderr, "spool busy") {
		t.Fatalf("%+v", res)
	}
	if took < 1900*time.Millisecond || took > 4*time.Second {
		t.Fatalf("gave up after %v, want about 2s", took)
	}
	if len(tree.events(t)) != 0 {
		t.Fatal("spooled while the lock was held")
	}
}

func TestEventIsRegisteredInUsage(t *testing.T) {
	res := runAgent(t, "/nonexistent", nil, "help")
	if !strings.Contains(res.stdout, "event") {
		t.Fatalf("usage does not list event: %q", res.stdout)
	}
}
