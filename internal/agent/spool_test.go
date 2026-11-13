// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// testEvent builds a valid event whose id is id (32 hex).
func testEvent(id string) proto.Event {
	return proto.Event{Schema: 1, ID: &id, Host: "app01", TS: time.Date(2031, 3, 4, 12, 0, 0, 0, time.UTC),
		Path: "/srv/x", Signature: "Win.Test.EICAR_HDB-1", Source: "clamd"}
}

func eventBody(t *testing.T, id string) []byte {
	t.Helper()
	b, err := json.Marshal(testEvent(id))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const idA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// The success path is exactly these calls in this order. Dropping either
// fsync (the file's, or the directory's) changes the sequence and fails here.
func TestPublishSequence(t *testing.T) {
	ts := newTestSpool(t)
	q := ts.OpenRun(t)
	ts.FS.reset()
	res, err := q.publish(dirEvents, idA, eventBody(t, idA))
	if err != nil || res.SyncErr != nil {
		t.Fatalf("publish: %v %v", err, res.SyncErr)
	}
	want := []string{"OpenFile(tmp)", "Fchmod(tmp)", "Write(tmp)", "Sync(tmp)", "Close(tmp)", "Link(tmp)", "Remove(tmp)", "SyncDir"}
	if got := ts.FS.Calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("call sequence\n got %v\nwant %v", got, want)
	}
	if got := ts.names(t, dirEvents); len(got) != 1 || got[0] != res.Name {
		t.Fatalf("events = %v, want only %s", got, res.Name)
	}
}

func TestPublishErrors(t *testing.T) {
	boom := errors.New("injected")
	for _, c := range []struct {
		name   string
		setup  func(r *recFS)
		syncOK bool // SyncErr expected instead of a failure
		calls  map[string]int
	}{
		{name: "write error", setup: func(r *recFS) { r.fail["Write"] = boom }},
		{name: "short write", setup: func(r *recFS) { r.writeLimit = 5 }},
		{name: "file fsync error", setup: func(r *recFS) { r.fail["Sync"] = boom }, calls: map[string]int{"Sync(tmp)": 1}},
		{name: "close error", setup: func(r *recFS) { r.fail["Close"] = boom }},
		{name: "chmod error", setup: func(r *recFS) { r.fail["Fchmod"] = boom }},
		{name: "link error", setup: func(r *recFS) { r.fail["Link"] = boom }},
	} {
		t.Run(c.name, func(t *testing.T) {
			ts := newTestSpool(t)
			q := ts.OpenRun(t)
			c.setup(ts.FS)
			ts.FS.reset()
			_, err := q.publish(dirEvents, idA, eventBody(t, idA))
			if err == nil {
				t.Fatal("publish succeeded")
			}
			if got := ts.names(t, dirEvents); len(got) != 0 {
				t.Fatalf("a final name or temp file is left: %v", got)
			}
			counts := map[string]int{}
			for _, c := range ts.FS.Calls() {
				counts[c]++
			}
			for k, v := range c.calls {
				if counts[k] != v {
					t.Fatalf("%s called %d times, want %d (never retry an fsync)", k, counts[k], v)
				}
			}
		})
	}
}

// A failing temp-file removal after the link leaves the item published (two
// names); the reader waits and Sweep removes the temp name.
func TestPublishRemoveTmpFailureKeepsItem(t *testing.T) {
	ts := newTestSpool(t)
	q := ts.OpenRun(t)
	ts.FS.fail["Remove(tmp)"] = errors.New("injected")
	res, err := q.publish(dirEvents, idA, eventBody(t, idA))
	if err != nil {
		t.Fatalf("publish failed: %v", err)
	}
	delete(ts.FS.fail, "Remove(tmp)")
	if got := ts.names(t, dirEvents); len(got) != 2 {
		t.Fatalf("want the item and the temp name, got %v", got)
	}
	// The reader skips it while the second name exists.
	if _, _, err := q.ReadItem(dirEvents, res.Name, maxEventFileBytes); !errors.Is(err, errSkip) {
		t.Fatalf("ReadItem = %v, want errSkip", err)
	}
	ts.Clock.Advance(tmpMaxAge + time.Minute)
	for _, n := range ts.names(t, dirEvents) {
		if strings.HasPrefix(n, tmpPrefix) {
			old := ts.Clock.Now().Add(-time.Hour)
			if err := os.Chtimes(filepath.Join(ts.Dir, dirEvents, n), old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	if res := q.Sweep(); res.Temp != 1 {
		t.Fatalf("sweep removed %d temp files, want 1", res.Temp)
	}
	if _, _, err := q.ReadItem(dirEvents, res.Name, maxEventFileBytes); err != nil {
		t.Fatalf("ReadItem after sweep: %v", err)
	}
}

func TestPublishSyncDirFailureKeepsItem(t *testing.T) {
	ts := newTestSpool(t)
	q := ts.OpenRun(t)
	ts.FS.fail["SyncDir"] = errors.New("injected")
	res, err := q.publish(dirEvents, idA, eventBody(t, idA))
	if err != nil || res.SyncErr == nil {
		t.Fatalf("err=%v SyncErr=%v, want a published item with an unconfirmed directory sync", err, res.SyncErr)
	}
	if got := ts.names(t, dirEvents); len(got) != 1 {
		t.Fatalf("events = %v", got)
	}
}

// Link must not replace an existing item: with the first name taken the next
// nanosecond name is used, and the old content is intact. With rename() the old
// item would be silently overwritten.
func TestPublishNeverOverwrites(t *testing.T) {
	ts := newTestSpool(t)
	q := ts.OpenRun(t)
	first := fmt.Sprintf("%020d-%s.json", ts.Clock.Now().UnixNano(), idA)
	if err := os.WriteFile(filepath.Join(ts.Dir, dirEvents, first), []byte("OLD"), 0o640); err != nil {
		t.Fatal(err)
	}
	res, err := q.publish(dirEvents, idA, eventBody(t, idA))
	if err != nil {
		t.Fatal(err)
	}
	if res.Name == first {
		t.Fatal("reused an existing name")
	}
	got, _ := os.ReadFile(filepath.Join(ts.Dir, dirEvents, first))
	if string(got) != "OLD" {
		t.Fatalf("existing item overwritten: %q", got)
	}
}

// A reader that looks between Close and Link sees no item: the final name only
// appears once the content is on disk (writing straight to the final name would
// show a partial file here).
func TestPublishIsAtomicToReaders(t *testing.T) {
	ts := newTestSpool(t)
	q := ts.OpenRun(t)
	var seen []string
	ts.FS.hook = func(op, name string) {
		if op == "Link" {
			seen = ts.names(t, dirEvents)
		}
	}
	if _, err := q.publish(dirEvents, idA, eventBody(t, idA)); err != nil {
		t.Fatal(err)
	}
	l, err := q.List(dirEvents, listSpec{oldest: 10})
	if err != nil || len(l.Oldest) != 1 {
		t.Fatalf("list after publish: %v %v", l, err)
	}
	for _, n := range seen {
		if _, ok := nameTime(n); ok {
			t.Fatalf("a final name %s existed before the link", n)
		}
	}
}

func put(t *testing.T, ts *testSpool, dir, name string, body []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(ts.Dir, dir, name), body, 0o640); err != nil {
		t.Fatal(err)
	}
}

func itemFileName(clock *fakeClock, id string, offset time.Duration) string {
	return fmt.Sprintf("%020d-%s.json", clock.Now().Add(offset).UnixNano(), id)
}

func TestReaderNeverFollowsOrOpensNonRegular(t *testing.T) {
	ts := newTestSpool(t)
	q := ts.OpenRun(t)
	secret := filepath.Join(filepath.Dir(ts.Dir), "secret")
	const marker = "TOP-SECRET-MARKER"
	if err := os.WriteFile(secret, []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	ev := filepath.Join(ts.Dir, dirEvents)

	t.Run("symlink outside", func(t *testing.T) {
		n := itemFileName(ts.Clock, idA, 0)
		if err := os.Symlink("../../secret", filepath.Join(ev, n)); err != nil {
			t.Fatal(err)
		}
		data, _, err := q.ReadItem(dirEvents, n, maxEventFileBytes)
		if !errors.Is(err, errNonRegular) || bytes.Contains(data, []byte(marker)) {
			t.Fatalf("err=%v data=%q", err, data)
		}
		if _, err := os.Lstat(filepath.Join(ev, n)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the symlink was not removed: %v", err)
		}
		if _, err := os.Stat(secret); err != nil {
			t.Fatal("the target was touched")
		}
	})
	t.Run("symlink to another item", func(t *testing.T) {
		other := itemFileName(ts.Clock, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 0)
		put(t, ts, dirEvents, other, eventBody(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
		n := itemFileName(ts.Clock, idA, 1)
		if err := os.Symlink(other, filepath.Join(ev, n)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := q.ReadItem(dirEvents, n, maxEventFileBytes); !errors.Is(err, errNonRegular) {
			t.Fatalf("err=%v", err)
		}
		if _, err := os.Lstat(filepath.Join(ev, other)); err != nil {
			t.Fatal("the real item was removed")
		}
	})
	t.Run("fifo does not hang", func(t *testing.T) {
		n := itemFileName(ts.Clock, idA, 2)
		if err := syscall.Mkfifo(filepath.Join(ev, n), 0o640); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, _, err := q.ReadItem(dirEvents, n, maxEventFileBytes); done <- err }()
		select {
		case err := <-done:
			if !errors.Is(err, errNonRegular) {
				t.Fatalf("err=%v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("ReadItem hung on a FIFO")
		}
		if _, err := os.Lstat(filepath.Join(ev, n)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("the FIFO was not removed")
		}
	})
}

func TestReaderHardlink(t *testing.T) {
	ts := newTestSpool(t)
	q := ts.OpenRun(t)
	outside := filepath.Join(filepath.Dir(ts.Dir), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	n := itemFileName(ts.Clock, idA, 0)
	link := filepath.Join(ts.Dir, dirEvents, n)
	if err := os.Link(outside, link); err != nil {
		t.Skipf("hard links not permitted here") // precondition of the test, not of the code under test
	}
	// Young: a publish may be in progress, so only skip.
	now := ts.Clock.Now()
	if _, _, err := q.ReadItem(dirEvents, n, maxEventFileBytes); !errors.Is(err, errSkip) {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatal("a young hardlink was removed")
	}
	// Old (the outside file's mtime is the link's mtime): the name is unlinked.
	old := now.Add(-time.Hour)
	if err := os.Chtimes(outside, old, old); err != nil {
		t.Fatal(err)
	}
	if _, _, err := q.ReadItem(dirEvents, n, maxEventFileBytes); !errors.Is(err, errSkip) {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Lstat(link); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("the old hostile name was not unlinked")
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != "outside" {
		t.Fatalf("the outside file was touched: %q %v", b, err)
	}
}

// Races: the hook runs between two steps of the reader and swaps the entry.
func TestReaderRaces(t *testing.T) {
	t.Run("symlink swapped in between Lstat and OpenFile", func(t *testing.T) {
		ts := newTestSpool(t)
		q := ts.OpenRun(t)
		outside := filepath.Join(filepath.Dir(ts.Dir), "secret")
		os.WriteFile(outside, []byte(eventBodyString(t)), 0o600)
		n := itemFileName(ts.Clock, idA, 0)
		p := filepath.Join(ts.Dir, dirEvents, n)
		put(t, ts, dirEvents, n, eventBody(t, idA))
		swapped := false
		ts.FS.hook = func(op, name string) {
			if op == "OpenFile" && strings.HasSuffix(name, n) && !swapped {
				swapped = true
				os.Remove(p)
				os.Symlink("../../secret", p)
			}
		}
		_, _, err := q.ReadItem(dirEvents, n, maxEventFileBytes)
		if err == nil {
			t.Fatal("the swapped-in symlink was read")
		}
	})
	t.Run("regular file replaced by a FIFO in the gap", func(t *testing.T) {
		ts := newTestSpool(t)
		q := ts.OpenRun(t)
		n := itemFileName(ts.Clock, idA, 0)
		p := filepath.Join(ts.Dir, dirEvents, n)
		put(t, ts, dirEvents, n, eventBody(t, idA))
		swapped := false
		ts.FS.hook = func(op, name string) {
			if op == "OpenFile" && strings.HasSuffix(name, n) && !swapped {
				swapped = true
				os.Remove(p)
				syscall.Mkfifo(p, 0o640)
			}
		}
		done := make(chan error, 1)
		go func() { _, _, err := q.ReadItem(dirEvents, n, maxEventFileBytes); done <- err }()
		select {
		case err := <-done:
			if !errors.Is(err, errChanged) {
				t.Fatalf("err=%v, want errChanged", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("hung on a FIFO swapped in at the last moment")
		}
	})
	t.Run("a different regular file swapped in is detected by inode", func(t *testing.T) {
		ts := newTestSpool(t)
		q := ts.OpenRun(t)
		n := itemFileName(ts.Clock, idA, 0)
		p := filepath.Join(ts.Dir, dirEvents, n)
		put(t, ts, dirEvents, n, eventBody(t, idA))
		swapped := false
		ts.FS.hook = func(op, name string) {
			if op == "OpenFile" && strings.HasSuffix(name, n) && !swapped {
				swapped = true
				os.Remove(p)
				os.WriteFile(p, []byte("{}"), 0o640)
			}
		}
		if _, _, err := q.ReadItem(dirEvents, n, maxEventFileBytes); !errors.Is(err, errChanged) {
			t.Fatalf("err=%v, want errChanged", err)
		}
	})
	t.Run("replaced after reading and before delete", func(t *testing.T) {
		ts := newTestSpool(t)
		q := ts.OpenRun(t)
		n := itemFileName(ts.Clock, idA, 0)
		p := filepath.Join(ts.Dir, dirEvents, n)
		put(t, ts, dirEvents, n, eventBody(t, idA))
		_, id, err := q.ReadItem(dirEvents, n, maxEventFileBytes)
		if err != nil {
			t.Fatal(err)
		}
		os.Remove(p)
		os.WriteFile(p, []byte("REPLACEMENT"), 0o640)
		if err := q.Delete(dirEvents, n, id); !errors.Is(err, errReplaced) {
			t.Fatalf("Delete = %v, want errReplaced", err)
		}
		if b, _ := os.ReadFile(p); string(b) != "REPLACEMENT" {
			t.Fatalf("the replacement was deleted: %q", b)
		}
		// Unchanged item: deleted.
		_, id, _ = q.ReadItem(dirEvents, n, maxEventFileBytes)
		if err := q.Delete(dirEvents, n, id); err != nil {
			t.Fatal(err)
		}
	})
}

func eventBodyString(t *testing.T) string { return string(eventBody(t, idA)) }

func TestReaderBoundedAndOwnership(t *testing.T) {
	ts := newTestSpool(t)
	q := ts.OpenRun(t)
	n := itemFileName(ts.Clock, idA, 0)
	put(t, ts, dirEvents, n, bytes.Repeat([]byte("x"), 65<<10))
	if _, _, err := q.ReadItem(dirEvents, n, maxEventFileBytes); !errors.Is(err, errTooLarge) {
		t.Fatalf("err=%v, want errTooLarge", err)
	}
	exact := itemFileName(ts.Clock, idA, 1)
	put(t, ts, dirEvents, exact, bytes.Repeat([]byte("x"), maxEventFileBytes))
	if _, _, err := q.ReadItem(dirEvents, exact, maxEventFileBytes); err != nil {
		t.Fatalf("a file of exactly the limit: %v", err)
	}
	// A report not owned by the agent: the spool believes another uid is the agent.
	r := itemFileName(ts.Clock, idA, 2)
	put(t, ts, dirReports, r, []byte("{}"))
	ts.Opts.AgentUID = os.Getuid() + 1
	q2 := &Queue{o: ts.Opts, root: q.root}
	if _, _, err := q2.ReadItem(dirReports, r, maxReportFileBytes); !errors.Is(err, errNotOwned) {
		t.Fatalf("err=%v, want errNotOwned", err)
	}
	// EACCES is passed through, for the caller to skip.
	acc := itemFileName(ts.Clock, idA, 3)
	put(t, ts, dirEvents, acc, []byte("{}"))
	if err := os.Chmod(filepath.Join(ts.Dir, dirEvents, acc), 0); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		if _, _, err := q.ReadItem(dirEvents, acc, maxEventFileBytes); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("err=%v, want a permission error", err)
		}
	}
}

// A 10 MiB file in spool/events must cost at most limit+1 bytes of reading, not 10 MiB:
// the bound is what keeps clamd's group from making the agent allocate without limit.
func TestReaderNeverReadsMoreThanItsLimit(t *testing.T) {
	ts := newTestSpool(t)
	q := ts.OpenRun(t)
	n := itemFileName(ts.Clock, idA, 0)
	f, err := os.Create(filepath.Join(ts.Dir, dirEvents, n))
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(10 << 20) // sparse: it costs no disk, and reads back as zeros
	f.Close()
	ts.FS.mu.Lock()
	ts.FS.bytesRead = 0
	ts.FS.mu.Unlock()
	if _, _, err := q.ReadItem(dirEvents, n, maxEventFileBytes); !errors.Is(err, errTooLarge) {
		t.Fatalf("err = %v, want errTooLarge", err)
	}
	ts.FS.mu.Lock()
	defer ts.FS.mu.Unlock()
	if ts.FS.bytesRead > maxEventFileBytes+1 {
		t.Fatalf("read %d bytes of an oversized item, want at most %d", ts.FS.bytesRead, maxEventFileBytes+1)
	}
}

func TestEventSideRefusesSymlinkedSpool(t *testing.T) {
	ts := newTestSpool(t)
	ts.OpenRun(t).Close()
	o := ts.Opts
	o.AgentUID = -1

	// events/ replaced by a symlink to another directory.
	elsewhere := filepath.Join(filepath.Dir(ts.Dir), "elsewhere")
	os.Mkdir(elsewhere, 0o770)
	evPath := filepath.Join(ts.Dir, dirEvents)
	os.Rename(evPath, evPath+".real")
	os.Symlink(elsewhere, evPath)
	if _, err := OpenSpoolForEvent(o); !errors.Is(err, ErrNotOurSpool) {
		t.Fatalf("symlinked events: %v", err)
	}
	os.Remove(evPath)
	os.Rename(evPath+".real", evPath)

	// spool itself a symlink.
	link := ts.Dir + "-link"
	os.Symlink(ts.Dir, link)
	o.Dir = link
	if _, err := OpenSpoolForEvent(o); !errors.Is(err, ErrNotOurSpool) {
		t.Fatalf("symlinked spool: %v", err)
	}
	// Without the sticky bit clamd's group could delete other items.
	o.Dir = ts.Dir
	os.Chmod(evPath, 0o770)
	if _, err := OpenSpoolForEvent(o); !errors.Is(err, ErrNotOurSpool) {
		t.Fatalf("events without the sticky bit: %v", err)
	}
	os.Chmod(evPath, 0o770|fs.ModeSticky|fs.ModeSetgid)
	if q, err := OpenSpoolForEvent(o); err != nil {
		t.Fatalf("the correct layout was refused: %v", err)
	} else {
		q.Close()
	}
	// Nothing was written anywhere by the failed attempts.
	if got, _ := os.ReadDir(elsewhere); len(got) != 0 {
		t.Fatalf("something was written outside: %v", got)
	}
}

func TestRunRefusesBadSpool(t *testing.T) {
	ts := newTestSpool(t)
	os.Chmod(ts.Dir, 0o757)
	if _, err := OpenSpoolForRun(ts.Opts); !errors.Is(err, ErrNotOurSpool) {
		t.Fatalf("world-writable: %v", err)
	}
	os.Chmod(ts.Dir, 0o750)
	ts.Opts.AgentUID = os.Getuid() + 1
	if _, err := OpenSpoolForRun(ts.Opts); !errors.Is(err, ErrNotOurSpool) {
		t.Fatalf("not owned by the agent: %v", err)
	}
	ts.Opts.AgentUID = os.Getuid()
	ts.Opts.Dir = filepath.Join(ts.Dir, "missing")
	if _, err := OpenSpoolForRun(ts.Opts); err == nil {
		t.Fatal("a missing spool was accepted")
	}
}

func TestSecondRunIsRefused(t *testing.T) {
	ts := newTestSpool(t)
	ts.OpenRun(t)
	if _, err := OpenSpoolForRun(ts.Opts); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second run: %v", err)
	}
}

func TestLayoutIsCreatedAndRepaired(t *testing.T) {
	ts := newTestSpool(t)
	q := ts.OpenRun(t)
	check := func() {
		for dir, want := range map[string]fs.FileMode{
			dirEvents: 0o770 | fs.ModeSetgid | fs.ModeSticky, dirReports: 0o700, dirQuarantine: 0o700,
		} {
			fi, err := os.Lstat(filepath.Join(ts.Dir, dir))
			if err != nil || fi.Mode()&(fs.ModePerm|fs.ModeSetgid|fs.ModeSticky) != want {
				t.Fatalf("%s: %v %v, want %v", dir, fi, err, want)
			}
		}
		fi, err := os.Lstat(filepath.Join(ts.Dir, fileUsage))
		if err != nil || fi.Mode().Perm() != 0o660 {
			t.Fatalf("usage: %v %v", fi, err)
		}
	}
	check()
	q.Close()
	os.Chmod(filepath.Join(ts.Dir, dirEvents), 0o700)
	ts.OpenRun(t)
	check()
}

// The cap is on real disk use (st_blocks), not on file sizes or entry counts:
// a sparse 10 MiB file occupies no blocks and must count as (almost) nothing,
// while temp files, junk names and quarantine count like items. The expected
// value is computed independently with stat(2).
func TestUsageCountsRealBlocks(t *testing.T) {
	ts := newTestSpool(t)
	q := ts.OpenRun(t)
	put(t, ts, dirEvents, itemFileName(ts.Clock, idA, 0), bytes.Repeat([]byte("x"), 300))
	put(t, ts, dirEvents, ".tmp-stale", bytes.Repeat([]byte("x"), 10))
	put(t, ts, dirEvents, "junk", bytes.Repeat([]byte("x"), 5000))
	put(t, ts, dirQuarantine, "q.json", []byte("x"))
	sparse := filepath.Join(ts.Dir, dirEvents, "sparse")
	f, err := os.Create(sparse)
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(10 << 20)
	f.Close()
	if err := q.Recount(); err != nil {
		t.Fatal(err)
	}
	var want int64
	filepath.WalkDir(ts.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		fi, _ := d.Info()
		st, _ := statOf(fi)
		want += st.Blocks * 512
		return nil
	})
	total, base, err := q.Usage()
	if err != nil {
		t.Fatal(err)
	}
	if total != want || base != want {
		t.Fatalf("total=%d base=%d, want %d (the sum of st_blocks*512 of every entry)", total, base, want)
	}
	if want > 1<<20 {
		t.Fatalf("a sparse file was counted by its size: %d", want)
	}
}

func TestAdmitEventHonoursCap(t *testing.T) {
	ts := newTestSpool(t)
	ts.Opts.MaxBytes = 3 * blockEstimate
	ts.OpenRun(t)
	e := ts.OpenEvent(t)
	for i := 0; i < 3; i++ {
		if _, err := e.AdmitEvent(300); err != nil {
			t.Fatalf("admission %d: %v", i, err)
		}
	}
	if _, err := e.AdmitEvent(300); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("fourth admission: %v, want ErrSpoolFull", err)
	}
}

// Many concurrent admitters (clamd scans on several threads) at the limit: the
// lock makes exactly the right number pass. Without it two would read the same
// total and both be admitted.
func TestConcurrentAdmissionAtLimit(t *testing.T) {
	ts := newTestSpool(t)
	ts.Opts.MaxBytes = 5 * blockEstimate
	ts.OpenRun(t)
	const workers = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted, full := 0, 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o := ts.Opts
			o.AgentUID = -1
			o.Sleep = func(time.Duration) { time.Sleep(time.Millisecond) }
			o.Now = time.Now
			q, err := OpenSpoolForEvent(o)
			if err != nil {
				t.Error(err)
				return
			}
			defer q.Close()
			_, err = q.AdmitEvent(300)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				admitted++
			case errors.Is(err, ErrSpoolFull):
				full++
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if admitted != 5 || full != workers-5 {
		t.Fatalf("admitted=%d full=%d, want 5 and %d", admitted, full, workers-5)
	}
}

func TestAdmitFailedPublishRefunds(t *testing.T) {
	ts := newTestSpool(t)
	ts.OpenRun(t)
	e := ts.OpenEvent(t)
	refund, err := e.AdmitEvent(300)
	if err != nil {
		t.Fatal(err)
	}
	before, _, _ := e.Usage()
	refund()
	after, _, _ := e.Usage()
	if after != before-blockEstimate {
		t.Fatalf("refund: %d -> %d", before, after)
	}
}

// The lock wait is bounded: another holder keeps it, the admission gives up
// after LockWait on the injected clock, and says "busy" (clamd waits for this).
func TestAdmitLockWaitIsBounded(t *testing.T) {
	ts := newTestSpool(t)
	ts.OpenRun(t)
	e := ts.OpenEvent(t)
	holder, _, err := e.lockUsage()
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	start := ts.Clock.Now()
	e2 := ts.OpenEvent(t)
	if _, err := e2.AdmitEvent(300); !errors.Is(err, ErrSpoolBusy) {
		t.Fatalf("err=%v, want ErrSpoolBusy", err)
	}
	if waited := ts.Clock.Now().Sub(start); waited < 2*time.Second || waited > 3*time.Second {
		t.Fatalf("waited %v on the injected clock, want about 2s", waited)
	}
}

func TestAdmitFallsBackWithoutUsageFile(t *testing.T) {
	ts := newTestSpool(t)
	ts.Opts.MaxBytes = 3 * blockEstimate
	run := ts.OpenRun(t)
	e := ts.OpenEvent(t)
	for _, corrupt := range []bool{false, true} {
		if corrupt {
			os.WriteFile(filepath.Join(ts.Dir, fileUsage), []byte("not json"), 0o660)
		} else {
			os.Remove(filepath.Join(ts.Dir, fileUsage))
		}
		// two items on disk, room for exactly one more by the bounded count
		for i := 0; i < 2; i++ {
			put(t, ts, dirEvents, itemFileName(ts.Clock, fmt.Sprintf("%032x", i+int(boolInt(corrupt))*10), 0), []byte("x"))
		}
		if _, err := e.AdmitEvent(300); err != nil {
			t.Fatalf("corrupt=%v: first admission: %v", corrupt, err)
		}
		put(t, ts, dirEvents, itemFileName(ts.Clock, fmt.Sprintf("%032x", 99+int(boolInt(corrupt))), 0), []byte("x"))
		if _, err := e.AdmitEvent(300); !errors.Is(err, ErrSpoolFull) {
			t.Fatalf("corrupt=%v: err=%v, want ErrSpoolFull", corrupt, err)
		}
		for _, n := range ts.names(t, dirEvents) {
			os.Remove(filepath.Join(ts.Dir, dirEvents, n))
		}
	}
	// run rewrites the file on its next recount.
	if err := run.Recount(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run.Usage(); err != nil {
		t.Fatalf("usage not rewritten: %v", err)
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// 20,000 items: an admission makes no ReadDir call, and the lister reads in
// chunks and keeps only the bounded names.
func TestLargeDirectory(t *testing.T) {
	ts := newTestSpool(t)
	ts.Opts.MaxBytes = 1 << 30
	run := ts.OpenRun(t)
	ev := filepath.Join(ts.Dir, dirEvents)
	base := ts.Clock.Now().UnixNano()
	for i := 0; i < 20000; i++ {
		f, err := os.Create(filepath.Join(ev, fmt.Sprintf("%020d-%032x.json", base+int64(i), i)))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	e := ts.OpenEvent(t)
	ts.FS.mu.Lock()
	ts.FS.readDirs = 0
	ts.FS.mu.Unlock()
	if _, err := e.AdmitEvent(300); err != nil {
		t.Fatal(err)
	}
	if ts.FS.readDirs != 0 {
		t.Fatalf("admission made %d ReadDir calls; it must not scan the directory", ts.FS.readDirs)
	}
	ts.Clock.Advance(time.Hour)
	l, err := run.List(dirEvents, listSpec{oldest: 256, newest: 64, freshAge: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Oldest) != 256 || len(l.Newest) != 0 || l.Total != 20000 {
		t.Fatalf("oldest=%d newest=%d total=%d", len(l.Oldest), len(l.Newest), l.Total)
	}
	if l.Oldest[0] != fmt.Sprintf("%020d-%032x.json", base, 0) || l.Oldest[255] != fmt.Sprintf("%020d-%032x.json", base+255, 255) {
		t.Fatalf("not the 256 oldest: %s .. %s", l.Oldest[0], l.Oldest[255])
	}
	if ts.FS.readDirs < 20000/readDirChunk {
		t.Fatalf("read the directory in %d chunks, want at least %d", ts.FS.readDirs, 20000/readDirChunk)
	}
}

func TestListFreshNewestFirst(t *testing.T) {
	ts := newTestSpool(t)
	q := ts.OpenRun(t)
	old1 := itemFileName(ts.Clock, "11111111111111111111111111111111", -time.Hour)
	old2 := itemFileName(ts.Clock, "22222222222222222222222222222222", -50*time.Minute)
	f1 := itemFileName(ts.Clock, "33333333333333333333333333333333", -30*time.Second)
	f2 := itemFileName(ts.Clock, "44444444444444444444444444444444", -5*time.Second)
	for _, n := range []string{old1, old2, f1, f2} {
		put(t, ts, dirEvents, n, []byte("{}"))
	}
	put(t, ts, dirEvents, "weird name", []byte("{}"))
	l, err := q.List(dirEvents, listSpec{oldest: 10, newest: 10, freshAge: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(l.Newest, []string{f2, f1}) {
		t.Fatalf("fresh = %v", l.Newest)
	}
	if !reflect.DeepEqual(l.Oldest, []string{old1, old2, f1, f2}) {
		t.Fatalf("oldest = %v", l.Oldest)
	}
	if !reflect.DeepEqual(l.Junk, []string{"weird name"}) {
		t.Fatalf("junk = %v", l.Junk)
	}
}

// A report that does not fit evicts the OLDEST reports only. Events are never
// evicted, and when only events fill the cap the report is refused.
func TestPutReportEvictsOnlyOldReports(t *testing.T) {
	ts := newTestSpool(t)
	ts.Opts.MaxBytes = 4 * blockEstimate
	q := ts.OpenRun(t)
	e := ts.OpenEvent(t)
	if _, err := e.AdmitEvent(300); err != nil { // one block of events
		t.Fatal(err)
	}
	ev := itemFileName(ts.Clock, idA, 0)
	put(t, ts, dirEvents, ev, []byte("{}"))
	rep := proto.Report{Schema: 1, Host: "h", Tags: []string{}}
	var first []string
	for i := 0; i < 6; i++ {
		if err := q.PutReport(rep); err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
		if i == 2 {
			first = ts.names(t, dirReports)
		}
		ts.Clock.Advance(time.Second)
	}
	reports := ts.names(t, dirReports)
	if len(reports) != 3 {
		t.Fatalf("%d reports kept with room for 3: %v", len(reports), reports)
	}
	if reports[0] <= first[2] {
		t.Fatalf("the oldest reports were not the ones evicted: kept %v, early %v", reports, first)
	}
	if _, err := os.Stat(filepath.Join(ts.Dir, dirEvents, ev)); err != nil {
		t.Fatal("an event was evicted")
	}
	if total, _, _ := q.Usage(); total > ts.Opts.MaxBytes {
		t.Fatalf("total %d over the cap %d", total, ts.Opts.MaxBytes)
	}

	// Events alone filling the cap: the report is refused and no event goes.
	ts2 := newTestSpool(t)
	ts2.Opts.MaxBytes = 2 * blockEstimate
	q2 := ts2.OpenRun(t)
	e2 := ts2.OpenEvent(t)
	for i := 0; i < 2; i++ {
		if _, err := e2.AdmitEvent(300); err != nil {
			t.Fatal(err)
		}
		put(t, ts2, dirEvents, itemFileName(ts2.Clock, fmt.Sprintf("%032x", i), time.Duration(i)), []byte("{}"))
	}
	if err := q2.PutReport(rep); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("err=%v, want ErrSpoolFull", err)
	}
	if got := ts2.names(t, dirEvents); len(got) != 2 {
		t.Fatalf("events evicted: %v", got)
	}
}

func TestPutReportNeverStoresReplay(t *testing.T) {
	ts := newTestSpool(t)
	q := ts.OpenRun(t)
	if err := q.PutReport(proto.Report{Schema: 1, Host: "h", Tags: []string{}, Replay: true}); err != nil {
		t.Fatal(err)
	}
	n := ts.names(t, dirReports)
	b, _ := os.ReadFile(filepath.Join(ts.Dir, dirReports, n[0]))
	if !bytes.Contains(b, []byte(`"replay":false`)) {
		t.Fatalf("stored report: %s", b)
	}
}

func TestSweep(t *testing.T) {
	ts := newTestSpool(t)
	q := ts.OpenRun(t)
	now := ts.Clock.Now()
	// reports: one 8 days old, one fresh
	oldR := itemFileName(ts.Clock, idA, -8*24*time.Hour)
	newR := itemFileName(ts.Clock, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", -time.Hour)
	put(t, ts, dirReports, oldR, []byte("{}"))
	put(t, ts, dirReports, newR, []byte("{}"))
	// quarantine: 105 files, of which one 40 days old
	for i := 0; i < 105; i++ {
		n := fmt.Sprintf("%020d-%032x.json", now.Add(time.Duration(i)*time.Second).UnixNano(), i)
		put(t, ts, dirQuarantine, n, []byte("{}"))
	}
	oldQ := filepath.Join(ts.Dir, dirQuarantine, fmt.Sprintf("%020d-%032x.json", now.UnixNano(), 0))
	age := now.Add(-40 * 24 * time.Hour)
	os.Chtimes(oldQ, age, age)
	res := q.Sweep()
	if res.Reports != 1 {
		t.Fatalf("reports removed: %d", res.Reports)
	}
	if got := ts.names(t, dirReports); len(got) != 1 || got[0] != newR {
		t.Fatalf("reports: %v", got)
	}
	if got := ts.names(t, dirQuarantine); len(got) != quarantineMaxN {
		t.Fatalf("quarantine has %d files, want %d", len(got), quarantineMaxN)
	}
	if _, err := os.Stat(oldQ); err == nil {
		t.Fatal("the 40-day-old quarantine file survived")
	}
}

// Recount keeps what `event` admitted while the scan ran, so the cap cannot be
// exceeded by a race between the scan and the write.
func TestRecountKeepsAdmissionsMadeDuringTheScan(t *testing.T) {
	ts := newTestSpool(t)
	run := ts.OpenRun(t)
	e := ts.OpenEvent(t)
	if _, err := e.AdmitEvent(300); err != nil {
		t.Fatal(err)
	}
	admitted := false
	ts.FS.hook = func(op, name string) {
		if op == "Lstat" && !admitted {
			admitted = true
			if _, err := e.AdmitEvent(300); err != nil {
				t.Error(err)
			}
		}
	}
	if err := run.Recount(); err != nil {
		t.Fatal(err)
	}
	ts.FS.hook = nil
	total, base, err := run.Usage()
	if err != nil {
		t.Fatal(err)
	}
	if total-base != blockEstimate {
		t.Fatalf("total=%d base=%d: the admission made during the scan was lost", total, base)
	}
}

func TestLogsNeverContainJunkNames(t *testing.T) {
	// The reader logs the directory kind, never a name chosen by clamd's group.
	ts := newTestSpool(t)
	var buf bytes.Buffer
	ts.Opts.Log = slog.New(slog.NewTextHandler(&buf, nil))
	q := ts.OpenRun(t)
	const marker = "MARKER-PATH-NAME"
	os.Symlink("/etc/passwd", filepath.Join(ts.Dir, dirEvents, marker))
	if _, _, err := q.ReadItem(dirEvents, marker, maxEventFileBytes); !errors.Is(err, errNonRegular) {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), marker) || strings.Contains(buf.String(), "passwd") {
		t.Fatalf("log: %s", buf.String())
	}
	_ = io.Discard
}
