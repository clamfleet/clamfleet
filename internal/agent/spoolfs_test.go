// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// recFS wraps the real filesystem seam. It records every call, can fail any
// call by name, and can run a hook just before a call, which is how a test
// stages a race ("a symlink appears between the Lstat and the open").
//
// Operation names are short ("OpenFile", "Fchmod", "Write", "Sync", "Close",
// "Link", "Remove", "SyncDir", "Lstat", "ReadDir", ...). A file name that
// starts with .tmp- is recorded as part of the name too, e.g. "Remove(tmp)".
type recFS struct {
	osFS
	mu    sync.Mutex
	calls []string
	// fail maps an operation name to the error it returns instead of running.
	fail map[string]error
	// hook runs before the operation; name is the path argument ("" if none).
	hook func(op, name string)
	// writeLimit, when > 0, makes Write store only that many bytes (a short write).
	writeLimit int
	// syncDelay is slept in a file Sync (a slow disk).
	syncDelay time.Duration
	readDirs  int
	// bytesRead counts the bytes returned by file Reads (the reader's allocation bound).
	bytesRead int64
}

func (r *recFS) rec(op, name string) error {
	r.mu.Lock()
	tag := op
	if strings.HasPrefix(filepath.Base(name), tmpPrefix) {
		tag = op + "(tmp)"
	}
	r.calls = append(r.calls, tag)
	hook := r.hook
	err := r.fail[tag]
	if err == nil {
		err = r.fail[op]
	}
	r.mu.Unlock()
	if hook != nil {
		hook(op, name)
	}
	return err
}

func (r *recFS) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.calls...)
}

func (r *recFS) reset() {
	r.mu.Lock()
	r.calls = nil
	r.mu.Unlock()
}

func (r *recFS) OpenRoot(dir string) (spoolRoot, error) {
	if err := r.rec("OpenRoot", dir); err != nil {
		return nil, err
	}
	root, err := r.osFS.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &recRoot{spoolRoot: root, r: r}, nil
}

type recRoot struct {
	spoolRoot
	r *recFS
}

func (o *recRoot) Lstat(name string) (fs.FileInfo, error) {
	if err := o.r.rec("Lstat", name); err != nil {
		return nil, err
	}
	return o.spoolRoot.Lstat(name)
}

func (o *recRoot) OpenFile(name string, flag int, perm fs.FileMode) (spoolFile, error) {
	if err := o.r.rec("OpenFile", name); err != nil {
		return nil, err
	}
	f, err := o.spoolRoot.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &recFile{spoolFile: f, r: o.r, name: name}, nil
}

func (o *recRoot) Link(a, b string) error {
	if err := o.r.rec("Link", a); err != nil {
		return err
	}
	return o.spoolRoot.Link(a, b)
}

func (o *recRoot) Remove(name string) error {
	if err := o.r.rec("Remove", name); err != nil {
		return err
	}
	return o.spoolRoot.Remove(name)
}

func (o *recRoot) Rename(a, b string) error {
	if err := o.r.rec("Rename", a); err != nil {
		return err
	}
	return o.spoolRoot.Rename(a, b)
}

func (o *recRoot) SyncDir(name string) error {
	if err := o.r.rec("SyncDir", name); err != nil {
		return err
	}
	return o.spoolRoot.SyncDir(name)
}

func (o *recRoot) OpenDir(name string) (dirReader, error) {
	d, err := o.spoolRoot.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return &recDir{dirReader: d, r: o.r}, nil
}

type recDir struct {
	dirReader
	r *recFS
}

func (d *recDir) ReadDir(n int) ([]fs.DirEntry, error) {
	d.r.mu.Lock()
	d.r.readDirs++
	d.r.mu.Unlock()
	return d.dirReader.ReadDir(n)
}

type recFile struct {
	spoolFile
	r    *recFS
	name string
}

func (f *recFile) Chmod(m fs.FileMode) error {
	if err := f.r.rec("Fchmod", f.name); err != nil {
		return err
	}
	return f.spoolFile.Chmod(m)
}

func (f *recFile) Read(p []byte) (int, error) {
	n, err := f.spoolFile.Read(p)
	f.r.mu.Lock()
	f.r.bytesRead += int64(n)
	f.r.mu.Unlock()
	return n, err
}

func (f *recFile) Write(p []byte) (int, error) {
	if err := f.r.rec("Write", f.name); err != nil {
		return 0, err
	}
	if f.r.writeLimit > 0 && len(p) > f.r.writeLimit {
		return f.spoolFile.Write(p[:f.r.writeLimit])
	}
	return f.spoolFile.Write(p)
}

func (f *recFile) Sync() error {
	if err := f.r.rec("Sync", f.name); err != nil {
		return err
	}
	if f.r.syncDelay > 0 {
		time.Sleep(f.r.syncDelay)
	}
	return f.spoolFile.Sync()
}

func (f *recFile) Close() error {
	if err := f.r.rec("Close", f.name); err != nil {
		f.spoolFile.Close()
		return err
	}
	return f.spoolFile.Close()
}

// fakeClock is the injected clock of the spool tests. Sleep advances it, so a
// lock-wait loop finishes without real waiting.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

// newFakeClock starts at the real time of the test run, then stands still. It
// cannot start in a fixed past or future year: the spool compares the clock with
// file modification times, which the real filesystem stamps with real time.
func newFakeClock() *fakeClock { return &fakeClock{t: time.Now().UTC().Truncate(time.Second)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// testSpool lays out a spool in a temp directory and returns it opened for
// `run`, with the layout created. MaxBytes defaults to 1 MiB.
type testSpool struct {
	Dir   string
	Clock *fakeClock
	FS    *recFS
	Opts  SpoolOptions
}

func newTestSpool(t *testing.T) *testSpool {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	clock := newFakeClock()
	rfs := &recFS{fail: map[string]error{}}
	n := 0
	var idMu sync.Mutex
	opts := SpoolOptions{
		Dir: dir, MaxBytes: 1 << 20, MaxEventAge: 365 * 24 * time.Hour, AgentUID: os.Getuid(),
		Now: clock.Now, FS: rfs, Sleep: clock.Advance,
		NewID: func() string {
			idMu.Lock()
			defer idMu.Unlock()
			n++
			return strings.Repeat("0", 24) + padHex(n)
		},
	}
	return &testSpool{Dir: dir, Clock: clock, FS: rfs, Opts: opts}
}

func padHex(n int) string {
	const digits = "0123456789abcdef"
	b := []byte("00000000")
	for i := 7; i >= 0 && n > 0; i-- {
		b[i] = digits[n%16]
		n /= 16
	}
	return string(b)
}

// OpenRun opens the spool as the agent service and closes it at the end of the test.
func (ts *testSpool) OpenRun(t *testing.T) *Queue {
	t.Helper()
	q, err := OpenSpoolForRun(ts.Opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	return q
}

// OpenEvent opens the spool as the event command. The layout must exist.
func (ts *testSpool) OpenEvent(t *testing.T) *Queue {
	t.Helper()
	o := ts.Opts
	o.AgentUID = -1
	q, err := OpenSpoolForEvent(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	return q
}

// names lists the entries of a spool subdirectory, sorted.
func (ts *testSpool) names(t *testing.T, sub string) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(ts.Dir, sub))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}
