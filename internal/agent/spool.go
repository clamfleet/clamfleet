// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// spool.go: the agent's on-disk queue of events and reports.
//
// Responsibilities: the spool layout and its start-up checks, the no-replace
// publish protocol, the hardened reader, block-accurate accounting under a
// lock shared with `event`, ordering, delete and quarantine with an inode
// check, and age-based cleanup. Validation of an item's content is validate.go;
// sending is drain.go.
//
// Trust boundary: clamd's user and group may ADD items to spool/events (they
// run `clamfleet-agent event`), so anything in that directory is untrusted
// input: it may be a symlink, a FIFO, a hardlink to a file outside the spool,
// a huge file, or a file swapped between our check and our open. The reader
// (ReadItem) defends against each of those; see docs/detections.md.
//
// Dependencies: the spoolFS seam, proto, and the standard library. It never
// imports internal/store or internal/server.

package agent

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// Spool subdirectories and files, relative to the spool root.
const (
	dirEvents     = "events"
	dirReports    = "reports"
	dirQuarantine = "quarantine"
	fileUsage     = "usage"
	fileRunLock   = ".lock"
	tmpPrefix     = ".tmp-"
)

// Limits of the reader and of cleanup (milestone 5, section 4.3).
const (
	maxEventFileBytes  = 64 << 10
	maxReportFileBytes = 1 << 20
	// publishInProgress is how long a name with two links is given to finish
	// publishing (or recover from a crash) before it is treated as hostile.
	publishInProgress = 10 * time.Minute
	tmpMaxAge         = 10 * time.Minute
	reportMaxAge      = 7 * 24 * time.Hour
	quarantineMaxAge  = 30 * 24 * time.Hour
	quarantineMaxN    = 100
	// blockEstimate rounds an item's size up the way a filesystem allocates, so
	// admission, which must not scan the directory, is close to real usage.
	blockEstimate = 4096
	// defaultLockWait bounds how long `event` waits for the usage lock: clamd
	// waits for `event`, so this wait is clamd's wait (4.2).
	defaultLockWait = 2 * time.Second
	// fallbackMaxEntries bounds the directory count used when the accounting
	// file is missing or corrupt; beyond it the spool counts as full.
	fallbackMaxEntries = 65536
	readDirChunk       = 512
)

// Errors a caller distinguishes.
var (
	// ErrSpoolFull: admission refused because the cap would be exceeded.
	ErrSpoolFull = errors.New("spool full")
	// ErrSpoolBusy: the usage lock was not obtained within the wait bound.
	ErrSpoolBusy = errors.New("spool busy")
	// ErrNotOurSpool: a start-up check failed (not a directory, a symlink, not
	// owned by the agent, writable by everyone).
	ErrNotOurSpool = errors.New("spool is not a directory owned by the agent")
	// ErrAlreadyRunning: another `run` holds the spool lock.
	ErrAlreadyRunning = errors.New("another clamfleet-agent run holds the spool lock")

	// Read outcomes. None of them is a failure of the spool itself.
	errSkip       = errors.New("item not ready")
	errNonRegular = errors.New("not a regular file")
	errTooLarge   = errors.New("item larger than its limit")
	errNotOwned   = errors.New("item not owned by the agent")
	errChanged    = errors.New("item changed while being read")
	errReplaced   = errors.New("item replaced after it was read")
)

// itemName matches what publish creates: 20 digits of Unix nanoseconds, a
// dash, 32 hex characters.
var itemName = regexp.MustCompile(`^([0-9]{20})-([0-9a-f]{32})\.json$`)

// SpoolOptions configures a Spool. Everything with a side effect is injectable.
type SpoolOptions struct {
	// Dir is the spool directory (spool.dir).
	Dir string
	// MaxBytes is the hard cap on real disk use (spool.max_mb).
	MaxBytes int64
	// MaxEventAge is spool.max_event_days.
	MaxEventAge time.Duration
	// AgentUID is the uid that must own the spool; -1 when unknown. `run`
	// passes its own uid. `event` runs as clamd's user and cannot know it, so it
	// only demands that the spool and spool/events share an owner.
	AgentUID int
	// Now is the only clock.
	Now func() time.Time
	FS  spoolFS
	Log *slog.Logger
	// LockWait bounds the usage-lock wait (default 2 s); Sleep is the pause
	// between attempts (default time.Sleep). Both are injectable so a test
	// holding the lock needs no real 2 s.
	LockWait time.Duration
	Sleep    func(time.Duration)
	// NewID returns 32 lowercase hex characters (default: crypto/rand).
	NewID func() string
}

// Queue is an opened spool directory (named Queue because Spool is the config section).
type Queue struct {
	o    SpoolOptions
	root spoolRoot
	// runLock is held by `run` for the life of the process.
	runLock spoolFile
}

func (o *SpoolOptions) defaults() {
	if o.FS == nil {
		o.FS = osFS{}
	}
	if o.LockWait == 0 {
		o.LockWait = defaultLockWait
	}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
	if o.NewID == nil {
		o.NewID = randomID
	}
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

// randomID returns 16 random bytes as 32 lowercase hex characters.
func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on Linux (getrandom); if it ever does, an
		// id that is not unique would corrupt deduplication, so stop.
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// checkDir applies the checks common to both sides to an Lstat result.
func (o *SpoolOptions) checkDir(fi fs.FileInfo, wantUID int) (statInfo, error) {
	st, ok := statOf(fi)
	if !ok || fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return st, ErrNotOurSpool
	}
	if wantUID >= 0 && int(st.UID) != wantUID {
		return st, ErrNotOurSpool
	}
	return st, nil
}

// openSpoolRoot opens dir and proves the root is the directory that was
// Lstat'ed, which closes the window between "checked a path" and "opened it".
func openSpoolRoot(o SpoolOptions, spoolStat statInfo) (spoolRoot, error) {
	root, err := o.FS.OpenRoot(o.Dir)
	if err != nil {
		return nil, fmt.Errorf("open spool: %w", err)
	}
	fi, err := root.Stat()
	st, ok := statOf(fi)
	if err != nil || !ok || st.ID != spoolStat.ID {
		root.Close()
		return nil, ErrNotOurSpool
	}
	return root, nil
}

// OpenSpoolForEvent opens the spool as the `event` command: it never creates
// anything. It refuses (ErrNotOurSpool) unless spool/ and spool/events are real
// directories, not symlinks, with the same owner; spool/ is not world-writable
// and spool/events is sticky and closed to others (mode 3770), because the
// sticky bit is what stops clamd's group deleting items it did not write.
func OpenSpoolForEvent(o SpoolOptions) (*Queue, error) {
	o.defaults()
	spFI, err := o.FS.Lstat(o.Dir)
	if err != nil {
		return nil, fmt.Errorf("spool: %w", err)
	}
	spSt, err := o.checkDir(spFI, o.AgentUID)
	if err != nil || spFI.Mode().Perm()&0o002 != 0 {
		return nil, ErrNotOurSpool
	}
	evFI, err := o.FS.Lstat(o.Dir + "/" + dirEvents)
	if err != nil {
		return nil, fmt.Errorf("spool/events: %w", err)
	}
	evSt, err := o.checkDir(evFI, int(spSt.UID))
	if err != nil || evFI.Mode()&fs.ModeSticky == 0 || evFI.Mode().Perm()&0o007 != 0 {
		return nil, ErrNotOurSpool
	}
	root, err := openSpoolRoot(o, spSt)
	if err != nil {
		return nil, err
	}
	// events could have been swapped for a symlink since the Lstat above.
	fi, err := root.Lstat(dirEvents)
	st, ok := statOf(fi)
	if err != nil || !ok || st.ID != evSt.ID || fi.Mode()&fs.ModeSymlink != 0 {
		root.Close()
		return nil, ErrNotOurSpool
	}
	return &Queue{o: o, root: root}, nil
}

// OpenSpoolForRun opens the spool as the agent service. The spool directory
// itself must exist (the installer creates it with the right owner and group);
// the subdirectories, the usage file and the run lock are created or repaired
// here. It takes the single-instance lock.
func OpenSpoolForRun(o SpoolOptions) (*Queue, error) {
	o.defaults()
	fi, err := o.FS.Lstat(o.Dir)
	if err != nil {
		return nil, fmt.Errorf("spool %s: %w", o.Dir, err)
	}
	st, err := o.checkDir(fi, o.AgentUID)
	if err != nil || fi.Mode().Perm()&0o002 != 0 {
		return nil, fmt.Errorf("%w: %s", ErrNotOurSpool, o.Dir)
	}
	root, err := openSpoolRoot(o, st)
	if err != nil {
		return nil, err
	}
	s := &Queue{o: o, root: root}
	if err := s.ensureLayout(); err != nil {
		root.Close()
		return nil, err
	}
	lock, err := root.OpenFile(fileRunLock, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("spool lock: %w", err)
	}
	if err := lock.Flock(syscall.LOCK_EX | syscall.LOCK_NB); err != nil {
		lock.Close()
		root.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("spool lock: %w", err)
	}
	s.runLock = lock
	return s, nil
}

// ensureLayout creates or repairs the subdirectories and the usage file.
func (s *Queue) ensureLayout() error {
	for _, d := range []struct {
		name string
		mode fs.FileMode
	}{
		// events: clamd's user creates files (group write, setgid for the group),
		// and the sticky bit keeps it from removing what it did not write.
		{dirEvents, 0o770 | fs.ModeSetgid | fs.ModeSticky},
		{dirReports, 0o700},
		{dirQuarantine, 0o700},
	} {
		fi, err := s.root.Lstat(d.name)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := s.root.Mkdir(d.name, 0o700); err != nil {
				return fmt.Errorf("create spool/%s: %w", d.name, err)
			}
		case err != nil:
			return fmt.Errorf("spool/%s: %w", d.name, err)
		default:
			st, ok := statOf(fi)
			if !ok || !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 || (s.o.AgentUID >= 0 && int(st.UID) != s.o.AgentUID) {
				return fmt.Errorf("%w: spool/%s", ErrNotOurSpool, d.name)
			}
			if fi.Mode()&(fs.ModePerm|fs.ModeSetgid|fs.ModeSticky) == d.mode {
				continue
			}
		}
		if err := s.root.Chmod(d.name, d.mode); err != nil {
			return fmt.Errorf("chmod spool/%s: %w", d.name, err)
		}
	}
	// The usage file is created here, by the owner, so `event` (which never
	// creates anything) only ever opens it.
	f, err := s.root.OpenFile(fileUsage, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o660)
	if err != nil {
		return fmt.Errorf("spool usage file: %w", err)
	}
	defer f.Close()
	// umask-proof: clamd's group must be able to read and write it.
	if err := f.Chmod(0o660); err != nil {
		return fmt.Errorf("spool usage file: %w", err)
	}
	// A fresh (empty) file would read as corrupt and make `event` fall back to
	// counting the directory, so give it a record. The first recount corrects it.
	if fi, err := f.Stat(); err == nil && fi.Size() == 0 {
		return writeUsage(f, usageRec{At: s.o.Now().Unix()})
	}
	return nil
}

// Close releases the root and the run lock.
func (s *Queue) Close() error {
	if s.runLock != nil {
		s.runLock.Close()
	}
	return s.root.Close()
}

// itemPath is the path of an item relative to the spool root.
func itemPath(dir, name string) string { return dir + "/" + name }

// ----- publish -----

// PublishResult is the outcome of a publish that created the item.
type PublishResult struct {
	Name string
	// SyncErr is non-nil when the item exists but the directory fsync failed:
	// its durability across power loss is unconfirmed. The item is kept (it may
	// well be sent), and the caller reports it.
	SyncErr error
}

// publish writes body to dir under a new unique name, with this protocol
// (milestone 5, section 4.3). Every step is a separate call on the seam, so a
// test can see the order and inject a failure:
//
//  1. create .tmp-<id> with O_EXCL|O_NOFOLLOW, then fchmod 0640 (umask-proof);
//  2. write the whole body;
//  3. fsync the file (never retried: after a failed fsync the page cache state
//     is unknown, and a retry could report success for data that is lost);
//  4. close;
//  5. link(tmp, final): no-replace by construction (EEXIST), so an existing
//     item is never overwritten, unlike rename();
//  6. remove tmp (a failure only leaves a second name, cleaned up later);
//  7. fsync the directory.
//
// A reader never sees a partial file: the final name appears only after the
// content is on disk. On any failure before step 5 no final name exists and
// the temp file is removed.
func (s *Queue) publish(dir, id string, body []byte) (PublishResult, error) {
	tmp := itemPath(dir, tmpPrefix+s.o.NewID())
	f, err := s.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return PublishResult{}, fmt.Errorf("create temp file: %w", err)
	}
	fail := func(step string, err error) (PublishResult, error) {
		f.Close()
		s.root.Remove(tmp)
		return PublishResult{}, fmt.Errorf("%s: %w", step, err)
	}
	if err := f.Chmod(0o600); err != nil {
		return fail("chmod temp file", err)
	}
	n, err := f.Write(body)
	if err == nil && n < len(body) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fail("write", err)
	}
	if err := f.Sync(); err != nil {
		return fail("fsync", err)
	}
	if err := f.Close(); err != nil {
		s.root.Remove(tmp)
		return PublishResult{}, fmt.Errorf("close: %w", err)
	}
	base := s.o.Now().UnixNano()
	var final string
	linked := false
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("%020d-%s.json", base+int64(i), id)
		err := s.root.Link(tmp, itemPath(dir, name))
		if err == nil {
			final, linked = name, true
			break
		}
		if !errors.Is(err, fs.ErrExist) {
			s.root.Remove(tmp)
			return PublishResult{}, fmt.Errorf("link: %w", err)
		}
	}
	if !linked {
		s.root.Remove(tmp)
		return PublishResult{}, errors.New("link: no free item name after 5 tries")
	}
	if err := s.root.Remove(tmp); err != nil {
		s.o.Log.Warn("spool: temp file not removed after publish; cleanup will remove it", "error", err.Error())
	}
	res := PublishResult{Name: final}
	if err := s.root.SyncDir(dir); err != nil {
		res.SyncErr = err
	}
	return res, nil
}

// AddEvent admits and publishes one event: the whole write side of the event
// command. If the publish fails the admitted room is given back.
func (s *Queue) AddEvent(ev proto.Event) (PublishResult, error) {
	if ev.ID == nil {
		return PublishResult{}, errors.New("event without an id")
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return PublishResult{}, fmt.Errorf("encode event: %w", err)
	}
	refund, err := s.AdmitEvent(len(body))
	if err != nil {
		return PublishResult{}, err
	}
	res, err := s.publish(dirEvents, *ev.ID, body)
	if err != nil {
		refund()
		return PublishResult{}, err
	}
	return res, nil
}

// ----- accounting -----

// usageRec is the content of spool/usage.
type usageRec struct {
	Total int64 `json:"total"`
	Base  int64 `json:"base"`
	At    int64 `json:"at"`
}

var errNoUsage = errors.New("usage file missing or corrupt")

// lockUsage opens spool/usage and takes its exclusive lock, retrying for up to
// LockWait (ErrSpoolBusy after that). A missing or unreadable file is
// errNoUsage; an event never creates it. The caller closes the file, which
// also drops the lock.
func (s *Queue) lockUsage() (spoolFile, usageRec, error) {
	f, err := s.root.OpenFile(fileUsage, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, usageRec{}, errNoUsage
		}
		return nil, usageRec{}, fmt.Errorf("spool usage file: %w", err)
	}
	deadline := s.o.Now().Add(s.o.LockWait)
	for {
		err := f.Flock(syscall.LOCK_EX | syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, usageRec{}, fmt.Errorf("spool usage lock: %w", err)
		}
		if !s.o.Now().Before(deadline) {
			f.Close()
			return nil, usageRec{}, ErrSpoolBusy
		}
		s.o.Sleep(10 * time.Millisecond)
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4096))
	var rec usageRec
	if err != nil || json.Unmarshal(raw, &rec) != nil || rec.Total < 0 || rec.Base < 0 {
		return f, usageRec{}, errNoUsage
	}
	return f, rec, nil
}

func writeUsage(f spoolFile, rec usageRec) error {
	b, _ := json.Marshal(rec)
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err := f.Write(b)
	return err
}

func roundUp(n int64) int64 { return (n + blockEstimate - 1) / blockEstimate * blockEstimate }

// AdmitEvent reserves room for an event of bodyLen bytes. It is O(1): one
// small file under a lock, no directory scan, because clamd waits for it.
// ErrSpoolFull when the cap would be exceeded, ErrSpoolBusy when the lock is
// not obtained in time. The returned refund gives the room back when the
// publish that follows fails.
func (s *Queue) AdmitEvent(bodyLen int) (refund func(), err error) {
	est := roundUp(int64(bodyLen))
	f, rec, err := s.lockUsage()
	switch {
	case errors.Is(err, errNoUsage):
		if f != nil {
			// Corrupt but lockable: count, and leave the repair to `run`.
			defer f.Close()
		}
		n, cerr := s.fallbackCount()
		if cerr != nil || n*blockEstimate+est > s.o.MaxBytes {
			return nil, ErrSpoolFull
		}
		s.o.Log.Warn("spool usage file missing or corrupt: counting entries; the agent service will rewrite it")
		return func() {}, nil
	case err != nil:
		return nil, err
	}
	defer f.Close()
	if rec.Total+est > s.o.MaxBytes {
		return nil, ErrSpoolFull
	}
	rec.Total += est
	if err := writeUsage(f, rec); err != nil {
		return nil, fmt.Errorf("spool usage file: %w", err)
	}
	return func() { s.addUsage(-est) }, nil
}

// addUsage adjusts the running total by delta, best effort: the next recount
// corrects any error.
func (s *Queue) addUsage(delta int64) {
	f, rec, err := s.lockUsage()
	if err != nil {
		if f != nil {
			f.Close()
		}
		return
	}
	defer f.Close()
	rec.Total += delta
	if rec.Total < 0 {
		rec.Total = 0
	}
	_ = writeUsage(f, rec)
}

// fallbackCount counts the entries of events/, reading at most
// fallbackMaxEntries; beyond that the error says "too many".
func (s *Queue) fallbackCount() (int64, error) {
	d, err := s.root.OpenDir(dirEvents)
	if err != nil {
		return 0, err
	}
	defer d.Close()
	var n int64
	for {
		ents, err := d.ReadDir(readDirChunk)
		n += int64(len(ents))
		if n > fallbackMaxEntries {
			return n, errors.New("too many entries")
		}
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}

// Usage returns the recorded total and the base of the last recount.
func (s *Queue) Usage() (total, base int64, err error) {
	f, rec, err := s.lockUsage()
	if f != nil {
		f.Close()
	}
	return rec.Total, rec.Base, err
}

// scanUsage sums st_blocks*512 of every entry under the spool: items, temp
// files, junk names, quarantine, and the accounting file itself. Real blocks,
// not sizes: a 300-byte file occupies a block.
func (s *Queue) scanUsage() (int64, error) {
	var total int64
	add := func(name string) {
		if fi, err := s.root.Lstat(name); err == nil {
			if st, ok := statOf(fi); ok {
				total += st.Blocks * 512
			}
		}
	}
	add(fileUsage)
	add(fileRunLock)
	for _, dir := range []string{dirEvents, dirReports, dirQuarantine} {
		d, err := s.root.OpenDir(dir)
		if err != nil {
			return 0, err
		}
		for {
			ents, err := d.ReadDir(readDirChunk)
			for _, e := range ents {
				add(itemPath(dir, e.Name()))
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				d.Close()
				return 0, err
			}
		}
		d.Close()
	}
	return total, nil
}

// Recount computes the true usage and stores it. It scans without the lock
// (scanning is slow) and then, under the lock, adds whatever `event` admitted
// while the scan ran: those items may be missing from the scan, and losing
// them would let the cap be exceeded. total = computed + admitted-during-scan,
// base = computed.
func (s *Queue) Recount() error {
	f, before, err := s.lockUsage()
	if f != nil {
		f.Close()
	}
	if err != nil && !errors.Is(err, errNoUsage) {
		return err
	}
	computed, err := s.scanUsage()
	if err != nil {
		return err
	}
	f, after, err := s.lockUsage()
	if f == nil {
		return err
	}
	defer f.Close()
	during := after.Total - before.Total
	if errors.Is(err, errNoUsage) || during < 0 {
		during = 0
	}
	return writeUsage(f, usageRec{Total: computed + during, Base: computed, At: s.o.Now().Unix()})
}

// PutReport stores a heartbeat. Under the usage lock it evicts the OLDEST
// reports (never events) until the report fits; if it still does not fit it
// returns ErrSpoolFull and the report is not spooled. replay is never stored:
// the agent decides it at send time.
func (s *Queue) PutReport(r proto.Report) error {
	r.Replay = false
	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	est := roundUp(int64(len(body)))
	f, rec, err := s.lockUsage()
	if err != nil {
		if f != nil {
			f.Close()
		}
		if errors.Is(err, errNoUsage) {
			// run owns this file: recount rewrites it, then retry once.
			if rerr := s.Recount(); rerr != nil {
				return rerr
			}
			f, rec, err = s.lockUsage()
		}
		if err != nil {
			if f != nil {
				f.Close()
			}
			return err
		}
	}
	for rec.Total+est > s.o.MaxBytes {
		freed, ok := s.evictOldestReport()
		if !ok {
			f.Close()
			return ErrSpoolFull
		}
		rec.Total -= freed
		if rec.Total < 0 {
			rec.Total = 0
		}
	}
	rec.Total += est
	err = writeUsage(f, rec)
	f.Close()
	if err != nil {
		return fmt.Errorf("spool usage file: %w", err)
	}
	if _, err := s.publish(dirReports, s.o.NewID(), body); err != nil {
		s.addUsage(-est)
		return err
	}
	return nil
}

// evictOldestReport removes the oldest report and returns the bytes it freed.
func (s *Queue) evictOldestReport() (int64, bool) {
	l, err := s.List(dirReports, listSpec{oldest: 1})
	if err != nil || len(l.Oldest) == 0 {
		return 0, false
	}
	p := itemPath(dirReports, l.Oldest[0])
	// Subtract what admission added (the size rounded up to a block), not the
	// real blocks: the running total is made of estimates until the next
	// recount, and mixing the two would drift on filesystems whose allocation
	// unit is not 4 KiB.
	var freed int64
	if fi, err := s.root.Lstat(p); err == nil {
		freed = roundUp(fi.Size())
	}
	if err := s.root.Remove(p); err != nil {
		return 0, false
	}
	return freed, true
}

// ----- listing -----

// listSpec says how many names List keeps.
type listSpec struct {
	// oldest names are kept in ascending order.
	oldest int
	// newest names are kept in descending order; with freshAge > 0 only those
	// younger than freshAge qualify.
	newest   int
	freshAge time.Duration
}

// listing is the bounded view of a directory.
type listing struct {
	Oldest []string
	Newest []string
	// Junk are regular-looking entries whose name is not an item name (bounded).
	Junk []string
	// Total is how many entries were read, temp files included (Sweep handles
	// those by age).
	Total int
}

// nameTime returns the time encoded in an item name.
func nameTime(name string) (time.Time, bool) {
	m := itemName.FindStringSubmatch(name)
	if m == nil {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, n), true
}

// List reads dir in chunks of readDirChunk entries and keeps only the names
// the spec asks for, so memory stays bounded however many entries exist.
// Names sort by their embedded time because the digits are zero-padded.
func (s *Queue) List(dir string, sp listSpec) (listing, error) {
	d, err := s.root.OpenDir(dir)
	if err != nil {
		return listing{}, err
	}
	defer d.Close()
	var l listing
	now := s.o.Now()
	for {
		ents, err := d.ReadDir(readDirChunk)
		for _, e := range ents {
			l.Total++
			name := e.Name()
			t, ok := nameTime(name)
			switch {
			case !ok:
				if len(name) >= len(tmpPrefix) && name[:len(tmpPrefix)] == tmpPrefix {
					continue
				}
				if len(l.Junk) < 64 {
					l.Junk = append(l.Junk, name)
				}
			default:
				l.Oldest = append(l.Oldest, name)
				if sp.newest > 0 && (sp.freshAge == 0 || now.Sub(t) < sp.freshAge) {
					l.Newest = append(l.Newest, name)
				}
			}
		}
		// Trim after each chunk: sort and cut to the bound.
		if len(l.Oldest) > sp.oldest {
			sort.Strings(l.Oldest)
			l.Oldest = l.Oldest[:sp.oldest]
		}
		if len(l.Newest) > sp.newest {
			sort.Sort(sort.Reverse(sort.StringSlice(l.Newest)))
			l.Newest = l.Newest[:sp.newest]
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return l, err
		}
	}
	sort.Strings(l.Oldest)
	sort.Sort(sort.Reverse(sort.StringSlice(l.Newest)))
	return l, nil
}

// ----- reading, deleting, quarantine -----

// ReadItem reads one item defensively. clamd's group can put anything in
// spool/events, so, in order:
//  1. Lstat the name: only a regular file is ever opened. A symlink, FIFO,
//     socket or device is removed and errNonRegular returned.
//  2. nlink > 1: a publish is in progress (or crashed between link and
//     remove), or the name is a hardlink to a file elsewhere. Younger than 10
//     minutes: errSkip. Older: the NAME is unlinked (the other name and its
//     file are untouched) and errSkip returned.
//  3. Open with O_NOFOLLOW|O_NONBLOCK and fstat: it must be the very file
//     Lstat saw (same device and inode) and still nlink 1. O_NONBLOCK makes a
//     FIFO swapped in at the last moment fail the check instead of hanging.
//  4. Read at most limit bytes (one more is read to detect an overlong item).
//  5. In reports/ and quarantine/ the file must be owned by the agent.
//
// It returns the bytes and the identity to give Delete or Quarantine. EACCES
// comes back as fs.ErrPermission, ENOENT as fs.ErrNotExist.
func (s *Queue) ReadItem(dir, name string, limit int) ([]byte, fileID, error) {
	p := itemPath(dir, name)
	fi, err := s.root.Lstat(p)
	if err != nil {
		return nil, fileID{}, err
	}
	if !fi.Mode().IsRegular() {
		if err := s.root.Remove(p); err != nil {
			return nil, fileID{}, fmt.Errorf("remove non-regular entry: %w", err)
		}
		s.o.Log.Warn("spool: removed a non-regular entry", "dir", dir)
		return nil, fileID{}, errNonRegular
	}
	st, ok := statOf(fi)
	if !ok {
		return nil, fileID{}, errChanged
	}
	if st.Nlink > 1 {
		if s.o.Now().Sub(fi.ModTime()) >= publishInProgress {
			if err := s.root.Remove(p); err == nil {
				s.o.Log.Warn("spool: removed an entry with several hard links", "dir", dir)
			}
		}
		return nil, fileID{}, errSkip
	}
	f, err := s.root.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fileID{}, err
	}
	defer f.Close()
	ofi, err := f.Stat()
	if err != nil {
		return nil, fileID{}, err
	}
	ost, ok := statOf(ofi)
	if !ok || !ofi.Mode().IsRegular() || ost.ID != st.ID || ost.Nlink != 1 {
		s.o.Log.Warn("spool: an entry changed while being read; it will be read again", "dir", dir)
		return nil, fileID{}, errChanged
	}
	if dir != dirEvents && s.o.AgentUID >= 0 && int(ost.UID) != s.o.AgentUID {
		return nil, ost.ID, errNotOwned
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fileID{}, err
	}
	if len(data) > limit {
		return nil, ost.ID, errTooLarge
	}
	return data, ost.ID, nil
}

// sameFile re-checks that name still is the file with identity id.
func (s *Queue) sameFile(p string, id fileID) bool {
	fi, err := s.root.Lstat(p)
	if err != nil {
		return false
	}
	st, ok := statOf(fi)
	return ok && st.ID == id && fi.Mode().IsRegular()
}

// Delete removes an item after it was delivered. It Lstats again and compares
// the identity with the one ReadItem saw: an item replaced in between is left
// alone (errReplaced) and will be read again. Linux has no unlink-by-fd, so a
// gap between this check and the unlink remains; only clamd's group could use
// it, and the worst result is one lost, re-creatable item (docs/detections.md).
func (s *Queue) Delete(dir, name string, id fileID) error {
	p := itemPath(dir, name)
	if !s.sameFile(p, id) {
		s.o.Log.Warn("spool: an item was replaced after it was read; left for the next pass", "dir", dir)
		return errReplaced
	}
	if err := s.root.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Quarantine moves an invalid item to spool/quarantine under a fresh name, with
// the same replaced-after-read check as Delete.
func (s *Queue) Quarantine(dir, name string, id fileID) error {
	p := itemPath(dir, name)
	if !s.sameFile(p, id) {
		s.o.Log.Warn("spool: an item was replaced after it was read; left for the next pass", "dir", dir)
		return errReplaced
	}
	dst := itemPath(dirQuarantine, fmt.Sprintf("%020d-%s.json", s.o.Now().UnixNano(), s.o.NewID()))
	return s.root.Rename(p, dst)
}

// RemoveName removes an entry by name without reading it (junk names in
// events/ that cannot be items); non-regular entries and hardlinks are
// removed too, since removing a name never touches another file.
func (s *Queue) RemoveName(dir, name string) error {
	return s.root.Remove(itemPath(dir, name))
}

// QuarantineJunk moves a regular file with an unexpected name aside, after
// confirming it is a regular, single-link file; anything else is removed.
func (s *Queue) QuarantineJunk(dir, name string) error {
	p := itemPath(dir, name)
	fi, err := s.root.Lstat(p)
	if err != nil {
		return err
	}
	if st, ok := statOf(fi); !fi.Mode().IsRegular() || !ok || st.Nlink > 1 {
		return s.root.Remove(p)
	}
	dst := itemPath(dirQuarantine, fmt.Sprintf("%020d-%s.json", s.o.Now().UnixNano(), s.o.NewID()))
	return s.root.Rename(p, dst)
}

// ----- cleanup -----

// SweepResult counts what Sweep removed, for the log line.
type SweepResult struct {
	Temp, Reports, Quarantine int
}

// Sweep applies the time- and count-based rules that need no content:
//   - temp files older than 10 minutes (a crashed publish);
//   - reports older than 7 days (a heartbeat that old is noise);
//   - quarantine files older than 30 days, and the oldest beyond 100.
//
// Spooled events are NOT touched here: they expire by their own ts after
// spool.max_event_days, which needs their content (drain.go).
func (s *Queue) Sweep() SweepResult {
	var res SweepResult
	now := s.o.Now()
	for _, dir := range []string{dirEvents, dirReports} {
		res.Temp += s.removeOld(dir, func(name string, fi fs.FileInfo) bool {
			return len(name) >= len(tmpPrefix) && name[:len(tmpPrefix)] == tmpPrefix && now.Sub(fi.ModTime()) >= tmpMaxAge
		})
	}
	res.Reports = s.removeOld(dirReports, func(name string, fi fs.FileInfo) bool {
		t, ok := nameTime(name)
		return ok && now.Sub(t) >= reportMaxAge
	})
	res.Quarantine = s.removeOld(dirQuarantine, func(name string, fi fs.FileInfo) bool {
		return now.Sub(fi.ModTime()) >= quarantineMaxAge
	})
	// Count cap: the oldest names beyond quarantineMaxN go.
	if l, err := s.List(dirQuarantine, listSpec{oldest: 1 << 20}); err == nil && len(l.Oldest)+len(l.Junk) > quarantineMaxN {
		all := append(append([]string{}, l.Oldest...), l.Junk...)
		sort.Strings(all)
		for _, n := range all[:len(all)-quarantineMaxN] {
			if s.root.Remove(itemPath(dirQuarantine, n)) == nil {
				res.Quarantine++
			}
		}
	}
	return res
}

// removeOld removes the entries of dir for which due returns true.
func (s *Queue) removeOld(dir string, due func(name string, fi fs.FileInfo) bool) int {
	d, err := s.root.OpenDir(dir)
	if err != nil {
		return 0
	}
	defer d.Close()
	n := 0
	for {
		ents, err := d.ReadDir(readDirChunk)
		for _, e := range ents {
			fi, lerr := s.root.Lstat(itemPath(dir, e.Name()))
			if lerr != nil {
				continue
			}
			if due(e.Name(), fi) && s.root.Remove(itemPath(dir, e.Name())) == nil {
				n++
			}
		}
		if err != nil {
			return n
		}
	}
}
