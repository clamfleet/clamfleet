// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// spoolfs.go: the filesystem seam of the spool.
//
// Responsibilities: the spoolFS, spoolRoot and spoolFile interfaces, and their
// production implementation on os.Root and the syscall package. Every spool
// operation goes through them, relative to a directory opened once, so that
//   - a test can record the exact call sequence (a missing fsync fails a test),
//     inject an error at any step, and run a hook between two steps to stage a
//     race (a symlink swapped in after the Lstat);
//   - a path under the spool can never be resolved outside it: os.Root refuses
//     symlinks that leave the root, which matters because clamd's group can
//     create entries in spool/events.
//
// Dependencies: the standard library only (CGO_ENABLED=0 safe: syscall.Flock).

package agent

import (
	"io/fs"
	"os"
	"syscall"
)

// spoolFS opens roots. It is the only thing that touches a path by name.
type spoolFS interface {
	// OpenRoot opens dir as a Root. dir itself is resolved with symlinks
	// followed, so callers Lstat it first and compare identities (spool.go).
	OpenRoot(dir string) (spoolRoot, error)
	// Lstat is Lstat of an absolute path, without following a final symlink.
	Lstat(path string) (fs.FileInfo, error)
}

// spoolRoot is a directory opened for relative access.
type spoolRoot interface {
	// Stat is the Stat of the root directory itself (the open fd, not the path).
	Stat() (fs.FileInfo, error)
	Lstat(name string) (fs.FileInfo, error)
	OpenFile(name string, flag int, perm fs.FileMode) (spoolFile, error)
	// Link creates newname as a second name of oldname. It fails with EEXIST
	// when newname exists: a no-replace publish by construction.
	Link(oldname, newname string) error
	Remove(name string) error
	Rename(oldname, newname string) error
	// Mkdir and Chmod are used only by `run`, which owns the spool and creates
	// or repairs its subdirectories.
	Mkdir(name string, perm fs.FileMode) error
	Chmod(name string, mode fs.FileMode) error
	// SyncDir fsyncs the directory name (".", or a subdirectory) so a created
	// or linked entry survives power loss.
	SyncDir(name string) error
	// OpenDir opens a directory for chunked reading.
	OpenDir(name string) (dirReader, error)
	Close() error
}

// dirReader reads a directory in chunks, so a directory with a million
// entries never sits in memory at once.
type dirReader interface {
	ReadDir(n int) ([]fs.DirEntry, error)
	Close() error
}

// spoolFile is an open file.
type spoolFile interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
	Sync() error
	Stat() (fs.FileInfo, error)
	// Chmod is fchmod: umask-proof, applied to the open file.
	Chmod(mode fs.FileMode) error
	Truncate(size int64) error
	Seek(offset int64, whence int) (int64, error)
	// Flock takes or drops an advisory lock (syscall.LOCK_EX|LOCK_NB, LOCK_UN).
	Flock(how int) error
}

// osFS is the production seam.
type osFS struct{}

func (osFS) OpenRoot(dir string) (spoolRoot, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return osRoot{r}, nil
}

func (osFS) Lstat(path string) (fs.FileInfo, error) { return os.Lstat(path) }

type osRoot struct{ r *os.Root }

func (o osRoot) Stat() (fs.FileInfo, error)                { return o.r.Stat(".") }
func (o osRoot) Lstat(name string) (fs.FileInfo, error)    { return o.r.Lstat(name) }
func (o osRoot) Link(oldname, newname string) error        { return o.r.Link(oldname, newname) }
func (o osRoot) Remove(name string) error                  { return o.r.Remove(name) }
func (o osRoot) Rename(oldname, newname string) error      { return o.r.Rename(oldname, newname) }
func (o osRoot) Mkdir(name string, perm fs.FileMode) error { return o.r.Mkdir(name, perm) }
func (o osRoot) Chmod(name string, mode fs.FileMode) error { return o.r.Chmod(name, mode) }
func (o osRoot) Close() error                              { return o.r.Close() }

func (o osRoot) OpenFile(name string, flag int, perm fs.FileMode) (spoolFile, error) {
	f, err := o.r.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return osFile{f}, nil
}

func (o osRoot) SyncDir(name string) error {
	d, err := o.r.Open(name)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

func (o osRoot) OpenDir(name string) (dirReader, error) {
	d, err := o.r.Open(name)
	if err != nil {
		return nil, err
	}
	return d, nil
}

type osFile struct{ *os.File }

func (f osFile) Flock(how int) error {
	// Fd() switches the file to blocking mode, which is harmless for the
	// regular files we lock; the lock is released when the file is closed.
	return syscall.Flock(int(f.File.Fd()), how)
}

// fileID identifies a file on a filesystem; two opens of the same file give the
// same fileID, and a replaced file gives a different one.
type fileID struct {
	Dev, Ino uint64
}

// statInfo is the part of a Stat the spool cares about.
type statInfo struct {
	ID     fileID
	Nlink  uint64
	UID    uint32
	Blocks int64 // 512-byte units, as st_blocks
	Mode   fs.FileMode
}

// statOf extracts the Unix fields. ok is false when the FileInfo does not come
// from a Unix stat (never the case on Linux); callers then fail closed.
func statOf(fi fs.FileInfo) (statInfo, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return statInfo{}, false
	}
	return statInfo{
		ID:     fileID{Dev: uint64(st.Dev), Ino: st.Ino},
		Nlink:  uint64(st.Nlink),
		UID:    st.Uid,
		Blocks: st.Blocks,
		Mode:   fi.Mode(),
	}, true
}
