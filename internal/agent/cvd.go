// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// cvd.go: reads the signature databases (daily, main, bytecode) of ClamAV.
//
// Responsibilities: parse the 512-byte header of a .cvd/.cld file into
// proto.SigDB (version, signature count, build time), pick the newer of a
// .cvd/.cld pair, and give the modification time of daily.* as freshclam's
// last-resort "last ok" time.
// Dependencies: the filesystem and the proto package. Reads the header only,
// never the signatures, so it is cheap and needs no ClamAV tools.

package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// cvdHeaderSize is how much of a .cvd/.cld file holds the header (spec 6.2).
const cvdHeaderSize = 512

// cvdTimeLayout is the human-readable build time in header field 1, e.g.
// "16 Sep 2021 08-32 -0400". Used only when the numeric stime field is absent.
const cvdTimeLayout = "02 Jan 2006 15-04 -0700"

// sigDBNames are the official databases the report covers (spec 7.3).
// Third-party databases and *.sign files in the same directory are ignored by
// looking up exact file names only.
var sigDBNames = []string{"daily", "main", "bytecode"}

// ParseCVDHeader parses the header of a .cvd or .cld file (the first 512
// bytes, or less for a truncated file).
//
// Assumption A8, confirmed against Debian 13 files: the header is
// colon-separated, "ClamAV-VDB:<time>:<version>:<sigs>:<f-level>:<md5>:<dsig>:<builder>:<stime>",
// space/NUL padded to 512 bytes. Built is stime (unix seconds, field 8) when
// present and numeric, because it has second resolution and no zone to
// misread; otherwise the time string of field 1.
func ParseCVDHeader(b []byte) (proto.SigDB, error) {
	text := strings.Trim(string(b), " \x00\r\n\t")
	f := strings.Split(text, ":")
	if f[0] != "ClamAV-VDB" {
		return proto.SigDB{}, errors.New("not a ClamAV database header (bad magic)")
	}
	if len(f) < 4 {
		return proto.SigDB{}, fmt.Errorf("header has %d fields, need at least 4", len(f))
	}
	version, err := strconv.Atoi(f[2])
	if err != nil {
		return proto.SigDB{}, fmt.Errorf("invalid version %q", f[2])
	}
	sigs, err := strconv.ParseInt(f[3], 10, 64)
	if err != nil {
		return proto.SigDB{}, fmt.Errorf("invalid signature count %q", f[3])
	}
	var built time.Time
	if len(f) > 8 {
		if sec, err := strconv.ParseInt(strings.TrimSpace(f[8]), 10, 64); err == nil {
			built = time.Unix(sec, 0)
		}
	}
	if built.IsZero() {
		t, err := time.Parse(cvdTimeLayout, f[1])
		if err != nil {
			return proto.SigDB{}, fmt.Errorf("no usable build time (stime missing, time string %q invalid)", f[1])
		}
		built = t
	}
	return proto.SigDB{Version: version, Built: proto.UTC(built), Sigs: sigs}, nil
}

// readCVD reads and parses one database file.
func readCVD(path string) (proto.SigDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return proto.SigDB{}, err
	}
	defer f.Close()
	buf := make([]byte, cvdHeaderSize)
	n, err := io.ReadFull(f, buf)
	// A short file is parsed as far as it goes; the parser then rejects it
	// if the header is incomplete.
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return proto.SigDB{}, err
	}
	return ParseCVDHeader(buf[:n])
}

// lookupSigDB finds <name>.cvd and <name>.cld in dir. When both exist and
// parse, the higher version wins, as clamd does (assumption A9, not verified
// on a live host: no .cld was captured, see testdata/README.md). A missing
// file is not a problem (nil, no problems); an unreadable or invalid one is.
func lookupSigDB(dir, name string) (*proto.SigDB, []Problem) {
	var best *proto.SigDB
	var problems []Problem
	for _, ext := range []string{".cvd", ".cld"} {
		path := filepath.Join(dir, name+ext)
		db, err := readCVD(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			problems = append(problems, Problem{"sigs." + name, fmt.Errorf("%s: %w", path, err)})
		case best == nil || db.Version > best.Version:
			d := db
			best = &d
		}
	}
	return best, problems
}

// collectSigs reads the three official databases from dir.
func collectSigs(dir string) (proto.Sigs, []Problem) {
	var s proto.Sigs
	var problems []Problem
	for _, n := range sigDBNames {
		db, p := lookupSigDB(dir, n)
		problems = append(problems, p...)
		switch n {
		case "daily":
			s.Daily = db
		case "main":
			s.Main = db
		case "bytecode":
			s.Bytecode = db
		}
	}
	return s, problems
}

// dailyMTime returns the newest modification time of daily.cvd/daily.cld, the
// last-resort stand-in for "freshclam last succeeded" (spec 6.2).
func dailyMTime(dir string) (time.Time, bool) {
	var newest time.Time
	for _, ext := range []string{".cvd", ".cld"} {
		if st, err := os.Stat(filepath.Join(dir, "daily"+ext)); err == nil && st.ModTime().After(newest) {
			newest = st.ModTime()
		}
	}
	return newest, !newest.IsZero()
}
