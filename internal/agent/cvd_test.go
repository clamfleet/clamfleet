// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sigtoolInfo parses the text "sigtool --info" printed in the container: the
// independent oracle for the header parser.
func sigtoolInfo(t *testing.T, b []byte) (version int, sigs int64, built time.Time) {
	t.Helper()
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		var err error
		switch k {
		case "Version":
			version, err = strconv.Atoi(v)
		case "Signatures":
			sigs, err = strconv.ParseInt(v, 10, 64)
		case "Build time":
			built, err = time.Parse("02 Jan 2006 15:04 -0700", v)
		}
		if err != nil {
			t.Fatalf("sigtool info: %s: %v", line, err)
		}
	}
	if version == 0 || sigs == 0 || built.IsZero() {
		t.Fatalf("incomplete sigtool info: %q", b)
	}
	return
}

func TestRecordedHeadersMatchSigtool(t *testing.T) {
	hdrs, err := filepath.Glob("testdata/cvd/*/*.hdr")
	if err != nil || len(hdrs) < 3 {
		t.Fatalf("expected recorded headers, got %v (%v)", hdrs, err)
	}
	for _, h := range hdrs {
		raw, err := os.ReadFile(h)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseCVDHeader(raw)
		if err != nil {
			t.Errorf("%s: %v", h, err)
			continue
		}
		wv, ws, wb := sigtoolInfo(t, fixture(t, strings.TrimPrefix(strings.TrimSuffix(h, ".hdr")+".info", "testdata/")))
		// sigtool prints the build time to the minute; stime has seconds.
		if got.Version != wv || got.Sigs != ws || !got.Built.Truncate(time.Minute).Equal(wb) {
			t.Errorf("%s: got %+v, sigtool says version=%d sigs=%d built=%s", h, got, wv, ws, wb)
		}
		if got.Built.Location() != time.UTC {
			t.Errorf("%s: Built is not UTC", h)
		}
	}
}

func TestParseCVDHeaderRejects(t *testing.T) {
	daily := fixture(t, "cvd/initial/daily.cvd.hdr")
	cases := map[string][]byte{
		"truncated": daily[:40],
		// The real recorded header with ONLY the magic changed: every other
		// field is valid, so only the magic check can reject it.
		"wrong magic":   bytes.Replace(daily, []byte("ClamAV-VDB"), []byte("NotClamAV!"), 1),
		"bad version":   []byte("ClamAV-VDB:16 Sep 2021 08-32 -0400:abc:100:90:md5:dsig:builder:1631795520"),
		"bad sig count": []byte("ClamAV-VDB:16 Sep 2021 08-32 -0400:62:many:90:md5:dsig:builder:1631795520"),
		"no time":       []byte("ClamAV-VDB:garbage:62:100:90:md5:dsig:builder"),
		"empty":         nil,
	}
	for name, in := range cases {
		if _, err := ParseCVDHeader(in); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseCVDHeaderFallsBackToTimeString(t *testing.T) {
	// No stime field (field 8): the zoned time string is used.
	got, err := ParseCVDHeader([]byte("ClamAV-VDB:16 Sep 2021 08-32 -0400:62:6647427:90:md5:dsig:builder"))
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2021, 9, 16, 12, 32, 0, 0, time.UTC); !got.Built.Equal(want) || got.Version != 62 {
		t.Fatalf("got %+v want built %s", got, want)
	}
}

func writeDB(t *testing.T, dir, file string, hdr []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, file), append(append([]byte{}, hdr...), make([]byte, 100)...), 0o600); err != nil {
		t.Fatal(err)
	}
}

var versionFieldRE = regexp.MustCompile(`^(ClamAV-VDB:[^:]*:)\d+`)

// withVersion rewrites the version field of a recorded header.
func withVersion(hdr []byte, v int) []byte {
	return versionFieldRE.ReplaceAll(hdr, []byte("${1}"+strconv.Itoa(v)))
}

func TestLookupPrefersHigherVersionOfCvdAndCld(t *testing.T) {
	hdr := fixture(t, "cvd/initial/daily.cvd.hdr") // version 28181
	dir := t.TempDir()
	writeDB(t, dir, "daily.cvd", hdr)
	writeDB(t, dir, "daily.cld", withVersion(hdr, 28190))
	if db, p := lookupSigDB(dir, "daily"); db == nil || db.Version != 28190 || len(p) != 0 {
		t.Fatalf("cld newer: got %+v %v", db, p)
	}
	writeDB(t, dir, "daily.cld", withVersion(hdr, 28100))
	if db, _ := lookupSigDB(dir, "daily"); db == nil || db.Version != 28181 {
		t.Fatalf("cvd newer: got %+v", db)
	}
}

func TestCollectSigsIgnoresSignFilesAndMissing(t *testing.T) {
	dir := t.TempDir()
	writeDB(t, dir, "daily.cvd.sign", []byte("junk"))
	writeDB(t, dir, "extra-third-party.cvd", fixture(t, "cvd/initial/main.cvd.hdr"))
	s, p := collectSigs(dir)
	if s.Daily != nil || s.Main != nil || s.Bytecode != nil || len(p) != 0 {
		t.Fatalf("got %+v %v", s, p)
	}
	s, p = collectSigs(filepath.Join(dir, "nonexistent"))
	if s.Daily != nil || len(p) != 0 {
		t.Fatalf("missing dir: got %+v %v", s, p)
	}
}

func TestCollectSigsInvalidHeaderIsNullPlusProblem(t *testing.T) {
	dir := t.TempDir()
	writeDB(t, dir, "daily.cvd", []byte("ClamAV-VDB:short"))
	writeDB(t, dir, "main.cvd", fixture(t, "cvd/initial/main.cvd.hdr"))
	s, p := collectSigs(dir)
	if s.Daily != nil || s.Main == nil || s.Main.Version != 63 || len(p) != 1 || p[0].Source != "sigs.daily" {
		t.Fatalf("got %+v %v", s, p)
	}
}

func TestDailyMTime(t *testing.T) {
	dir := t.TempDir()
	if _, ok := dailyMTime(dir); ok {
		t.Fatal("no daily file must give ok=false")
	}
	writeDB(t, dir, "daily.cvd", nil)
	writeDB(t, dir, "daily.cld", nil)
	old, newer := time.Unix(1_700_000_000, 0), time.Unix(1_800_000_000, 0)
	_ = os.Chtimes(filepath.Join(dir, "daily.cvd"), old, old)
	_ = os.Chtimes(filepath.Join(dir, "daily.cld"), newer, newer)
	if got, ok := dailyMTime(dir); !ok || !got.Equal(newer) {
		t.Fatalf("got %v %v", got, ok)
	}
}
