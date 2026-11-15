// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// virusevent.go: tells whether clamd.conf runs ClamFleet's event command.
//
// Responsibilities: ParseVirusEvent, which turns clamd.conf into the value of
// report.clamd.virus_event ("clamfleet", "other" or "none").
// Dependencies: the proto package for the three values.

package agent

import (
	"bufio"
	"bytes"
	"path"
	"strings"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// ParseVirusEvent classifies the VirusEvent option of a clamd.conf.
//
// It reads the file the way ClamAV's optparse() does (see ParseLocalSocket):
// the key is case-sensitive, key and value split at the first blank, a value
// starting with '"' runs to the last '"', '#' inside an unquoted value starts a
// comment, and the FIRST occurrence wins. That is what clamd itself runs.
//
// Result:
//   - "none": no active VirusEvent line (absent, commented out, or empty);
//   - "clamfleet": the command is <path>/clamfleet-agent followed by the word
//     "event" (extra arguments such as --config are fine);
//   - "other": anything else, including a wrapper script, which the operator
//     has to wire to `clamfleet-agent event` and which we cannot see into.
//     The health rule therefore stays quiet for "other" (decision 6).
func ParseVirusEvent(conf []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(conf))
	// A very long line is not a VirusEvent we can judge; Scan stops with an
	// error and the loop below falls through to "none".
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimLeft(sc.Text(), " \t")
		if len(line) <= 1 || line[0] == '#' {
			continue
		}
		i := strings.IndexAny(line, " \t")
		if i < 0 || line[:i] != "VirusEvent" {
			continue
		}
		val := strings.TrimRight(strings.TrimLeft(line[i+1:], " \t"), " \t\r\n")
		if val == "" {
			continue
		}
		if val[0] == '"' {
			end := strings.LastIndexByte(val[1:], '"')
			if end <= 0 {
				return proto.VirusEventNone
			}
			val = val[1 : 1+end]
		} else if h := strings.IndexByte(val, '#'); h >= 0 {
			val = strings.TrimRight(val[:h], " \t")
		}
		if val == "" {
			return proto.VirusEventNone
		}
		f := strings.Fields(val)
		if len(f) >= 2 && path.Base(f[0]) == "clamfleet-agent" && f[1] == "event" {
			return proto.VirusEventClamfleet
		}
		return proto.VirusEventOther
	}
	return proto.VirusEventNone
}
