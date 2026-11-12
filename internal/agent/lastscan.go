// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// lastscan.go: reads the summary of the last scheduled scan.
//
// Responsibilities: load the JSON file the scan wrapper (a later milestone)
// writes, treating a missing file as "no scan" and a malformed one as a Problem.
// Dependencies: the filesystem and the proto package.

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// readLastScan reads the scan summary written by the scan wrapper (a later
// milestone). A missing file means no scan is configured or none has run: nil
// and no problem. An unreadable or invalid file is nil plus a problem.
func readLastScan(path string) (*proto.LastScan, *Problem) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, &Problem{"last_scan", err}
	}
	var s proto.LastScan
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, &Problem{"last_scan", fmt.Errorf("%s: %w", path, err)}
	}
	// An empty object decodes without error but is not a summary.
	if s.Started.IsZero() || s.Finished.IsZero() {
		return nil, &Problem{"last_scan", fmt.Errorf("%s: missing started or finished time", path)}
	}
	s.Started, s.Finished = proto.UTC(s.Started), proto.UTC(s.Finished)
	return &s, nil
}
