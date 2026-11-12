// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// host.go: identifies the operating system for the report.
//
// Responsibilities: parse os-release(5) (ID and VERSION_ID) and try the
// standard locations in order.
// Dependencies: the filesystem and the proto package.

package agent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/clamfleet/clamfleet/internal/proto"
)

// DefaultOSReleasePaths are tried in order, per os-release(5).
var DefaultOSReleasePaths = []string{"/etc/os-release", "/usr/lib/os-release"}

// ParseOSRelease reads ID and VERSION_ID from os-release(5) content. Values
// may be unquoted or quoted with ' or ". A missing VERSION_ID (Debian
// testing/sid) gives "".
func ParseOSRelease(b []byte) proto.OS {
	var o proto.OS
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		switch k {
		case "ID":
			o.ID = v
		case "VERSION_ID":
			o.Version = v
		}
	}
	return o
}

// readOSRelease reads the first existing file of paths.
func readOSRelease(paths []string) (proto.OS, error) {
	var errs []error
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err == nil {
			return ParseOSRelease(b), nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return proto.OS{}, errors.New("no os-release path configured")
	}
	return proto.OS{}, fmt.Errorf("os-release: %w", errors.Join(errs...))
}
