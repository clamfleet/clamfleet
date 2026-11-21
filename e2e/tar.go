//go:build e2e

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

package e2e

import (
	"archive/tar"
	"io"
)

// writeTar writes one executable file into a tar stream. Pushing a binary
// through "ssh ... tar -xf -" avoids shell quoting of the transfer command.
func writeTar(w io.Writer, name string, data []byte) error {
	tw := tar.NewWriter(w)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data))}); err != nil {
		return err
	}
	if _, err := tw.Write(data); err != nil {
		return err
	}
	return tw.Close()
}

// writeTarFiles writes several regular files (mode 0644) into one tar stream, for
// pushing packages into the container or VM.
func writeTarFiles(w io.Writer, files map[string][]byte) error {
	tw := tar.NewWriter(w)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	return tw.Close()
}
