// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: The ClamFleet Authors

// Package version holds the build version of the ClamFleet binaries.
package version

// Version is overridden at link time (-ldflags -X, see the Makefile and,
// later, goreleaser). The default marks a build made without the Makefile.
var Version = "0.0.0-dev"
