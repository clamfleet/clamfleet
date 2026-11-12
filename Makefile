# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# Developer entry points. `make check` is what CI will run.
# staticcheck must be installed separately (see CLAUDE.md for the pinned version).

GO ?= go
BIN := bin
VERSION ?= 0.0.0-dev
LDFLAGS := -s -w -X github.com/clamfleet/clamfleet/internal/version.Version=$(VERSION)

.PHONY: build vet staticcheck test scripts-test check e2e fixtures

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/clamfleet-agent ./cmd/clamfleet-agent

vet:
	$(GO) vet ./...
	$(GO) vet -tags e2e ./...

staticcheck:
	staticcheck ./...
	staticcheck -tags e2e ./...

test:
	$(GO) test ./...

# Shell tests that need no container (fake ssh).
scripts-test:
	./deploy/test/reset_test.sh

check: vet staticcheck test scripts-test

# Needs the clamfleet-test container; read docs/testing.md first.
# CFT_EXEC (command prefix that runs a command inside the container) and
# INCUS_HOST (ssh target of the Incus host) have NO default: they name
# infrastructure that does not belong in a public repository. Set them in the
# environment or in the gitignored local.mk (see local.mk.example).
-include local.mk
export CFT_EXEC INCUS_HOST

e2e:
	@test -n "$(CFT_EXEC)" -a -n "$(INCUS_HOST)" || { echo "e2e: set CFT_EXEC and INCUS_HOST (environment or local.mk, see local.mk.example)" >&2; exit 1; }
	$(GO) test -tags e2e -count=1 -timeout 20m -v ./e2e/

fixtures:
	./deploy/test/capture-fixtures.sh
