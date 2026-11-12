# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# Developer entry points. `make check` is what CI will run.
# staticcheck and sqlc must be installed separately (see CLAUDE.md for the pinned version).

GO ?= go
BIN := bin
VERSION ?= 0.0.0-dev
LDFLAGS := -s -w -X github.com/clamfleet/clamfleet/internal/version.Version=$(VERSION)

.PHONY: build vet staticcheck test scripts-test sqlc-check generate check e2e fixtures

# Both binaries are static (CGO_ENABLED=0: the server uses pure-Go SQLite).
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/clamfleet-agent ./cmd/clamfleet-agent
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/clamfleet-server ./cmd/clamfleet-server

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

# sqlc is a build-time tool only (pinned in CLAUDE.md): the generated code uses database/sql.
generate:
	sqlc generate

# Fails when the committed sqlcdb output does not match the migrations and queries.
sqlc-check:
	sqlc diff

check: vet staticcheck sqlc-check test scripts-test

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
