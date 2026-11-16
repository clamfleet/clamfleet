# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# Developer entry points. `make check` is what CI will run.
# staticcheck and sqlc must be installed separately (see CLAUDE.md for the pinned version).

GO ?= go
BIN := bin
VERSION ?= 0.0.0-dev
LDFLAGS := -s -w -X github.com/clamfleet/clamfleet/internal/version.Version=$(VERSION)

.PHONY: build vet staticcheck test scripts-test sqlc-check generate check packages e2e e2e-apparmor e2e-web fixtures webfixture web-fixture

# Both binaries are static (CGO_ENABLED=0: the server uses pure-Go SQLite).
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/clamfleet-agent ./cmd/clamfleet-agent
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/clamfleet-server ./cmd/clamfleet-server

# Packages (milestone 6): .deb and .rpm of the agent and the server into dist/, built by nfpm, which is a
# build-time tool only (pinned in CLAUDE.md, run with `go run` like sqlc; nothing of it is in the binaries).
# VERSION is semver; a pre-release such as 0.6.0-rc1 becomes 0.6.0~rc1 in a deb. amd64 only (arm64 is 6c).
NFPM_VERSION := v2.49.0
NFPM := $(GO) run github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)
PKG_DIR ?= dist
packages: build
	rm -rf $(PKG_DIR) && mkdir -p $(PKG_DIR)
	set -e; for pkg in agent server; do for fmt in deb rpm; do \
		VERSION=$(VERSION) NFPM_ARCH=amd64 $(NFPM) package -f deploy/packaging/nfpm-$$pkg.yaml -p $$fmt -t $(PKG_DIR)/; \
	done; done
	ls -l $(PKG_DIR)

vet:
	$(GO) vet ./...
	$(GO) vet -tags e2e ./...
	$(GO) vet -tags "e2e e2e_apparmor" ./...

staticcheck:
	staticcheck ./...
	staticcheck -tags e2e ./...
	staticcheck -tags "e2e e2e_apparmor" ./...

test:
	$(GO) test ./...

# Shell tests that need no container (fake ssh).
scripts-test:
	./deploy/test/reset_test.sh
	./deploy/test/units_test.sh
	./deploy/test/selinux_test.sh
	./deploy/test/packages_test.sh

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
# The AppArmor VM (milestone 5, decision 7): CFA_EXEC is the command prefix that runs a command
# in the VM, CFA_HOST the ssh target of the Incus host that holds it. Also no defaults.
export CFT_EXEC INCUS_HOST CFA_EXEC CFA_HOST

e2e:
	@test -n "$(CFT_EXEC)" -a -n "$(INCUS_HOST)" || { echo "e2e: set CFT_EXEC and INCUS_HOST (environment or local.mk, see local.mk.example)" >&2; exit 1; }
	$(MAKE) packages VERSION=0.6.0-e2e1
	$(GO) test -tags e2e -count=1 -timeout 20m -v ./e2e/

# AppArmor enforcing, in the throwaway Debian 13 VM (docs/testing.md "The AppArmor VM"). Part of the
# milestone 5 acceptance; `make e2e` does not run it because it needs the VM. Without CFA_EXEC and
# CFA_HOST it FAILS (it never skips). The same suite code runs against the VM: the environment points
# CFT_EXEC and INCUS_HOST at it, CT/SNAP make deploy/test/reset.sh restore the VM's `clean` snapshot.
e2e-apparmor:
	@test -n "$(CFA_EXEC)" -a -n "$(CFA_HOST)" || { echo "e2e-apparmor: set CFA_EXEC and CFA_HOST (environment or local.mk, see local.mk.example and docs/testing.md)" >&2; exit 1; }
	CFT_EXEC="$(CFA_EXEC)" INCUS_HOST="$(CFA_HOST)" CT=clamfleet-aa SNAP=clean READY_FILE=/var/lib/clamav/freshclam.dat \
		$(GO) test -tags "e2e e2e_apparmor" -count=1 -timeout 30m -v -run 'TestAppArmor|TestClamdOnlyExecsTheAgent' ./e2e/

fixtures:
	./deploy/test/capture-fixtures.sh

# Browser fixture (docs/testing.md "Browser fixture"): a throwaway server on 127.0.0.1 with
# seeded users and hosts. `webfixture` only builds the program (bin/webfixture), which is what
# a test runner should start so signals reach it directly; `web-fixture` builds everything and
# runs it in the foreground until Ctrl-C.
webfixture: build
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN)/webfixture ./hack/webfixture

web-fixture: webfixture
	$(BIN)/webfixture --server-bin $(BIN)/clamfleet-server $(WEB_FIXTURE_ARGS)

# Browser E2E for the console (e2e/web, Playwright, Chromium only). Needs Node and an installed
# Chromium matching the pinned @playwright/test (PLAYWRIGHT_BROWSERS_PATH, see /opt/env.sh;
# README of e2e/web). The suite starts bin/webfixture itself on 127.0.0.1 and its global teardown
# stops it, also when tests fail; no browser or server outlives the run.
e2e-web: webfixture
	cd e2e/web && npm ci && npx playwright test
