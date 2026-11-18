# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# Developer entry points. `make check` is what developers run; CI runs `make ci`, which adds the
# workflow lint, the module hygiene checks and the no-skip test gate (docs/testing.md, "CI").
# staticcheck and sqlc must be installed: `make tools` installs the pinned versions below.

GO ?= go
BIN := bin
VERSION ?= 0.0.0-dev
LDFLAGS := -s -w -X github.com/clamfleet/clamfleet/internal/version.Version=$(VERSION)

.PHONY: tools ci release release-snapshot lint-workflows mod-check test-ci build vet staticcheck test scripts-test sqlc-check generate check packages e2e e2e-image e2e-docker record-freshclam-history e2e-apparmor e2e-el9 e2e-idp e2e-web fixtures webfixture web-fixture

# Build-time tools and their pins. The same versions are in CLAUDE.md and docs/testing.md: change all
# together. They are installed with `go install`, never added to go.mod (the Go `tool` directive would
# put the tools' modules into go.sum, and a contributor's build must not depend on a linter).
# sqlc is built with CGO disabled (as CLAUDE.md prescribes): the binary then needs no C toolchain.
STATICCHECK_VERSION := v0.8.2
SQLC_VERSION := v1.31.1
# actionlint is not installed: `make lint-workflows` runs it with `go run` at this version.
ACTIONLINT_VERSION := v1.7.12
# cyclonedx-gomod writes the SBOMs of a release; deploy/release/release.sh runs it with `go run` at this version.
CYCLONEDX_VERSION := v1.12.0

tools:
	$(GO) install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	CGO_ENABLED=0 $(GO) install github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)

# Both binaries are static (CGO_ENABLED=0: the server uses pure-Go SQLite).
# E2E_BUILD_TAGS: extra build tags, only for the package upgrade e2e (e2e_migration: a test-only
# migration). It is picked up from the environment, so `build` (and with it `packages`) refuses a
# non-empty value unless VERSION contains "e2e": an exported tag must never reach a release package.
# The tagged binary also announces itself, "+e2e_migration" after its version (migrations/e2e_overlay.go).
E2E_BUILD_TAGS ?=
build:
	@test -z "$(E2E_BUILD_TAGS)" || case "$(VERSION)" in *e2e*) ;; *) echo "build: E2E_BUILD_TAGS=$(E2E_BUILD_TAGS) is only for e2e builds: VERSION=$(VERSION) does not contain e2e" >&2; exit 1 ;; esac
	CGO_ENABLED=0 $(GO) build -trimpath -tags '$(E2E_BUILD_TAGS)' -ldflags '$(LDFLAGS)' -o $(BIN)/clamfleet-agent ./cmd/clamfleet-agent
	CGO_ENABLED=0 $(GO) build -trimpath -tags '$(E2E_BUILD_TAGS)' -ldflags '$(LDFLAGS)' -o $(BIN)/clamfleet-server ./cmd/clamfleet-server

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

# The unsigned release assets of VERSION (X.Y.Z or X.Y.Z-rc.N) into dist/release, with the script's self-checks
# (docs/releasing.md). Needs go, git, jq, dpkg-deb, rpm, rpm2cpio and cpio. Signing is deploy/release/sign.sh and
# happens only in the release workflow's sign job: the release key is never on a developer's machine.
release:
	CYCLONEDX_VERSION=$(CYCLONEDX_VERSION) ./deploy/release/release.sh $(VERSION)

# The same with VERSION 0.0.0-rc.1, on a dirty tree, with the notes taken from "Unreleased". Never signed or published.
release-snapshot:
	RELEASE_SNAPSHOT=1 CYCLONEDX_VERSION=$(CYCLONEDX_VERSION) ./deploy/release/release.sh 0.0.0-rc.1

vet:
	$(GO) vet ./...
	$(GO) vet -tags e2e ./...
	$(GO) vet -tags "e2e e2e_apparmor e2e_el9" ./...
	$(GO) vet -tags e2e_idp ./...

staticcheck:
	staticcheck ./...
	staticcheck -tags e2e ./...
	staticcheck -tags "e2e e2e_apparmor e2e_el9" ./...
	staticcheck -tags e2e_idp ./...

test:
	$(GO) test ./...

# Shell tests that need no container (fake ssh).
scripts-test:
	./deploy/test/reset_test.sh
	./deploy/test/units_test.sh
	./deploy/test/selinux_test.sh
	./deploy/test/packages_test.sh
	./deploy/test/headers_test.sh
	./deploy/test/workflows_test.sh
	./deploy/test/dco_test.sh
	./deploy/test/l1paths_test.sh
	./deploy/test/l1guard_test.sh
	./deploy/test/release_test.sh
	./deploy/test/webtests_test.sh

# sqlc is a build-time tool only (pinned in CLAUDE.md): the generated code uses database/sql.
generate:
	sqlc generate

# Fails when the committed sqlcdb output does not match the migrations and queries.
sqlc-check:
	sqlc diff

check: vet staticcheck sqlc-check test scripts-test

# What CI runs on every pull request (docs/testing.md, "CI"): `check` plus the workflow lint, the module
# and formatting hygiene, and the test gate in place of plain `go test`. Kept apart from `check` so a
# developer's loop stays short and needs no network beyond the module cache.
ci: vet staticcheck sqlc-check scripts-test lint-workflows mod-check test-ci

lint-workflows:
	$(GO) run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

# go.mod and go.sum are what the build uses, so they must be what `go mod tidy` would write and match
# the module cache; gofmt covers tracked Go files only (e2e/web/node_modules is not ours).
mod-check:
	$(GO) mod tidy -diff
	$(GO) mod verify
	@bad="$$(gofmt -l $$(git ls-files '*.go'))"; test -z "$$bad" || { echo "gofmt: these files are not formatted:" >&2; echo "$$bad" >&2; exit 1; }

# The unit tests behind hack/testgate: a failure, a skip or a build failure all fail the run, which
# `go test` alone would not for a skip. -count=1 is required: the cmd/* and hack/webfixture tests build
# binaries that go test's result cache cannot see (CLAUDE.md). bash and pipefail so that a `go test`
# that dies without a verdict (it still prints events) fails the target too.
test-ci:
	$(GO) build -o $(BIN)/testgate ./hack/testgate
	bash -o pipefail -c '$(GO) test -count=1 -json ./... | $(BIN)/testgate'

# Needs the clamfleet-test container; read docs/testing.md first.
# CFT_EXEC (command prefix that runs a command inside the container) and
# INCUS_HOST (ssh target of the Incus host) have NO default: they name
# infrastructure that does not belong in a public repository. Set them in the
# environment or in the gitignored local.mk (see local.mk.example).
-include local.mk
# The AppArmor VM (milestone 5, decision 7): CFA_EXEC is the command prefix that runs a command
# in the VM, CFA_HOST the ssh target of the Incus host that holds it. Also no defaults.
# The AlmaLinux 9 VM (milestone 6, decision 11): CFE_EXEC and CFE_HOST, the same way. Also no defaults.
# The identity-provider container (M6 decision 11): CFI_EXEC and CFI_HOST, the same way. Also no defaults.
export CFT_EXEC INCUS_HOST CFA_EXEC CFA_HOST CFE_EXEC CFE_HOST CFI_EXEC CFI_HOST

e2e:
	@test -n "$(CFT_EXEC)" -a -n "$(INCUS_HOST)" || { echo "e2e: set CFT_EXEC and INCUS_HOST (environment or local.mk, see local.mk.example)" >&2; exit 1; }
	$(MAKE) packages VERSION=0.6.0-e2e1
	$(GO) test -tags e2e -count=1 -timeout 20m -v ./e2e/

# The same suite in Docker, which is what CI runs (docs/testing.md, "The e2e suite in Docker"). The image is
# a Debian 13 with systemd as PID 1, the distribution's ClamAV and frozen signatures (deploy/test/ci); it is
# never pushed anywhere (M6 decision 13). The container has no network, so the binaries go in over
# `docker exec -i`: that is why CFT_EXEC carries -i. The suite's own variables are set inline, so a
# local.mk written for the Incus suite cannot redirect it. READY_FILE is /etc/hostname, which clamd may read here.
E2E_IMAGE ?= clamfleet-e2e:ci
E2E_CT := clamfleet-ci
e2e-image:
	docker build -t $(E2E_IMAGE) -f deploy/test/ci/Dockerfile deploy/test/ci

# Re-records deploy/test/ci/testdata (the freshclam run the CI image carries) from the Incus test container.
# Needs the Incus suite's settings (CFT_EXEC, INCUS_HOST). Never hand-edit the recorded files.
record-freshclam-history:
	./deploy/test/record-freshclam-history.sh

# Needs a Docker daemon and the image (`make e2e-image`). The test gate with -expect-pkg fails the run when
# the set of passed top-level tests differs from the set the package declares, so a narrowed -run cannot pass.
# E2E_JOURNAL_DIR keeps each container's journal (reset.sh saves it before replacing the container); CI
# uploads it when the run fails. The trap saves the last container's journal, then removes it, however the run ends.
E2E_JOURNAL_DIR ?= $(CURDIR)/dist/e2e-journals
e2e-docker:
	@command -v docker >/dev/null || { echo "e2e-docker: docker is not installed; the Incus suite is "make e2e" (docs/testing.md)" >&2; exit 1; }
	$(MAKE) packages VERSION=0.6.0-e2e1
	$(GO) build -o $(BIN)/testgate ./hack/testgate
	mkdir -p $(E2E_JOURNAL_DIR)
	trap 'CT=$(E2E_CT) E2E_JOURNAL_DIR=$(E2E_JOURNAL_DIR) ./deploy/test/save-journal.sh; docker rm -f $(E2E_CT) >/dev/null 2>&1' EXIT; \
	CFT_EXEC="docker exec -i $(E2E_CT)" RESET_RUNTIME=docker CT=$(E2E_CT) E2E_IMAGE=$(E2E_IMAGE) READY_FILE=/etc/hostname E2E_JOURNAL_DIR=$(E2E_JOURNAL_DIR) \
		bash -o pipefail -c '$(GO) test -tags e2e -count=1 -timeout 40m -json ./e2e/ | $(BIN)/testgate -expect-pkg ./e2e -tags e2e'

# AppArmor enforcing, in the throwaway Debian 13 VM (docs/testing.md "The AppArmor VM"). Part of the
# milestone 5 acceptance; `make e2e` does not run it because it needs the VM. Without CFA_EXEC and
# CFA_HOST it FAILS (it never skips). The same suite code runs against the VM: the environment points
# CFT_EXEC and INCUS_HOST at it, CT/SNAP make deploy/test/reset.sh restore the VM's `clean` snapshot.
# deploy/test/l1-guard.sh runs first in both L1 targets and in e2e-idp (it also runs the commit as root on the Incus host): it refuses a commit that is on no origin branch
# (a fork's code) unless L1_APPROVED names it (R1 decision 6, docs/testing.md "Which changes need an L1 run").
e2e-apparmor:
	@test -n "$(CFA_EXEC)" -a -n "$(CFA_HOST)" || { echo "e2e-apparmor: set CFA_EXEC and CFA_HOST (environment or local.mk, see local.mk.example and docs/testing.md)" >&2; exit 1; }
	./deploy/test/l1-guard.sh
	$(MAKE) packages VERSION=0.6.0-e2e1
	CFT_EXEC="$(CFA_EXEC)" INCUS_HOST="$(CFA_HOST)" CT=clamfleet-aa SNAP=clean READY_FILE=/var/lib/clamav/freshclam.dat \
		$(GO) test -tags "e2e e2e_apparmor" -count=1 -timeout 30m -v -run 'TestAppArmor|TestClamdOnlyExecsTheAgent' ./e2e/

# RHEL 9 and SELinux Enforcing, in the throwaway AlmaLinux 9 VM (docs/testing.md "The AlmaLinux 9 VM"):
# the .rpm files are installed with dnf and the detection path must work through the SELinux module the
# package loads. Part of the milestone 6 acceptance, with `make e2e` and `make e2e-apparmor`. Without CFE_EXEC
# and CFE_HOST it FAILS (it never skips). READY_FILE is a file clamd's domain may read (under /var/lib/clamav).
e2e-el9:
	@test -n "$(CFE_EXEC)" -a -n "$(CFE_HOST)" || { echo "e2e-el9: set CFE_EXEC and CFE_HOST (environment or local.mk, see local.mk.example and docs/testing.md)" >&2; exit 1; }
	./deploy/test/l1-guard.sh
	$(MAKE) packages VERSION=0.6.0-e2e1
	CFT_EXEC="$(CFE_EXEC)" INCUS_HOST="$(CFE_HOST)" CT=clamfleet-el9 SNAP=clean READY_FILE=/var/lib/clamav/bytecode.cvd \
		$(GO) test -tags "e2e e2e_el9" -count=1 -timeout 40m -v -run 'TestEL9|TestSELinux' ./e2e/

# OpenLDAP and Keycloak in the throwaway clamfleet-idp container (docs/testing.md "The IdP container"): the real
# server signs users in against both. Part of the milestone 6b acceptance; `make e2e` does not run it. Without
# CFI_EXEC and CFI_HOST it FAILS (it never skips). It is built with the e2e_idp tag and without e2e: this
# container has no clamd, so the ClamAV suite's TestMain must not run. The same helpers read CFT_EXEC and
# INCUS_HOST, which this target points at the container.
e2e-idp:
	@test -n "$(CFI_EXEC)" -a -n "$(CFI_HOST)" || { echo "e2e-idp: set CFI_EXEC and CFI_HOST (environment or local.mk, see local.mk.example and docs/testing.md)" >&2; exit 1; }
	./deploy/test/l1-guard.sh
	CFT_EXEC="$(CFI_EXEC)" INCUS_HOST="$(CFI_HOST)" CT=clamfleet-idp SNAP=clean \
		$(GO) test -tags e2e_idp -count=1 -timeout 30m -v ./e2e/

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
# Chromium matching the pinned @playwright/test (PLAYWRIGHT_BROWSERS_PATH; see the
# README of e2e/web). The suite starts bin/webfixture itself on 127.0.0.1 and its global teardown
# stops it, also when tests fail; no browser or server outlives the run.
e2e-web: webfixture
	cd e2e/web && npm ci && npx playwright test
