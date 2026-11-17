#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# release_test.sh - deploy/release/{lib,release,sign,verify-tag}.sh against temporary repositories, stub
# tools and throwaway keys (`make check` runs it; no network, no container). Each refusal a script promises has
# a case that must fail, and a good run first so that a script that refuses everything cannot pass.
#
# What this cannot prove, and the CI `release-dry-run` job does with the real tools: that `rpmsign`, `rpmkeys`,
# `rpm2cpio` and cyclonedx-gomod behave as the stubs here pretend. The stubs are small and say what they stand
# for. The .deb files and the Go binaries in these tests are real.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
rel="$repo/deploy/release"
tmp="$(mktemp -d)"
trap 'gpgconf --homedir "$tmp/gh" --kill all >/dev/null 2>&1 || true; rm -rf "${tmp:?}"' EXIT
fail() { echo "release_test: FAIL: $*" >&2; exit 1; }

# The developer's git and gpg configuration must not leak in (signing keys, hooks, templates).
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
# The Go in the temporary module needs neither the network nor a toolchain download.
export GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=mod CGO_ENABLED=0 GOWORK=off
export GOCACHE="${GOCACHE:-$tmp/gocache}"

# ===================================================================================================
# lib.sh: the version policy and the CHANGELOG section.
# ===================================================================================================
# shellcheck source=../release/lib.sh
. "$rel/lib.sh"

for v in 1.2.3 1.0.0-rc.1 0.0.0-rc.1 10.20.30 1.0.0-rc.12; do
	release_version_ok "$v" || fail "version $v must be accepted"
done
for v in v1.2.3 1.2 01.2.3 1.2.3- 1.0.0-rc.01 1.0.0-beta.1 1.0.0+build 1.0.0-rc 1.0.0-rc.1.2 "" " 1.2.3" "1.2.3
"; do
	if release_version_ok "$v"; then fail "version '$v' must be refused"; fi
done

cat >"$tmp/CHANGELOG.md" <<'MD'
# Changelog

## Unreleased

### Added
- later thing

## [1.0.0-rc.1] - 2026-12-01

### Added
- first thing

- second thing (kept, with the blank line before it)

## [1.0.0-rc.10] - 2026-12-02

- the rc.10 text, which must not be mistaken for rc.1

## [1.2.3] - 2026-12-03

## [1.2.4] - 2026-12-04

## [1.2.5] - soon

- undated
MD
got="$(changelog_section 1.0.0-rc.1 "$tmp/CHANGELOG.md")"
want=$'### Added\n- first thing\n\n- second thing (kept, with the blank line before it)'
[ "$got" = "$want" ] || fail "changelog section was '$got'"
[ "$(changelog_section 1.0.0-rc.10 "$tmp/CHANGELOG.md")" = "- the rc.10 text, which must not be mistaken for rc.1" ] || fail "rc.10 section"
for v in 1.2.3 1.2.4 1.2.5 9.9.9 Unreleased 1x0y0-rc.1; do
	if changelog_section "$v" "$tmp/CHANGELOG.md" >/dev/null; then fail "changelog section $v must be refused (empty, undated, missing or Unreleased)"; fi
done

# ===================================================================================================
# A temporary project that looks enough like this one for release.sh: two commands, one module
# dependency (a local replace, so no network), a vendored htmx, and stubs for the tools that need the
# outside world (make, nfpm, rpm and cyclonedx-gomod).
# ===================================================================================================
stubs="$tmp/stubs"
mkdir -p "$stubs"

# `make packages VERSION=v PKG_DIR=d`: really builds the two commands (so version and vcs stamping are real),
# really builds the .deb files with dpkg-deb, and writes the "rpm" as a bare cpio archive (what rpm2cpio
# would hand to cpio) named as nfpm names rpms. STUB_* variables switch on one fault each.
cat >"$stubs/make" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = packages ] || { echo "stub make: only 'packages'" >&2; exit 2; }
v="" pkg=""
for a in "$@"; do case "$a" in VERSION=*) v="${a#VERSION=}" ;; PKG_DIR=*) pkg="${a#PKG_DIR=}" ;; esac; done
shown="${STUB_LDVERSION:-$v}"
vflags=()
[ -z "${STUB_NO_VCS:-}" ] || vflags=(-buildvcs=false)
rm -rf bin "${pkg:?}"; mkdir -p bin "$pkg"
for n in clamfleet-agent clamfleet-server; do
	go build -trimpath "${vflags[@]}" -ldflags "-X main.version=$shown" -o "bin/$n" "./cmd/$n"
done
[ -z "${STUB_COMMIT_AFTER:-}" ] || git commit -q --allow-empty -m "after the build"
dv="${v/-/\~}"
for n in clamfleet-agent clamfleet-server; do
	t="$(mktemp -d)"; mkdir -p "$t/usr/bin" "$t/DEBIAN"
	cp "bin/$n" "$t/usr/bin/$n"
	printf 'Package: %s\nVersion: %s\nArchitecture: amd64\nMaintainer: t <t@example.com>\nDescription: stub\n' "$n" "${STUB_DEB_VERSION:-$dv}" >"$t/DEBIAN/control"
	dpkg-deb --root-owner-group -Zgzip --build "$t" "$pkg/${n}_${dv}_amd64.deb" >/dev/null
	# The rpm differs from the tarball's binary by one byte when asked to.
	if [ -n "${STUB_RPM_TAMPER:-}" ]; then printf 'x' >>"$t/usr/bin/$n"; fi
	(cd "$t" && echo "./usr/bin/$n" | cpio -o -H newc --quiet) >"$pkg/${n}-${dv}-1.x86_64.rpm"
	rm -rf "${t:?}"
done
SH
# rpm2cpio: the stub "rpm" is already a cpio archive. rpm -qp: the header fields come from the file name.
cat >"$stubs/rpm2cpio" <<'SH'
#!/bin/sh
cat "$1"
SH
cat >"$stubs/rpm" <<'SH'
#!/usr/bin/env bash
# Stub for `rpm -qp --qf FMT FILE` (and, for sign.sh, the payload digest).
set -euo pipefail
[ "$1" = "-qp" ] || exit 2
f="${*: -1}"; b="$(basename "$f")"
case "$*" in
*PAYLOADDIGEST*)
	# Everything but the signature line is "payload".
	grep -av '^SIG:' "$f" | sha256sum | cut -d' ' -f1 ;;
*)
	[[ "$b" =~ ^(.+)-([^-]+)-([0-9]+)\.x86_64\.rpm$ ]] || exit 2
	printf '%s %s x86_64' "${BASH_REMATCH[1]}" "${STUB_RPM_VERSION:-${BASH_REMATCH[2]}}" ;;
esac
SH
# cyclonedx-gomod: the output shape of v1.12 for `bin` (checked once by hand: name is the module path, the
# subject's purl ends in #cmd/<binary>, library purls carry qualifiers and a subpath).
cat >"$stubs/cyclonedx-gomod" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = bin ] || exit 2
out="" ver="" bin=""
shift
while [ "$#" -gt 0 ]; do case "$1" in -output) out="$2"; shift 2 ;; -version) ver="$2"; shift 2 ;; -*) shift ;; *) bin="$1"; shift ;; esac; done
n="$(basename "$bin")"
libs='[]'
if [ "$n" = clamfleet-server ]; then
	libs='[{"type":"library","name":"example.com/dep","version":"v1.0.0","purl":"pkg:golang/example.com/dep@v1.0.0?goarch=amd64&goos=linux&type=module#sub"}]'
fi
[ -z "${STUB_SBOM_EXTRA:-}" ] || libs="$(jq -c --arg p "$STUB_SBOM_EXTRA" '. + [{"type":"library","name":"x","version":"1","purl":$p}]' <<<"$libs")"
jq -n --arg n "$n" --arg v "${STUB_SBOM_VERSION:-$ver}" --arg f "${STUB_SBOM_FORMAT:-CycloneDX}" --argjson libs "$libs" \
	'{bomFormat:$f, specVersion:"1.6", metadata:{component:{type:"application", name:"example.com/clam", version:$v, purl:("pkg:golang/example.com/clam@"+$v+"?goarch=amd64&goos=linux&type=module#cmd/"+$n)}}, components:$libs}' >"$out"
SH
chmod +x "$stubs"/*

# mkproject DIR: a committed, clean project with the release scripts copied in.
mkproject() {
	local d="$1"
	mkdir -p "$d/cmd/clamfleet-agent" "$d/cmd/clamfleet-server" "$d/dep" "$d/internal/web/static" "$d/deploy/release"
	cat >"$d/go.mod" <<'GO'
module example.com/clam

go 1.21

require example.com/dep v1.0.0

replace example.com/dep => ./dep
GO
	printf 'module example.com/dep\n\ngo 1.21\n' >"$d/dep/go.mod"
	printf 'package dep\n\n// Name is here so the server has one module dependency.\nconst Name = "dep"\n' >"$d/dep/dep.go"
	cat >"$d/cmd/clamfleet-agent/main.go" <<'GO'
package main

import (
	"fmt"
	"os"
)

var version = "unset"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("clamfleet-agent " + version)
	}
}
GO
	sed -e 's/clamfleet-agent/clamfleet-server/' -e 's|^import (|import (\n\t"example.com/dep"|' -e 's|^var version|var _ = dep.Name\n\nvar version|' "$d/cmd/clamfleet-agent/main.go" >"$d/cmd/clamfleet-server/main.go"
	echo "LICENSE text" >"$d/LICENSE"
	echo "README text" >"$d/README.md"
	printf '/bin/\n/dist/\n' >"$d/.gitignore"
	printf '// pretend htmx\n' >"$d/internal/web/static/htmx-2.0.11.min.js"
	cp "$rel/lib.sh" "$rel/release.sh" "$d/deploy/release/"
	local sum
	sum="$(sha256sum "$d/internal/web/static/htmx-2.0.11.min.js" | cut -d' ' -f1)"
	jq --arg h "$sum" '.component.hashes[0].content = $h' "$rel/sbom-extra.json" >"$d/deploy/release/sbom-extra.json"
	cat >"$d/CHANGELOG.md" <<'MD'
# Changelog

## Unreleased

- nothing

## [1.0.0-rc.1] - 2026-12-01

- the first release candidate
MD
	git -C "$d" init -q -b main
	git -C "$d" add -A
	git -C "$d" -c commit.gpgsign=false commit -q -m "initial"
}

proj="$tmp/proj"
mkproject "$proj"
export MAKE="$stubs/make" CYCLONEDX_CMD="$stubs/cyclonedx-gomod"
# The stubs rpm and rpm2cpio come first on PATH. The tools they stand for are not needed here.
export PATH="$stubs:$PATH"

# run_release VERSION: runs the project's copy of release.sh; the output is in $tmp/out, the status returned.
run_release() { (cd "$proj" && ./deploy/release/release.sh "$@") >"$tmp/out" 2>&1; }
expect_ok() { run_release "$@" || fail "release.sh $*: refused:
$(cat "$tmp/out")"; }
# expect_refused NAME WANTED-TEXT VERSION: the output must name the cause, not merely fail.
expect_refused() {
	local name="$1" text="$2"; shift 2
	if run_release "$@"; then fail "$name: release.sh accepted"; fi
	grep -qF -- "$text" "$tmp/out" || fail "$name: refused for another reason (wanted '$text'):
$(cat "$tmp/out")"
}

expect_ok 1.0.0-rc.1
out="$proj/dist/release"
for f in clamfleet_1.0.0-rc.1_linux_amd64.tar.gz clamfleet-agent_1.0.0~rc.1_amd64.deb clamfleet-server-1.0.0~rc.1-1.x86_64.rpm \
	clamfleet-agent_1.0.0-rc.1_sbom.cdx.json clamfleet-server_1.0.0-rc.1_sbom.cdx.json SHA256SUMS notes.md; do
	[ -f "$out/$f" ] || fail "a good run did not produce $f"
done
[ "$(cat "$out/notes.md")" = "- the first release candidate" ] || fail "notes.md is not the CHANGELOG section"
if grep -q 'notes.md\|SHA256SUMS' "$out/SHA256SUMS"; then fail "SHA256SUMS must not list itself or notes.md"; fi
[ "$(wc -l <"$out/SHA256SUMS")" -eq 7 ] || fail "SHA256SUMS lists $(wc -l <"$out/SHA256SUMS") files, wanted 7"
jq -e '[.components[] | select(.name == "htmx.org")] | length == 1' "$out/clamfleet-server_1.0.0-rc.1_sbom.cdx.json" >/dev/null || fail "no htmx in the server SBOM"
tar -tzf "$out/clamfleet_1.0.0-rc.1_linux_amd64.tar.gz" | sort | tr '\n' ' ' | grep -q 'LICENSE.*README.md' || fail "the tarball lacks LICENSE or README.md"

# Two runs of the same commit give the same tarball (determinism is what lets anyone rebuild and compare).
first="$(sha256sum "$out/clamfleet_1.0.0-rc.1_linux_amd64.tar.gz")"
sleep 1
expect_ok 1.0.0-rc.1
[ "$first" = "$(sha256sum "$out/clamfleet_1.0.0-rc.1_linux_amd64.tar.gz")" ] || fail "two runs gave different tarballs"

# Policy refusals (the version is checked before anything is built).
for v in v1.2.3 1.2 01.2.3 1.2.3- 1.0.0-rc.01 1.0.0-beta.1 1.0.0+build; do
	expect_refused "version $v" "outside the policy" "$v"
done
expect_refused "no changelog section" "no non-empty section" 1.0.1
expect_refused "unreleased as a version" "outside the policy" Unreleased
sed -i 's/^## \[1.0.0-rc.1\] - 2026-12-01$/## [1.0.0-rc.1] - 2026-12-01\n/; /the first release candidate/d' "$proj/CHANGELOG.md"
git -C "$proj" commit -q -am "empty section"
expect_refused "empty changelog section" "no non-empty section" 1.0.0-rc.1
printf '\n- notes again\n' >>"$proj/CHANGELOG.md"
git -C "$proj" commit -q -am "notes"

echo dirt >>"$proj/README.md"
expect_refused "dirty tree" "worktree is not clean" 1.0.0-rc.1
RELEASE_SNAPSHOT=1 run_release 0.0.0-rc.1 || fail "a snapshot of a dirty tree was refused:
$(cat "$tmp/out")"
grep -q 'snapshot' "$tmp/out" || fail "a snapshot does not say it is one"
if RELEASE_SNAPSHOT=1 run_release 1.0.0-rc.1; then fail "RELEASE_SNAPSHOT was accepted for a real version"; fi
git -C "$proj" checkout -q README.md
echo junk >"$proj/untracked.txt"
expect_refused "an untracked file" "worktree is not clean" 1.0.0-rc.1
rm "${proj:?}/untracked.txt"

E2E_BUILD_TAGS=e2e_migration expect_refused "E2E_BUILD_TAGS" "test-only build tags" 1.0.0-rc.1

# A missing prerequisite: a PATH holding every tool the script and its stubs use except one.
mkpath() { # DIR OMIT: symlinks to the tools by name; the stubs rpm and rpm2cpio are included
	local d="$1" omit="$2" t p
	mkdir -p "$d"
	for t in bash env awk sed grep sort find xargs install cut mktemp rm mv cat diff wc basename dirname head tail tr date git go tar gzip \
		sha256sum dpkg-deb cpio jq tee ls mkdir chmod readlink uname sh printf true false sleep cp ln id gpg gpgv gpgconf; do
		[ "$t" != "$omit" ] || continue
		p="$(command -v "$t" 2>/dev/null || true)"
		[ -z "$p" ] || ln -sf "$p" "$d/$t"
	done
	for t in rpm rpm2cpio; do [ "$t" != "$omit" ] || continue; ln -sf "$stubs/$t" "$d/$t"; done
}
for tool in go git tar gzip sha256sum dpkg-deb rpm rpm2cpio cpio jq; do
	mkpath "$tmp/path-$tool" "$tool"
	if (cd "$proj" && PATH="$tmp/path-$tool" "$BASH" ./deploy/release/release.sh 1.0.0-rc.1) >"$tmp/out" 2>&1; then fail "release.sh ran without $tool"; fi
	grep -q "missing tools: $tool" "$tmp/out" || fail "release.sh did not name the missing $tool:
$(cat "$tmp/out")"
done
mkpath "$tmp/path-none" none
(cd "$proj" && PATH="$tmp/path-none" "$BASH" ./deploy/release/release.sh 1.0.0-rc.1) >"$tmp/out" 2>&1 || fail "the restricted PATH itself is too small for a good run (fix the test):
$(cat "$tmp/out")"

# Self-check refusals: each is one fault injected into the stubs.
STUB_LDVERSION=9.9.9 expect_refused "a binary printing another version" "prints" 1.0.0-rc.1
STUB_NO_VCS=1 expect_refused "a binary without vcs info" "built from revision 'none'" 1.0.0-rc.1
STUB_COMMIT_AFTER=1 expect_refused "a binary built from another revision than HEAD" "built from revision" 1.0.0-rc.1
git -C "$proj" reset -q --hard HEAD~1   # drop the commit the previous case made, so the tree is as before
STUB_RPM_TAMPER=1 expect_refused "an rpm whose payload differs from the tarball" "differs from the tarball" 1.0.0-rc.1
STUB_DEB_VERSION=1.0.0 expect_refused "a deb with the wrong version" "Version is" 1.0.0-rc.1
STUB_RPM_VERSION=1.0.0 expect_refused "an rpm with the wrong version" "header says" 1.0.0-rc.1
STUB_SBOM_FORMAT=SPDX expect_refused "an SBOM of another format" "bomFormat" 1.0.0-rc.1
STUB_SBOM_VERSION=0.0.1 expect_refused "an SBOM of another version" "subject version" 1.0.0-rc.1
STUB_SBOM_EXTRA='pkg:golang/example.com/other@v2.0.0?type=module' expect_refused "an SBOM with a module go list does not know" "differ from 'go list" 1.0.0-rc.1
# Only golang purls are compared, so a non-Go component (htmx is one) is no finding.
STUB_SBOM_EXTRA='pkg:npm/htmx.org@2.0.11' expect_ok 1.0.0-rc.1

# htmx: a hash that is not the vendored file's, and a file whose version moved without the SBOM.
jq '.component.hashes[0].content = "00"' "$proj/deploy/release/sbom-extra.json" >"$tmp/x.json" && mv "$tmp/x.json" "$proj/deploy/release/sbom-extra.json"
git -C "$proj" commit -q -am "wrong htmx hash"
expect_refused "a wrong htmx hash" "lists htmx" 1.0.0-rc.1
git -C "$proj" reset -q --hard HEAD~1
git -C "$proj" mv internal/web/static/htmx-2.0.11.min.js internal/web/static/htmx-2.0.12.min.js
git -C "$proj" commit -q -m "htmx moved"
expect_refused "a bumped htmx file with a stale SBOM entry" "lists htmx" 1.0.0-rc.1
git -C "$proj" reset -q --hard HEAD~1
expect_ok 1.0.0-rc.1

echo "release_test: ok"
