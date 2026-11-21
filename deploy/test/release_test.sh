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
	# The "rpm" is a cpio archive: the binary plus a HDR member that the stub rpm answers header queries from.
	printf '%s %s\n' "$n" "$dv" >"$t/HDR"
	(cd "$t" && printf './usr/bin/%s\n./HDR\n' "$n" | cpio -o -H newc --quiet) >"$pkg/${n}-${dv}-1.x86_64.rpm"
	rm -rf "${t:?}"
done
SH
# rpm2cpio: the stub "rpm" is already a cpio archive. rpm -qp: the header fields come from its HDR member.
cat >"$stubs/rpm2cpio" <<'SH'
#!/bin/sh
cat "$1"
SH
cat >"$stubs/rpm" <<'SH'
#!/usr/bin/env bash
# Stub for `rpm -qp --qf FMT FILE` (and, for sign.sh, the payload digest).
set -euo pipefail
[ "$1" = "-qp" ] || exit 2
f="${*: -1}"
case "$*" in
*PAYLOADDIGEST*)
	# Everything but the signature line is "payload".
	grep -av '^SIG:' "$f" | sha256sum | cut -d' ' -f1 ;;
*)
	read -r hn hv < <(cpio -i --quiet --to-stdout '*HDR' <"$f")
	printf '%s %s x86_64' "$hn" "${STUB_RPM_VERSION:-$hv}" ;;
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
for f in clamfleet_1.0.0-rc.1_linux_amd64.tar.gz clamfleet-agent_1.0.0-rc.1_amd64.deb clamfleet-server-1.0.0-rc.1-1.x86_64.rpm \
	clamfleet-agent_1.0.0-rc.1_sbom.cdx.json clamfleet-server_1.0.0-rc.1_sbom.cdx.json SHA256SUMS notes.md; do
	[ -f "$out/$f" ] || fail "a good run did not produce $f"
done
[ "$(cat "$out/notes.md")" = "- the first release candidate" ] || fail "notes.md is not the CHANGELOG section"
if grep -q 'SHA256SUMS' "$out/SHA256SUMS"; then fail "SHA256SUMS must not list itself"; fi
# Asset names never carry "~" (GitHub likely renames it; the packages' internal version keeps it).
if ls "$out" | grep -q '~'; then fail "an asset name contains ~: $(ls "$out")"; fi
if grep -q '~' "$out/SHA256SUMS"; then fail "SHA256SUMS lists a name with ~"; fi
dpkg-deb -f "$out/clamfleet-agent_1.0.0-rc.1_amd64.deb" Version | grep -qx '1.0.0~rc.1' || fail "the deb's own version lost its ~"
grep -q '^[0-9a-f]*  notes.md$' "$out/SHA256SUMS" || fail "SHA256SUMS must list notes.md (the sign job checks it against the build's hash)"
[ "$(wc -l <"$out/SHA256SUMS")" -eq 8 ] || fail "SHA256SUMS lists $(wc -l <"$out/SHA256SUMS") files, wanted 8"
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

# ===================================================================================================
# sign.sh, with a real throwaway gpg key and stub rpm tools (rpmsign appends a signature line, rpmkeys
# reports one only for a signed file).
# ===================================================================================================
export GNUPGHOME="$tmp/gh"
mkdir -m 700 "$GNUPGHOME"
mkkey() { # DIR NAME: a primary (certify only) with one signing subkey; writes DIR/pub.asc, DIR/subkey.gpg, DIR/full.gpg
	local d="$1" fpr
	mkdir -p "$d"
	gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key "$2 <$2@example.invalid>" ed25519 cert 1d 2>/dev/null
	fpr="$(gpg --batch --list-keys --with-colons 2>/dev/null "$2@example.invalid" | awk -F: '$1 == "fpr" { print $10; exit }')"
	gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$fpr" ed25519 sign 1d 2>/dev/null
	gpg --batch --armor --export "$fpr" 2>/dev/null >"$d/pub.asc"
	gpg --batch --export-secret-subkeys "$fpr" 2>/dev/null >"$d/subkey.gpg"
	gpg --batch --export-secret-keys "$fpr" 2>/dev/null >"$d/full.gpg"
}
mkkey "$tmp/k1" release
mkkey "$tmp/k2" other
# The keys above live in the test's own GNUPGHOME; sign.sh makes its own, so it starts empty.
unset GNUPGHOME

cat >"$stubs/rpmsign" <<'SH'
#!/usr/bin/env bash
# Stub for `rpmsign --addsign --define ... FILE`: appends "SIG:<key>" where the key comes from the
# _gpg_name define, and refuses to run without the __gpg define (the real macro points at a missing gpg2).
set -euo pipefail
name="" gpg="" f=""
while [ "$#" -gt 0 ]; do case "$1" in --define) case "$2" in _gpg_name\ *) name="${2#_gpg_name }" ;; __gpg\ *) gpg="${2#__gpg }" ;; esac; shift 2 ;; --addsign) shift ;; *) f="$1"; shift ;; esac; done
[ -x "$gpg" ] || { echo "stub rpmsign: __gpg is not defined as an executable" >&2; exit 1; }
[ -z "${STUB_NO_SIGN:-}" ] || exit 0
printf 'SIG:%s\n' "${name%!}" >>"$f"
if [ -n "${STUB_CHANGE_PAYLOAD:-}" ]; then printf 'extra\n' >>"$f"; fi
SH
cat >"$stubs/rpmkeys" <<'SH'
#!/usr/bin/env bash
# Stub for `rpmkeys --dbpath DB --import KEY` and `rpmkeys --dbpath DB -Kv FILE`. Like the real one, an
# unsigned file exits 0 and prints no signature line.
set -euo pipefail
db="$2"; shift 2
case "$1" in
--import) cp "$2" "$db/key.asc" ;;
-Kv)
	f="$2"
	echo "$f:"
	if [ -n "${STUB_KEYID_OVERRIDE:-}" ]; then echo "    Header V4 EdDSA/SHA512 Signature, key ID ${STUB_KEYID_OVERRIDE}: OK"; exit 0; fi
	if grep -aq '^SIG:' "$f"; then
		fp="$(grep -a '^SIG:' "$f" | tail -1 | cut -d: -f2)"
		echo "    Header V4 EdDSA/SHA512 Signature, key ID $(tr 'A-F' 'a-f' <<<"${fp: -8}"): OK"
	fi
	echo "    Header SHA256 digest: OK" ;;
esac
SH
chmod +x "$stubs/rpmsign" "$stubs/rpmkeys"

# mkdist DIR: the unsigned artifact of a build job, with the checksums in the shape release.sh writes.
mkdist() {
	local d="$1"
	rm -rf "${d:?}"; mkdir -p "$d"
	printf 'rpm payload agent\n' >"$d/clamfleet-agent-1.0.0-rc.1-1.x86_64.rpm"
	printf 'rpm payload server\n' >"$d/clamfleet-server-1.0.0-rc.1-1.x86_64.rpm"
	printf 'tarball\n' >"$d/clamfleet_1.0.0-rc.1_linux_amd64.tar.gz"
	printf 'notes\n' >"$d/notes.md"
	(cd "$d" && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | LC_ALL=C sort | xargs -d '\n' sha256sum >SHA256SUMS)
}
run_sign() { # DIR PUBKEY [SUMS-SHA] [SUBKEYFILE]
	local d="$1" pub="$2" sums="${3:-}" key="${4:-$tmp/k1/subkey.gpg}"
	[ -n "$sums" ] || sums="$(sha256sum "$d/SHA256SUMS" | cut -d' ' -f1)"
	(RELEASE_SIGNING_SUBKEY_FD=7 "$rel/sign.sh" "$d" "$pub" "$sums" 7<"$key") >"$tmp/out" 2>&1
}
sign_refused() { # NAME TEXT DIR PUBKEY [SUMS] [KEY]
	if run_sign "${@:3}"; then fail "sign.sh: $1: accepted"; fi
	grep -qF -- "$2" "$tmp/out" || fail "sign.sh: $1: refused for another reason (wanted '$2'):
$(cat "$tmp/out")"
}

d="$tmp/dist"
mkdist "$d"
before="$(sha256sum "$d/SHA256SUMS" | cut -d' ' -f1)"
run_sign "$d" "$tmp/k1/pub.asc" || fail "sign.sh: a good run was refused:
$(cat "$tmp/out")"
[ -s "$d/SHA256SUMS.asc" ] || fail "sign.sh wrote no SHA256SUMS.asc"
grep -q "^SIG:" "$d/clamfleet-agent-1.0.0-rc.1-1.x86_64.rpm" || fail "the rpm was not signed"
[ "$before" != "$(sha256sum "$d/SHA256SUMS" | cut -d' ' -f1)" ] || fail "SHA256SUMS was not regenerated after signing"
(cd "$d" && sha256sum -c --quiet SHA256SUMS) || fail "the regenerated SHA256SUMS does not match the signed files"
grep -q '  notes.md$' "$d/SHA256SUMS" || fail "the regenerated SHA256SUMS dropped notes.md"

# The workflow passes DIR and the key relative to the checkout: sign.sh changes directory, so a relative key
# path must be resolved first. Every other case here passes absolute paths, which is how this once got through.
mkdist "$d"
rel_sums="$(sha256sum "$d/SHA256SUMS" | cut -d' ' -f1)"
(cd "$tmp" && RELEASE_SIGNING_SUBKEY_FD=7 "$rel/sign.sh" dist k1/pub.asc "$rel_sums" 7<"$tmp/k1/subkey.gpg") >"$tmp/out" 2>&1 ||
	fail "sign.sh: a relative DIR and public key were refused:
$(cat "$tmp/out")"
[ -s "$d/SHA256SUMS.asc" ] || fail "sign.sh with relative paths wrote no SHA256SUMS.asc"

# publish uploads what release.yml's `find` selects; every file SHA256SUMS lists must be in that set, or
# `sha256sum -c` over the downloaded assets reports a missing file. The real command is cut out of the workflow.
mkdist "$d"
rm -rf "$tmp/pub"; mkdir -p "$tmp/pub/dist"
cp -r "$d" "$tmp/pub/dist/release"
touch "$tmp/pub/dist/release/SHA256SUMS.asc" # present once sign.sh has run
find_cmd="$(grep -m1 -F 'mapfile -d' "$repo/.github/workflows/release.yml" | sed -E "s/^[^<]*< <\((.*)\)\$/\1/")"
[ -n "$find_cmd" ] || fail "cannot find the asset list command in release.yml"
uploaded="$(cd "$tmp/pub" && bash -c "$find_cmd" | tr '\0' '\n' | sed 's|^dist/release/||' | LC_ALL=C sort)"
want_up="$( { awk '{ print $2 }' "$d/SHA256SUMS"; echo SHA256SUMS; echo SHA256SUMS.asc; } | LC_ALL=C sort)"
[ "$uploaded" = "$want_up" ] || fail "release.yml publishes a different file set than SHA256SUMS lists (plus SHA256SUMS and its .asc):
$(diff <(echo "$want_up") <(echo "$uploaded") || true)"

mkdist "$d"
sign_refused "a checksum file that is not the one built" "the build job reported" "$d" "$tmp/k1/pub.asc" "$(printf '0%.0s' $(seq 64))"
mkdist "$d"; printf 'x' >>"$d/clamfleet_1.0.0-rc.1_linux_amd64.tar.gz"
sign_refused "an asset that no longer matches SHA256SUMS" "do not match SHA256SUMS" "$d" "$tmp/k1/pub.asc"
mkdist "$d"
sign_refused "a subkey whose primary is not the published one" "the published key's" "$d" "$tmp/k2/pub.asc"
mkdist "$d"
sign_refused "an export that carries the primary secret key" "PRIMARY secret key" "$d" "$tmp/k1/pub.asc" "" "$tmp/k1/full.gpg"
mkdist "$d"
STUB_NO_SIGN=1 sign_refused "an rpmsign that signs nothing (rpmkeys exits 0 on an unsigned rpm)" "no 'Signature, key ID" "$d" "$tmp/k1/pub.asc"
mkdist "$d"
STUB_CHANGE_PAYLOAD=1 sign_refused "signing that changes the payload" "changed the payload digest" "$d" "$tmp/k1/pub.asc"
mkdist "$d"
STUB_KEYID_OVERRIDE=deadbeef sign_refused "a signature line of another key" "no 'Signature, key ID" "$d" "$tmp/k1/pub.asc"
mkdist "$d"
# Files the build job's checksum file does not list must not be signed along: sign.sh regenerates the sums over
# the directory, so without this check a planted file would be published as if the build had made it.
mkdist "$d"; echo planted >"$d/planted.bin"
sign_refused "an extra file in the directory" "not exactly the ones SHA256SUMS lists" "$d" "$tmp/k1/pub.asc"
mkdist "$d"; rm "$d/notes.md"
sign_refused "a listed file that is missing" "do not match SHA256SUMS" "$d" "$tmp/k1/pub.asc"
mkdist "$d"; echo old >"$d/SHA256SUMS.asc"
sign_refused "a leftover signature file" "not exactly the ones SHA256SUMS lists" "$d" "$tmp/k1/pub.asc"
mkdist "$d"; mkdir "$d/sub"
sign_refused "a directory" "not a regular file" "$d" "$tmp/k1/pub.asc"
mkdist "$d"; ln -s notes.md "$d/link"
sign_refused "a symlink" "not a regular file" "$d" "$tmp/k1/pub.asc"
# Two keys in one stream: the awk parsing stops at the first, so the count of `sec` records must catch it.
cat "$tmp/k1/subkey.gpg" "$tmp/k2/subkey.gpg" >"$tmp/two.gpg"
mkdist "$d"
sign_refused "two keys imported at once" "not exactly one key" "$d" "$tmp/k1/pub.asc" "" "$tmp/two.gpg"
mkdist "$d"
rm "${d:?}"/*.rpm
(cd "$d" && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | xargs sha256sum >SHA256SUMS)
sign_refused "no rpm at all" "no .rpm" "$d" "$tmp/k1/pub.asc"
# The descriptor must be given and must be a number.
mkdist "$d"
if (RELEASE_SIGNING_SUBKEY_FD="" "$rel/sign.sh" "$d" "$tmp/k1/pub.asc" "$(sha256sum "$d/SHA256SUMS" | cut -d' ' -f1)") >"$tmp/out" 2>&1; then fail "sign.sh ran without a key descriptor"; fi

# ===================================================================================================
# verify-tag.sh: a temporary repository, throwaway SSH keys and a stub gh that answers from a file.
# ===================================================================================================
ssh-keygen -q -t ed25519 -N '' -C signer -f "$tmp/sshkey" >/dev/null
ssh-keygen -q -t ed25519 -N '' -C other -f "$tmp/sshother" >/dev/null
allowed="maintainer $(cut -d' ' -f1,2 "$tmp/sshkey.pub")"
export GITHUB_REPOSITORY=clamfleet/clamfleet
cat >"$stubs/gh" <<'SH'
#!/usr/bin/env bash
# Stub for `gh api URL`: answers with the file named by STUB_RUNS, whatever the query says, so that the
# script's own filtering is what the tests exercise.
[ "$1" = api ] || exit 2
case "$2" in repos/clamfleet/clamfleet/actions/workflows/ci.yml/runs\?*) cat "$STUB_RUNS" ;; *) echo "stub gh: unexpected $2" >&2; exit 2 ;; esac
SH
chmod +x "$stubs/gh"

vt="$tmp/vt"
mkdir -p "$vt"
git -C "$vt" init -q -b main
printf '# Changelog\n\n## [1.0.0-rc.1] - 2026-12-01\n\n- notes\n' >"$vt/CHANGELOG.md"
git -C "$vt" add CHANGELOG.md
git -C "$vt" -c commit.gpgsign=false commit -q -m "release commit"
parent="$(git -C "$vt" rev-parse HEAD)"
git -C "$vt" -c commit.gpgsign=false commit -q --allow-empty -m "child commit"
head="$(git -C "$vt" rev-parse HEAD)"

runs() { # SHA CONCLUSION [EVENT] [BRANCH] [STATUS]: a one-run answer
	jq -n --arg sha "$1" --arg c "$2" --arg e "${3:-push}" --arg b "${4:-main}" --arg s "${5:-completed}" \
		'{workflow_runs:[{event:$e, head_branch:$b, head_sha:$sha, status:$s, conclusion:$c, html_url:"https://example.invalid/run/1"}]}'
}
tagit() { # NAME KEY [annotated|light] [unsigned]: tags HEAD
	local name="$1" key="$2" kind="${3:-annotated}"
	git -C "$vt" tag -d "$name" >/dev/null 2>&1 || true
	if [ "$kind" = light ]; then git -C "$vt" tag "$name"
	elif [ "${4:-}" = unsigned ]; then git -C "$vt" tag -a -m "release $name" "$name"
	else git -C "$vt" -c gpg.format=ssh -c "user.signingkey=$key" tag -s -m "release $name" "$name"; fi
}
vtag() { (cd "$vt" && RELEASE_ALLOWED_SIGNERS="${SIGNERS-$allowed}" "$rel/verify-tag.sh" "$@") >"$tmp/out" 2>"$tmp/err"; }
vt_ok() { vtag "$@" || fail "verify-tag: $1 refused: $(cat "$tmp/err")"; }
vt_refused() { # NAME TEXT TAG
	if vtag "$3"; then fail "verify-tag: $1: accepted"; fi
	grep -qF -- "$2" "$tmp/err" || fail "verify-tag: $1: refused for another reason (wanted '$2'): $(cat "$tmp/err")"
}
export STUB_RUNS="$tmp/runs.json"

tagit v1.0.0-rc.1 "$tmp/sshkey"
runs "$head" success >"$STUB_RUNS"
vt_ok v1.0.0-rc.1
[ "$(grep '^commit=' "$tmp/out")" = "commit=$head" ] || fail "verify-tag: wrong commit line: $(cat "$tmp/out")"
[ "$(grep '^tag_object=' "$tmp/out")" = "tag_object=$(git -C "$vt" rev-parse refs/tags/v1.0.0-rc.1)" ] || fail "verify-tag: wrong tag_object line"
[ "$(wc -l <"$tmp/out")" -eq 2 ] || fail "verify-tag: stdout must be exactly the two output lines: $(cat "$tmp/out")"

runs "$parent" success >"$STUB_RUNS"   # Mutation 17: the only green run is for the parent.
vt_refused "a commit whose only green run is for its parent" "no successful push run" v1.0.0-rc.1
runs "$head" failure >"$STUB_RUNS"
vt_refused "a failed run" "no successful push run" v1.0.0-rc.1
runs "$head" success pull_request >"$STUB_RUNS"
vt_refused "a green pull request run" "no successful push run" v1.0.0-rc.1
runs "$head" success push develop >"$STUB_RUNS"
vt_refused "a green run on another branch" "no successful push run" v1.0.0-rc.1
runs "$head" "" push main in_progress >"$STUB_RUNS"
vt_refused "a run still in progress" "no successful push run" v1.0.0-rc.1
echo '{"workflow_runs":[]}' >"$STUB_RUNS"
vt_refused "no run at all" "no successful push run" v1.0.0-rc.1
runs "$head" success >"$STUB_RUNS"

tagit v1.0.0-rc.2 "$tmp/sshkey" annotated unsigned
vt_refused "an unsigned annotated tag" "signature" v1.0.0-rc.2
tagit v1.0.0-rc.3 "$tmp/sshkey" light
vt_refused "a lightweight tag" "lightweight" v1.0.0-rc.3
tagit v1.0.0-rc.4 "$tmp/sshother"
vt_refused "a signer that is not listed" "signature" v1.0.0-rc.4
SIGNERS="" vt_refused "no allowed signers" "RELEASE_ALLOWED_SIGNERS is empty" v1.0.0-rc.1
vt_refused "a tag that does not exist" "no tag" v1.0.0-rc.9
tagit v1.0.0-beta.1 "$tmp/sshkey"
vt_refused "a tag outside the version policy" "version policy" v1.0.0-beta.1
tagit 1.0.0-rc.1 "$tmp/sshkey"
vt_refused "a tag without the v" "does not start with v" 1.0.0-rc.1
tagit v1.0.1 "$tmp/sshkey"
vt_refused "a tag whose version has no changelog section" "no non-empty section" v1.0.1
SIGNERS="maintainer $(cut -d' ' -f1,2 "$tmp/sshother.pub")" vt_refused "a key that did not sign the tag" "signature" v1.0.0-rc.1

# A validly signed tag object, filed under the ref of another tag: the signature is good, the name is not.
tagit v1.0.0-rc.5 "$tmp/sshkey"
git -C "$vt" update-ref refs/tags/v1.0.0-rc.1 "$(git -C "$vt" rev-parse refs/tags/v1.0.0-rc.5)"
vt_refused "a tag object signed for another tag name" "must carry its own name" v1.0.0-rc.1

echo "release_test: ok"
