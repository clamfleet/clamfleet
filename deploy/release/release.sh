#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# release.sh VERSION - builds every UNSIGNED release asset into $OUT (default dist/release) and checks what
# it built: the tarball, the .deb and .rpm of the agent and the server, one CycloneDX SBOM per binary,
# SHA256SUMS and notes.md (the CHANGELOG section); asset names never contain "~". It never signs: sign.sh does that, in a separate job
# that holds the only secret, so no build tool ever runs next to the signing key (docs/releasing.md).
#
# Why a script and not goreleaser: goreleaser cannot load our nfpm files and its prebuilt builder is Pro-only
# (milestone 6c decision 1), so this is a short script around `make packages`.
#
# Needs: go, git, realpath, tar, gzip, sha256sum, dpkg-deb, rpm, rpm2cpio, cpio, jq. A missing one is a refusal with
# its name, never a skipped step: a self-check that did not run is worse than none.
#
# Environment:
#   OUT                  output directory (default dist/release), emptied first; must be inside the repository
#   MAKE                 the make command (default make); the tests replace it
#   CYCLONEDX_VERSION    cyclonedx-gomod version to `go run` (the Makefile passes its pin)
#   CYCLONEDX_CMD        replaces the `go run` command entirely; the tests use a stub
#   RELEASE_SNAPSHOT=1   `make release-snapshot` only: accepts a dirty tree and takes the notes from
#                        "Unreleased", and only for VERSION 0.0.0-rc.1. A snapshot is never signed or published.
#
# Side effects: runs `make packages` (writes bin/ and $OUT), runs the built binaries (`version`), and `go run`
# of cyclonedx-gomod (the module cache; network if the module is not cached).
# Exit status: 0 every asset built and every check passed; 1 anything else.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

die() { echo "release.sh: $*" >&2; exit 1; }

[ "$#" -eq 1 ] || die "usage: release.sh VERSION (for example 1.0.0-rc.1)"
version="$1"
OUT="${OUT:-dist/release}"
MAKE="${MAKE:-make}"
CYCLONEDX_VERSION="${CYCLONEDX_VERSION:-v1.12.0}"
snapshot="${RELEASE_SNAPSHOT:-}"

# Rule: only X.Y.Z and X.Y.Z-rc.N are releases (lib.sh).
release_version_ok "$version" || die "version '$version' is outside the policy X.Y.Z or X.Y.Z-rc.N (no 'v' prefix, no leading zeros, no other labels)"
if [ -n "$snapshot" ] && [ "$version" != "0.0.0-rc.1" ]; then
	die "RELEASE_SNAPSHOT is only for VERSION 0.0.0-rc.1, not $version"
fi

# Prerequisites first, all of them, so one run names every missing tool.
missing=""
for tool in go git tar gzip sha256sum dpkg-deb rpm rpm2cpio cpio jq; do
	command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
[ -z "$missing" ] || die "missing tools:$missing"

cd "$repo"

# $OUT is emptied with rm -rf below, so it must be a directory this script may destroy. Rule: strictly inside
# the repository (relative paths count from the repository root, as everything after the cd above does), and
# not inside .git. That excludes /, ., .., the repository itself and every parent of it, whatever way they are
# spelled (a trailing slash, dist/../.., a symlink): realpath -m resolves the spelling first. An OUT outside the
# repository is refused too; nothing here needs one, and a mistyped one is exactly how rm -rf goes wrong.
out_abs="$(realpath -m -- "$OUT")"
case "$out_abs" in
"$repo"/.git | "$repo"/.git/*) die "OUT '$OUT' is inside .git" ;;
"$repo"/?*) ;;
*) die "OUT '$OUT' is not a directory inside the repository $repo: it is emptied, so it must not be the repository, a parent of it, or elsewhere" ;;
esac
OUT="$out_abs"

# An exported E2E_BUILD_TAGS would put the test-only migration into a release binary. `make build` refuses it
# too, but a refusal that lives only in the Makefile is one edit from gone.
[ -z "${E2E_BUILD_TAGS:-}" ] || die "E2E_BUILD_TAGS is set ('$E2E_BUILD_TAGS'): a release must never carry test-only build tags"

if [ -z "$snapshot" ] && [ -n "$(git status --porcelain)" ]; then
	die "the worktree is not clean: a release is built from a commit, nothing else"
fi
commit="$(git rev-parse HEAD)"

# Notes. A release with no CHANGELOG section is refused so the notes cannot be forgotten at release time.
if [ -n "$snapshot" ]; then
	notes="$(awk '/^## Unreleased/ { insec = 1; next } /^## / { insec = 0 } insec { print }' CHANGELOG.md)"
	[ -n "$notes" ] || die "CHANGELOG.md has no Unreleased section"
else
	notes="$(changelog_section "$version" CHANGELOG.md)" || die "CHANGELOG.md has no non-empty section '## [$version] - YYYY-MM-DD'"
fi

# The tarball and the packages must carry the commit's timestamp, not the build's, or two builds of one
# commit differ. nfpm honours SOURCE_DATE_EPOCH too.
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct "$commit")"
export SOURCE_DATE_EPOCH

rm -rf "$OUT"
# PKG_DIR=$OUT: the packages land where the other assets go. The Makefile empties PKG_DIR first, which is
# why this runs before anything else is written there.
$MAKE packages VERSION="$version" PKG_DIR="$OUT"
printf '%s\n' "$notes" >"$OUT/notes.md"

# Asset names carry the plain version, never "~". nfpm names an rc package 1.0.0~rc.1 (the version INSIDE the
# package must keep the "~" so an rc sorts before the release), but GitHub likely renames "~" in an asset name,
# and then SHA256SUMS would list names that do not exist: `sha256sum -c --ignore-missing` would skip the
# packages without a word. The publish job also compares the names GitHub holds with the files uploaded.
rpm_version="${version/-/\~}"
for pkg in clamfleet-agent clamfleet-server; do
	for pair in "${pkg}_${rpm_version}_amd64.deb ${pkg}_${version}_amd64.deb" "${pkg}-${rpm_version}-1.x86_64.rpm ${pkg}-${version}-1.x86_64.rpm"; do
		read -r from to <<<"$pair"
		[ -f "$OUT/$from" ] || die "make packages did not produce $from"
		[ "$from" = "$to" ] || mv "$OUT/$from" "$OUT/$to"
	done
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --- Tarball: both binaries, LICENSE, README.md, deterministic. -------------------------------------------
tarball="clamfleet_${version}_linux_amd64.tar.gz"
stage="$tmp/stage/clamfleet_${version}_linux_amd64"
mkdir -p "$stage"
install -m 0755 bin/clamfleet-agent bin/clamfleet-server "$stage/"
install -m 0644 LICENSE README.md "$stage/"
# --sort=name, fixed owner and mtime and `gzip -n` (no name or time in the header) make the bytes a function
# of the inputs: anyone can rebuild the binaries from the tag and compare hashes.
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
	-C "$tmp/stage" -cf - "clamfleet_${version}_linux_amd64" | gzip -n >"$OUT/$tarball"

# --- SBOMs. -----------------------------------------------------------------------------------------------
# One per binary, from the built binary. Version and name checks below. -noserial and -notimestamp keep
# the file a function of the binary.
if [ -n "${CYCLONEDX_CMD:-}" ]; then
	read -r -a cdx <<<"$CYCLONEDX_CMD"
else
	cdx=(go run "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@${CYCLONEDX_VERSION}")
fi
for name in clamfleet-agent clamfleet-server; do
	"${cdx[@]}" bin -json -noserial -notimestamp -output "$OUT/${name}_${version}_sbom.cdx.json" -version "$version" "$stage/$name"
done

# htmx is a vendored JavaScript file, invisible to a Go SBOM tool. Only the server embeds internal/web.
htmx_files=(internal/web/static/htmx-*.min.js)
[ "${#htmx_files[@]}" -eq 1 ] && [ -f "${htmx_files[0]}" ] || die "expected exactly one internal/web/static/htmx-*.min.js"
htmx_file="${htmx_files[0]}"
server_sbom="$OUT/clamfleet-server_${version}_sbom.cdx.json"
jq --slurpfile extra deploy/release/sbom-extra.json '.components += [$extra[0].component]' "$server_sbom" >"$tmp/server.sbom.json"
mv "$tmp/server.sbom.json" "$server_sbom"

# --- Checksums. -------------------------------------------------------------------------------------------
# Every file, sorted by name in the C locale, so the file is the same everywhere. notes.md is listed too: it is the
# release text and also an uploaded asset (release.yml), so `sha256sum -c` over the downloads finds every listed file,
# and the sign job's check against the build job's hash of this file covers the notes as well. sign.sh can insist
# that the directory holds exactly what is listed.
write_sums() {
	(cd "$OUT" && find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name SHA256SUMS.asc -printf '%f\n' |
		LC_ALL=C sort | xargs -d '\n' sha256sum >SHA256SUMS)
}
write_sums

# --- Self-check. ------------------------------------------------------------------------------------------
# Each check names what it found. None is skippable: a release that cannot prove these is not shipped.
(cd "$OUT" && sha256sum -c --quiet SHA256SUMS) || die "SHA256SUMS does not match the assets"

mkdir -p "$tmp/check"
tar -xzf "$OUT/$tarball" -C "$tmp/check"
tbin="$tmp/check/clamfleet_${version}_linux_amd64"
sha_of() { sha256sum "$1" | cut -d' ' -f1; }

for name in clamfleet-agent clamfleet-server; do
	# Rule: a binary announces exactly the release version: no "+e2e_migration", no default 0.0.0-dev.
	got="$("$tbin/$name" version)"
	[ "$got" = "$name $version" ] || die "$name prints '$got', wanted '$name $version'"

	# The binary must be the commit's, built from a clean tree (Go stamps both into every binary).
	info="$(go version -m "$tbin/$name")"
	rev="$(awk '$1 == "build" && $2 ~ /^vcs\.revision=/ { sub(/^vcs\.revision=/, "", $2); print $2 }' <<<"$info")"
	# HEAD is read again here: a checkout that moved during the build must not pass because both sides
	# were read before it moved.
	now="$(git rev-parse HEAD)"
	[ "$rev" = "$now" ] && [ "$now" = "$commit" ] || die "$name was built from revision '${rev:-none}', HEAD is $now (it was $commit when this script started)"
	if [ -z "$snapshot" ]; then
		grep -q $'\tbuild\tvcs.modified=false$' <<<"$info" || die "$name was built from a modified tree"
	fi

	# Payload equality: the file inside each package is byte for byte the tarball's (a package that had
	# been built by another step would otherwise be a different program with the same version).
	want="$(sha_of "$tbin/$name")"
	deb="$OUT/${name}_${version}_amd64.deb"
	rpmf="$OUT/${name}-${version}-1.x86_64.rpm"
	[ -f "$deb" ] || die "missing $deb"
	[ -f "$rpmf" ] || die "missing $rpmf"
	got="$(dpkg-deb --fsys-tarfile "$deb" | tar -xO "./usr/bin/$name" | sha256sum | cut -d' ' -f1)"
	[ "$got" = "$want" ] || die "the binary in $(basename "$deb") differs from the tarball's"
	# The glob (not "./usr/bin/...") because rpm2cpio names members "./usr/bin/x" and a plain cpio archive "usr/bin/x".
	got="$(rpm2cpio "$rpmf" | cpio -i --quiet --to-stdout "*usr/bin/$name" | sha256sum | cut -d' ' -f1)"
	[ "$got" = "$want" ] || die "the binary in $(basename "$rpmf") differs from the tarball's"

	# Package metadata: the version a user's package manager sees ("~" sorts an rc before the release) and the arch.
	[ "$(dpkg-deb -f "$deb" Package)" = "$name" ] || die "$(basename "$deb"): wrong Package"
	[ "$(dpkg-deb -f "$deb" Version)" = "$rpm_version" ] || die "$(basename "$deb"): Version is '$(dpkg-deb -f "$deb" Version)', wanted $rpm_version"
	[ "$(dpkg-deb -f "$deb" Architecture)" = "amd64" ] || die "$(basename "$deb"): wrong Architecture"
	got="$(rpm -qp --qf '%{NAME} %{VERSION} %{ARCH}' "$rpmf")"
	[ "$got" = "$name $rpm_version x86_64" ] || die "$(basename "$rpmf"): header says '$got', wanted '$name $rpm_version x86_64'"

	# SBOM: format, subject, and the module set. The set is compared with `go list`, which reads the
	# source and not the binary, so a tool that mis-read the binary (or one that was handed the wrong
	# one) cannot agree with it by accident. Comparison rule: a purl is reduced to `module@version`
	# (the `pkg:golang/` prefix, the `?qualifiers` and the `#subpath` are dropped, case is kept) and the
	# two sets must be equal, nothing more and nothing less. The main module is excluded on both sides.
	sbom="$OUT/${name}_${version}_sbom.cdx.json"
	[ "$(jq -r .bomFormat "$sbom")" = "CycloneDX" ] || die "$sbom: bomFormat is not CycloneDX"
	[ "$(jq -r .metadata.component.version "$sbom")" = "$version" ] || die "$sbom: subject version is not $version"
	jq -e --arg n "$name" '.metadata.component.purl | endswith("#cmd/" + $n)' "$sbom" >/dev/null || die "$sbom: the subject is not cmd/$name"
	jq -r '.components[] | select((.purl // "") | startswith("pkg:golang/")) | .purl' "$sbom" |
		sed -E 's|^pkg:golang/||; s/[?#].*$//' | LC_ALL=C sort -u >"$tmp/sbom.set"
	go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}}{{end}}{{end}}' "./cmd/$name" | LC_ALL=C sort -u | sed '/^$/d' >"$tmp/golist.set"
	diff_out="$(diff "$tmp/golist.set" "$tmp/sbom.set")" || die "$sbom: its Go modules differ from 'go list -deps ./cmd/$name' (< go list, > SBOM):
$diff_out"
done

# htmx: in the server SBOM, with the vendored file's hash, and in no other. The version in the SBOM must
# be the one in the file name (a bumped file with a stale SBOM entry is refused).
htmx_sha="$(sha_of "$htmx_file")"
htmx_ver="$(basename "$htmx_file" | sed -E 's/^htmx-(.*)\.min\.js$/\1/')"
got="$(jq -r '[.components[] | select(.name == "htmx.org")] | map(.version + " " + (.hashes[] | select(.alg == "SHA-256") | .content)) | join(",")' "$server_sbom")"
[ "$got" = "$htmx_ver $htmx_sha" ] || die "the server SBOM lists htmx as '${got:-nothing}', the vendored file is '$htmx_ver $htmx_sha'"
jq -e '[.components[] | select(.name == "htmx.org")] | length == 0' "$OUT/clamfleet-agent_${version}_sbom.cdx.json" >/dev/null || die "the agent SBOM must not list htmx"

echo "release.sh: $version at $commit: $(wc -l <"$OUT/SHA256SUMS") assets in $OUT, every check passed"
if [ -n "$snapshot" ]; then echo "release.sh: this is a snapshot: never sign or publish it"; fi
