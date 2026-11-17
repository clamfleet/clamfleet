#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: The ClamFleet Authors
#
# sign.sh DIR EXPECTED_PUBKEY EXPECTED_SUMS_SHA256 - signs the .rpm files in DIR (rpmsign) and SHA256SUMS
# (a detached, armored signature), then verifies everything against the PUBLISHED key only.
#
#   DIR                    the unsigned assets release.sh built (the artifact of the build job)
#   EXPECTED_PUBKEY        the armored public key committed in the repository (deploy/release/clamfleet-release.asc)
#   EXPECTED_SUMS_SHA256   the SHA-256 of SHA256SUMS as the build job reported it: what we sign is what was built
#   RELEASE_SIGNING_SUBKEY_FD   (environment) the number of an open file descriptor that yields the secret
#                          SUBKEY export (gpg --export-secret-subkeys, no passphrase). It is read once, into a
#                          temporary GNUPGHOME, and never written anywhere else.
#
# This is the only script that sees the signing key, and it runs in the `sign` job, which runs no build tool.
# So it runs no go, no make and no network, and needs only gpg, gpgv, rpm, rpmsign, rpmkeys and coreutils
# (installed before the key exists). Do not add a dependency here without moving it out of reach of the key.
#
# Refuses (exit 1) unless: the checksums are the ones built; the imported key is a signing subkey WITHOUT its
# primary (an offline primary key must never reach CI) and the subkey's primary equals EXPECTED_PUBKEY's;
# an rpm's payload digest is unchanged by signing; and the signatures verify against EXPECTED_PUBKEY alone,
# which for an rpm means rpmkeys prints a `Signature, key ID <subkey>: OK` line. The exit code of
# `rpmkeys -Kv` is not enough: an UNSIGNED rpm exits 0 and says "digests OK" (verified on rpm 4.16).
#
# Side effects: rewrites the .rpm files, SHA256SUMS and SHA256SUMS.asc in DIR; a temporary directory, removed on exit.
set -euo pipefail

die() { echo "sign.sh: $*" >&2; exit 1; }

[ "$#" -eq 3 ] || die "usage: sign.sh DIR EXPECTED_PUBKEY EXPECTED_SUMS_SHA256"
dir="$1"
pubkey="$2"
want_sums="$3"
fd="${RELEASE_SIGNING_SUBKEY_FD:-}"
[[ "$fd" =~ ^[3-9]$|^[1-9][0-9]+$ ]] || die "RELEASE_SIGNING_SUBKEY_FD must be the number of an open descriptor (3 or higher)"
[ -d "$dir" ] || die "$dir is not a directory"
[ -f "$pubkey" ] || die "$pubkey is not a file"
[[ "$want_sums" =~ ^[0-9a-f]{64}$ ]] || die "EXPECTED_SUMS_SHA256 is not a SHA-256"

missing=""
for tool in gpg gpgv rpm rpmsign rpmkeys sha256sum; do
	command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
[ -z "$missing" ] || die "missing tools:$missing"
gpgbin="$(command -v gpg)"

cd "$dir"

# 1. We sign what the build job built. A swapped artifact changes this hash.
[ -f SHA256SUMS ] || die "no SHA256SUMS in $dir"
got="$(sha256sum SHA256SUMS | cut -d' ' -f1)"
[ "$got" = "$want_sums" ] || die "SHA256SUMS is $got, the build job reported $want_sums"
sha256sum -c --quiet SHA256SUMS || die "the assets do not match SHA256SUMS"

# 2. A private GNUPGHOME for the key (mode 700 from mktemp -d), always removed.
work="$(mktemp -d)"
export GNUPGHOME="$work/secret"
mkdir -m 700 "$GNUPGHOME"
cleanup() {
	gpgconf --homedir "$GNUPGHOME" --kill all >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

# The published key's primary fingerprint, read without importing it anywhere.
want_primary="$(gpg --batch --show-keys --with-colons "$pubkey" | awk -F: '$1 == "pub" { f = 1; next } f && $1 == "fpr" { print toupper($10); exit }')"
[ -n "$want_primary" ] || die "no key in $pubkey"

gpg --batch --quiet --import <&"$fd" 2>/dev/null || die "could not import the signing subkey from descriptor $fd"

# Parse the imported secret key (colon format): the primary, whether its secret half is present
# (field 15 is "#" for a stub), and every signing-capable subkey. Field 12 holds a subkey's own capabilities.
listing="$(gpg --batch --list-secret-keys --with-colons)"
primary="$(awk -F: '$1 == "sec" { f = 1; next } f && $1 == "fpr" { print toupper($10); exit }' <<<"$listing")"
primary_stub="$(awk -F: '$1 == "sec" { print ($15 == "#") ? "yes" : "no"; exit }' <<<"$listing")"
subs="$(awk -F: '$1 == "ssb" { sign = ($12 ~ /s/); next } sign && $1 == "fpr" { print toupper($10); sign = 0 }' <<<"$listing")"
[ "$(wc -l <<<"$primary")" -eq 1 ] && [ -n "$primary" ] || die "the imported material is not exactly one key"
[ "$primary_stub" = "yes" ] || die "the imported key carries its PRIMARY secret key: export only the signing subkey (gpg --export-secret-subkeys)"
[ -n "$subs" ] && [ "$(wc -l <<<"$subs")" -eq 1 ] || die "the imported key must have exactly one signing subkey"
subfpr="$subs"
[ "$primary" = "$want_primary" ] || die "the imported key's primary is $primary, the published key's is $want_primary"
subid="$(tr 'A-F' 'a-f' <<<"${subfpr: -8}")"

# 3. Sign every rpm and prove the payload did not change (a signature covers the header; the payload
# digest is in it, so a changed payload would be a different program under a valid signature).
shopt -s nullglob
rpms=(./*.rpm)
[ "${#rpms[@]}" -gt 0 ] || die "no .rpm in $dir"
for f in "${rpms[@]}"; do
	before="$(rpm -qp --qf '%{PAYLOADDIGEST}' "$f")"
	[ -n "$before" ] || die "$f: no payload digest"
	# __gpg: rpm's macro points at /usr/bin/gpg2, which Debian and Ubuntu do not ship ("Could not exec gpg",
	# verified on Ubuntu 24.04, rpm 4.18). _gpg_name with a trailing "!" selects exactly this subkey.
	rpmsign --addsign --define "__gpg $gpgbin" --define "_gpg_name ${subfpr}!" --define "_gpg_path $GNUPGHOME" "$f" >/dev/null ||
		die "rpmsign failed on $f"
	after="$(rpm -qp --qf '%{PAYLOADDIGEST}' "$f")"
	[ "$before" = "$after" ] || die "$f: signing changed the payload digest"
done

# 4. New checksums (the rpms changed), then the signature over them. Same file set as release.sh.
find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name SHA256SUMS.asc ! -name notes.md -printf '%f\n' |
	LC_ALL=C sort | xargs -d '\n' sha256sum >SHA256SUMS
rm -f SHA256SUMS.asc
gpg --batch --yes --armor --detach-sign --local-user "${subfpr}!" --output SHA256SUMS.asc SHA256SUMS ||
	die "could not sign SHA256SUMS"

# 5. Verify with the PUBLISHED key and nothing else: a fresh GNUPGHOME (so the secret half cannot help), and
# an empty rpm database that gets the published key only.
ver="$work/verify"
mkdir -m 700 "$ver" "$ver/rpmdb"
GNUPGHOME="$ver" gpg --batch --quiet --import "$pubkey" 2>/dev/null || die "cannot import $pubkey"
GNUPGHOME="$ver" gpg --batch --export >"$ver/pub.gpg"
status="$(gpgv --status-fd 1 --keyring "$ver/pub.gpg" SHA256SUMS.asc SHA256SUMS 2>/dev/null)" || die "SHA256SUMS.asc does not verify against $pubkey"
# VALIDSIG <signing fpr> ... <primary fpr>: both must be the ones we mean.
awk -v sub_="$subfpr" -v pri="$want_primary" '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { ok = (toupper($3) == sub_ && toupper($NF) == pri) } END { exit ok ? 0 : 1 }' <<<"$status" ||
	die "SHA256SUMS.asc is not a valid signature by the signing subkey of the published key"

rpmkeys --dbpath "$ver/rpmdb" --import "$pubkey" || die "rpmkeys cannot import $pubkey"
for f in "${rpms[@]}"; do
	out="$(rpmkeys --dbpath "$ver/rpmdb" -Kv "$f")" || die "$f: rpmkeys -Kv failed: $out"
	grep -Eq "Signature, key ID ([0-9a-f]{8})?${subid}: OK" <<<"$out" || die "$f: no 'Signature, key ID ${subid}: OK' line (unsigned or signed by another key): $out"
done

echo "sign.sh: signed ${#rpms[@]} rpm(s) and SHA256SUMS with subkey ${subfpr}, verified against the published key"
