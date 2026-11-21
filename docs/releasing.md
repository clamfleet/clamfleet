<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Releasing ClamFleet

The maintainer's runbook. A release is built by `.github/workflows/release.yml` from a signed tag, and nothing
else produces one: **the release key is never on a developer's machine or in CI outside the `sign` job.**
Contributors do not need this page; users who want to check a download need [docs/install.md](install.md#verifying-a-download).

## What a release is

| Asset | Name | Signed by |
|---|---|---|
| Binaries, `LICENSE`, `README.md` | `clamfleet_VERSION_linux_amd64.tar.gz` | `SHA256SUMS.asc` |
| Agent and server packages | `clamfleet-agent_VERSION_amd64.deb`, `clamfleet-server_VERSION_amd64.deb` | `SHA256SUMS.asc` |
| | `clamfleet-agent-VERSION-1.x86_64.rpm`, `clamfleet-server-VERSION-1.x86_64.rpm` | the rpm itself **and** `SHA256SUMS.asc` |
| SBOMs (CycloneDX JSON) | `clamfleet-agent_VERSION_sbom.cdx.json`, `clamfleet-server_VERSION_sbom.cdx.json` | `SHA256SUMS.asc` |
| Checksums and their signature | `SHA256SUMS`, `SHA256SUMS.asc` | the release subkey |

amd64 only in v1. **File names carry the plain version (`1.0.0-rc.1`), never `~`**: the version inside an rc package is `1.0.0~rc.1` (so it sorts before `1.0.0`), but GitHub likely renames a `~` in an asset name, and `SHA256SUMS` would then list names that do not exist (`sha256sum -c --ignore-missing` would skip the packages without a word). `release.sh` renames the files, and `publish` fails unless the asset names GitHub holds equal the files uploaded. `SHA256SUMS` also lists `notes.md`, which is uploaded as an asset next to the others (and is the release text), so `sha256sum -c SHA256SUMS` over a full download finds every listed file and the notes are covered by the checksum the sign job compares with the build job's. The .deb files carry no per-file signature: nothing on a stock Debian checks one (dpkg
ships with `no-debsig`, and `dpkg-sig` is not in Debian 13), so the signed checksums are the check. The
`.rpm` files are signed with the release subkey, which `rpm -Kv` verifies after `rpm --import`.
The server SBOM lists the vendored htmx (a JavaScript file a Go SBOM tool cannot see) next to the Go modules.

### Version policy

Only `X.Y.Z` and `X.Y.Z-rc.N` are released (`N` from 1, no leading zeros): `1.0.0-rc.1`, `1.0.0`. No other
pre-release label and no build metadata: a deb and an rpm each sort a suffix their own way (`~` in a deb), and
every extra label is another case to get right. The tag is the version with a `v`: `v1.0.0-rc.1`.
`release.sh` and `verify-tag.sh` both refuse anything else.

### The CHANGELOG section

Each release needs a section in `CHANGELOG.md` whose heading is exactly `## [VERSION] - YYYY-MM-DD` and whose
body is not empty. Its body becomes the release notes. A tag with no such section is refused. On the release
branch, rename `## Unreleased` to the heading and start a new `## Unreleased` above it holding one placeholder line
(`- Nothing yet.`): `make release-snapshot`, and so the `release-dry-run` job, takes its notes from `Unreleased` and
refuses an empty one. The placeholder is replaced by the next change on `develop`.

## Making a release (git flow)

1. `git switch -c release/VERSION develop`; write the CHANGELOG section; open a PR into `main`. Full CI runs,
   `release-dry-run` included. **Every release candidate needs all L1 targets green** (`make e2e-apparmor`,
   `make e2e-el9`, and the targets later added to the matrix, R1 decision 7) on the release branch's commit,
   whatever `deploy/test/l1-paths.txt` says; whoever runs them keeps the logs (they name hosts, so they stay out
   of the PR).
2. Merge it. The push to `main` runs full CI on the merge commit; **wait for it to pass**: the release
   workflow refuses a commit with no successful push run of `ci.yml` on `main` for exactly that SHA.
3. Tag that merge commit with **your signature** (an SSH key whose public half is in the repository variable
   `RELEASE_ALLOWED_SIGNERS`), check the signature locally the way the workflow will, and only then push:

   ```sh
   git -c gpg.format=ssh -c user.signingkey=~/.ssh/release_signing.pub \
       tag -s -m "ClamFleet 1.0.0-rc.1" v1.0.0-rc.1 <merge-commit>

   # The same allowed-signers format as the variable: one `principal key` line per signer.
   printf 'maintainer %s\n' "$(cut -d' ' -f1,2 ~/.ssh/release_signing.pub)" >/tmp/allowed_signers
   git -c gpg.ssh.allowedSignersFile=/tmp/allowed_signers verify-tag v1.0.0-rc.1   # must print "Good ... signature"

   git push origin v1.0.0-rc.1
   ```

   (`user.signingkey` is the public key file when the private key is in `ssh-agent`, or the private key file.)
   The tag must be annotated; a lightweight tag is refused. The ruleset `release-tags` restricts creating,
   updating and deleting `v*` tags to the maintainer, but a repository administrator can bypass a ruleset,
   so a tag is not immutable: `publish` re-reads the tag through the API and refuses unless it still points at
   the object `verify` accepted, which catches a tag moved during a run. A wrong tag after publishing costs a new
   version, not a retag.
4. The workflow runs `verify` and `build`, then waits at `sign` for your approval of the `release`
   environment (Actions, the run, "Review deployments"). Check the `verify` log first: it names the signer and
   the CI run it accepted.
5. After approval, `publish` creates a **draft** release. Download it and check it as a user would
   (docs/install.md, "Verifying a download"), install on Debian 13 and AlmaLinux 9, then publish the draft.
   A release candidate is marked a pre-release by the workflow.
6. Merge `main` back into `develop`.

If a step fails, fix it through `develop` and cut `release/VERSION+1rc` (`1.0.0-rc.2`); never move a tag.

### Locally

`make release-snapshot` builds and self-checks every unsigned asset into `dist/release` as `0.0.0-rc.1`
(dirty tree allowed, notes from "Unreleased"); `make release VERSION=1.0.0-rc.1` does the same for a real
version on a clean tree. They need `go`, `git`, `jq`, `dpkg-deb`, `rpm`, `rpm2cpio` and `cpio` and refuse, naming
the tool, when one is missing. **Neither signs**, and a local build is never published. The CI job
`release-dry-run` runs the snapshot and then `sign.sh` with a throwaway key on every ready pull request.

## The pipeline, and why it is split

| Job | Holds | Does |
|---|---|---|
| `verify` | read-only token | `deploy/release/verify-tag.sh`: annotated tag, good signature by an allowed key, version policy, full CI success for the exact commit, CHANGELOG section. Outputs the tag object and commit SHAs. |
| `build` | read-only token, **no secrets, no environment** | Checks out the verified commit, asserts `HEAD`, runs `make release`. The unsigned assets are an artifact kept one day; the SHA-256 of `SHA256SUMS` is a job output. |
| `sign` | environment `release`, the secret `RELEASE_SIGNING_SUBKEY` | After approval: `deploy/release/sign.sh`, which runs **no go, make or npm** (`deploy/test/workflows_test.sh` fails the build if it does, or if `secrets.` appears anywhere else). |
| `publish` | `contents: write` | Re-reads the tag through the API and refuses unless it is still the object `verify` accepted, then `gh release create --draft --verify-tag`. |

`sign.sh` signs only what the build job's checksum names; refuses a key that is not a lone signing subkey
whose primary equals `deploy/release/clamfleet-release.asc`; and verifies everything against that published
file, `rpmkeys -Kv` included (it must print `Signature, key ID <subkey>: OK`: an unsigned rpm also exits 0).
`rpmsign` needs `__gpg` defined because its default, `/usr/bin/gpg2`, does not exist on Ubuntu 24.04 (rpm 4.18, the runner the `sign` job uses; other versions were not checked).

What this does not stop: your GitHub account, or a malicious change to `sign.sh` that is reviewed, merged and
tagged. Both are bounded by review, the signed tag, the rulesets and the key's expiry. `verify-tag.sh` and the
workflow come from the tagged commit itself, so the tag rules are what keep an attacker from shipping a
different verifier.

## The release key

Done once, offline, by the maintainer (never on a fleet machine):

1. A certify-only primary key and one signing subkey, RSA-4096 (tested on EL9's rpm 4.16), both expiring in
   two years. Store the primary key and its **revocation certificate** offline.
2. Export **the subkey only**, without a passphrase. If the subkey has a passphrase (it normally does in
   your offline keyring), remove it in a temporary home so the offline keyring is never changed:

   ```sh
   export GNUPGHOME="$(mktemp -d)"                                  # a temporary home, removed at the end
   gpg --homedir ~/offline-gnupg --export-secret-subkeys FINGERPRINT | gpg --batch --import
   gpg --pinentry-mode loopback --passwd FINGERPRINT                # old passphrase, then an EMPTY new one
   gpg --armor --export-secret-subkeys FINGERPRINT > subkey.asc     # this file is the environment secret
   rm -rf "$GNUPGHOME"; unset GNUPGHOME
   ```

   (`--export-secret-subkeys` exports stubs for the primary, so the temporary home never holds the primary
   secret key; `sign.sh` refuses an export that does.) A passphrase kept in the same secret store would
   protect nothing, which is why the export has none. Delete `subkey.asc` once the secret is stored.
3. Publish the public key as `deploy/release/clamfleet-release.asc` (a pull request), and its **fingerprint on an
   independent channel**: README, `SECURITY.md`, your website, keys.openpgp.org. A user compares the file with
   those, so a replaced `.asc` alone cannot pass.
4. Repository settings: the environment secret `RELEASE_SIGNING_SUBKEY` (the armored subkey export) and the
   variable `RELEASE_ALLOWED_SIGNERS` (SSH public keys that may sign tags, one `principal key` line each).

Until step 3 is merged, `sign` refuses to run: there is nothing to verify against.

### Routine rotation

Before the subkey expires: offline, extend it or add a new one; update `clamfleet-release.asc` by pull request;
replace the secret; republish the key. Old signatures stay valid for users who refresh the key.

### The subkey is compromised

1. Delete the environment secret and disable the `release` workflow at once.
2. Offline, revoke **the subkey** with the primary key (reason: compromised) and add a new one.
3. Publish the updated public key (pull request, keys.openpgp.org, website).
4. List the releases signed after the suspected time. For each, rebuild from its signed tag in a fresh
   run and check that the binaries reproduce the published hashes before re-signing with the new subkey;
   one that does not reproduce is withdrawn. Publish an advisory.
5. RPM users: rpm 4.16 is believed to ignore revocations, so tell them to remove the old `gpg-pubkey-<id>`
   (`rpm -e`) and import the new key. (To confirm in the rehearsal on AlmaLinux 9.)

### The primary key is compromised

Publish the stored revocation certificate. A new key has a **new fingerprint**, announced on every
independent channel; every supported release is re-signed, with an advisory.

## The distribution containers

Level 2 of R1 decision 1 (`l2` in CI, `docs/testing.md`, "The distribution containers") is four images that follow
their distributions. What the maintainer does with them:

- **Digests move only by pull request.** Dependabot proposes the base images and the shared ClamAV image monthly, one
  pull request per directory (`deploy/test/ci`, `deb`, `rpm`). The ClamAV digest is in all three Dockerfiles and
  `deploy/test/ci/signatures_test.sh` fails until they agree: merge the three together. Read a new digest from the registry
  API, never by hand, and record it in the commit.
- **A release leaves the matrix** when its support ends (R1 decision 4: Ubuntu 22.04 on 2027-05-31, Debian 12 on
  2028-06-30): remove its leg, its facts row and its required check, the ruleset first. A release enters it with a leg
  in the workflow, a stage in the Dockerfile, a facts row and the added check names (R1 decision 8).
- **The ClamAV floor is 1.4.** A build that resolves an older clamd fails on purpose; it is the release's claim, not a
  tooling detail. Ubuntu 22.04 depends on `jammy-updates` for it.
- **A red leg is a finding.** Distribution updates can turn one red; fix it in its own pull request, never by re-running.
  A leg that cannot be fixed before a release is listed as "untested" in the release notes (R1 decision 5).

## Repository settings (the maintainer, once the repository is public)

Rulesets and environment reviewers do not exist on the free plan while a repository is private, so these
are set after the switch. The required checks are the job names `check`, `e2e`, `web`, `dco` and
`release-dry-run`, and the four checks of the matrix job `l2` (`l2 (debian-12)`, `l2 (ubuntu-22.04)`, `l2 (rocky-9)`, `l2 (almalinux-10)`). **Renaming or removing one blocks every merge until the ruleset is changed first**: change
the ruleset, then the workflow.

```sh
# protect: the checks, on main and develop. No bypass: the maintainer's own pull requests meet the checks too.
# integration_id 15368 is GitHub Actions: without it a status of that name posted by any other app counts.
gh api -X POST repos/clamfleet/clamfleet/rulesets --input - <<'JSON'
{
  "name": "protect", "target": "branch", "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/main", "refs/heads/develop"], "exclude": [] } },
  "rules": [
    { "type": "required_status_checks", "parameters": { "strict_required_status_checks_policy": false,
      "required_status_checks": [
        { "context": "check", "integration_id": 15368 }, { "context": "e2e", "integration_id": 15368 },
        { "context": "web", "integration_id": 15368 }, { "context": "dco", "integration_id": 15368 },
        { "context": "release-dry-run", "integration_id": 15368 },
        { "context": "l2 (debian-12)", "integration_id": 15368 }, { "context": "l2 (ubuntu-22.04)", "integration_id": 15368 },
        { "context": "l2 (rocky-9)", "integration_id": 15368 }, { "context": "l2 (almalinux-10)", "integration_id": 15368 } ] } },
    { "type": "non_fast_forward" },
    { "type": "deletion" }
  ]
}
JSON

# review: one approval, on main and develop. The maintainer bypasses it for pull requests only.
# NOTE: the bypass actor (the repository Admin role is believed to be actor_id 5) and the value
# "pull_request" for bypass_mode are believed correct: check them against the REST API reference for
# rulesets before running this.
gh api -X POST repos/clamfleet/clamfleet/rulesets --input - <<'JSON'
{
  "name": "review", "target": "branch", "enforcement": "active",
  "bypass_actors": [ { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request" } ],
  "conditions": { "ref_name": { "include": ["refs/heads/main", "refs/heads/develop"], "exclude": [] } },
  "rules": [ { "type": "pull_request", "parameters": { "required_approving_review_count": 1,
      "dismiss_stale_reviews_on_push": true, "require_code_owner_review": false,
      "require_last_push_approval": false, "required_review_thread_resolution": false } } ]
}
JSON

# release-tags: v* tags can be created only by the maintainer, and never moved or deleted.
gh api -X POST repos/clamfleet/clamfleet/rulesets --input - <<'JSON'
{
  "name": "release-tags", "target": "tag", "enforcement": "active",
  "bypass_actors": [ { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" } ],
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [ { "type": "creation" }, { "type": "update" }, { "type": "deletion" } ]
}
JSON
```

### Adding a required check (R1 decision 8)

The new check's name is not guessed: a matrix job's context is GitHub's `job (leg)` name, and a wrong guess in the
ruleset blocks every merge. So, per pull request that adds a job:

1. The pull request adds the job, its name in `REQUIRED` and `ALLOWED` in `deploy/test/workflows_test.sh`, and the
   name in `CLAUDE.md`, `docs/testing.md` and the JSON above. Its own run shows the exact check names.
2. **Before it merges**, the maintainer reads the names from that run and updates `protect`: a `PUT` of the whole
   rule list (the existing contexts plus the new ones, each with `"integration_id": 15368`), then reads the
   ruleset back and compares it with the JSON in this page.
3. Then the pull request is merged. Every other open pull request now waits for checks it has never run: it merges
   `develop` first.

Renaming or removing a required check: the ruleset first, then the workflow. A job that is not in the ruleset (like
`l1-paths`) is never listed in `REQUIRED`.

Keeping the checks in a ruleset of their own, with no bypass, is what makes the maintainer's bypass of `review` skip
the approval and nothing else.

Also: the `release` environment with the maintainer as required reviewer (**"prevent self-review" off**: he
both pushes the tag and approves it) and deployments only from tags `v*`; Actions limited to GitHub-owned
actions with SHA pinning required, a read-only default token, and approval for first-time fork contributors;
merge commits only (a squash or rebase would drop sign-offs); private vulnerability reporting, secret
scanning with push protection, and Dependabot alerts.
