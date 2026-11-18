<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Contributing to ClamFleet

Thank you for considering it. ClamFleet is a small project with one maintainer, so the rules below
are short and mostly exist to make a review quick. Please read the [Code of Conduct](CODE_OF_CONDUCT.md).
To report a security problem, do **not** open an issue: see [SECURITY.md](SECURITY.md).

## Before you start

- **Open an issue first for anything bigger than a small fix**, so you do not spend a weekend on
  something that cannot be merged. A bug report has a form that asks for versions and logs, and
  asks you to **remove detection paths, tokens, host names and email addresses** from them.
- **A new dependency needs an issue first.** The dependency list is part of the design
  ([docs/HANDOVER.md](docs/HANDOVER.md), section 5); a small piece of code is preferred over a
  package, except for hard, well-solved problems such as cryptography.
- Some things are **public interfaces**: the agent's payload structs (`internal/proto`), the alert
  payload (`internal/alert/payload.go`, pinned by golden files, documented in `docs/alerts.md`),
  and the configuration keys. Changing one needs a schema decision in an issue, never a drive-by edit.
  Golden and recorded files are never regenerated to make a test pass.

## Build and test

You need Go (the version in `go.mod`'s `toolchain` line; the `go` command fetches it if yours is
older) and GNU make.

```
make tools       # staticcheck and sqlc at the versions the project pins
make build       # the two static binaries into bin/
make check       # go vet, staticcheck, sqlc diff, go test ./..., script tests; no container, no network
make ci          # what CI runs: check, plus workflow lint, go mod tidy and gofmt checks, and the test gate
```

`make ci` is the one to run before you push. Its test gate fails on a **skipped** test as well as a
failed one, because a test that skips itself cannot fail when the feature breaks. A test that cannot
run in CI is excluded with a build tag in a reviewed change, never with a runtime `t.Skip`.

The end-to-end suite runs the real agent and server in a container with a real ClamAV and systemd:

```
make e2e-docker  # what CI runs; needs Docker, and builds a Debian 13 image (about 10 minutes)
make e2e         # the same suite in an Incus container you prepare yourself
make e2e-web     # Playwright browser tests of the console
```

[docs/testing.md](docs/testing.md) has the prerequisites of each. If you cannot run one, say so in the
pull request: CI runs them all on a ready pull request.

Some changes (packaging, the AppArmor and SELinux files, the agent) also get an extra test run in virtual
machines on the maintainer's machines, with the mandatory access control enforcing. A CI job tells the maintainer
which pull requests those are. For a pull request from a fork that run happens only after he has read your diff,
because it executes your code there; it may therefore come later than the CI results.

## Writing code

- **Every source, script and config file starts with two lines**:
  `SPDX-License-Identifier: AGPL-3.0-only` and `SPDX-FileCopyrightText: The ClamFleet Authors`
  (in the file's own comment syntax). A test fails if one is missing; the few exceptions are listed
  in `deploy/test/headers_test.sh`. By contributing you license your work under AGPL-3.0-only.
- **Comment the why, not the what.** The code shows what it does; a comment records the reason, the
  constraint, and the alternative that was tried and rejected. A file starts with a short header on
  its purpose; an exported function documents its parameters, results, errors and side effects.
  Remove a comment when you change the code it describes.
- **Show that your test can fail.** Break the code the test guards, watch the test go red, undo the
  break. A test that has never been seen failing is a claim, not a check. A new route or action needs a
  test that goes through the real router, not only a call to the handler.
- **Time and IDs come from an injected source**, never `time.Now()` inside logic you test.
- **Detection file paths are personal data.** They never go in a log line, an audit row, a URL or a
  summary payload.
- Keep dependencies to the standard library where you reasonably can, and bind nothing to a
  non-loopback address in a test or a tool.

## Commits and pull requests

- **Branches (git flow):** branch from `develop` as `feature/<topic>` or `fix/<topic>`, and open the
  pull request against `develop`. `main` holds releases only.
- **One self-contained change per commit**, with its tests. A message is
  `<type>(<scope>): <imperative summary, at most 72 characters>`, a blank line, and then **why**: the
  problem, what breaks without the change, what was tried and rejected. Types are `feat`, `fix`,
  `test`, `docs`, `build`, `ci`, `refactor`, `style`, `chore`. Look at `git log` for the style.
- **Sign off every commit** with `git commit -s` (or `git rebase --signoff` to add it afterwards).
  The sign-off is the [Developer Certificate of Origin](https://developercertificate.org/): you wrote
  the change, or you have the right to submit it, under this project's license. The sign-off email must
  be the commit author's. A check on the pull request fails without it.
- **Privacy:** the name and email in your commits and sign-offs are part of the public history and
  cannot be removed later. If you do not want your real name there, use a name and an address you are
  happy to have public (a GitHub noreply address works).
- **Pull request:** fill in the template. Its important part is the evidence: *what would be true if
  this were broken, and what you ran to show it is not*, and which tests you chose not to write and
  why. Mark it ready for review when `make ci` passes; a draft runs only the quick check, and the full
  suite runs when you mark it ready.
- **What gets it merged:** a green CI and one review by the maintainer. Reviews are about the
  design, the tests and the comments as much as the code. The merge is a merge commit, so your
  commits stay as you wrote them.

## Documentation

Behavior changes update the matching page in `docs/` and the `Unreleased` section of
[CHANGELOG.md](CHANGELOG.md). The CHANGELOG follows Keep a Changelog and the versions follow SemVer.
