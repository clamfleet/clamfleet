<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Security policy

## Supported versions

The latest minor release is supported: it gets security fixes. Older minor releases do not.
Before the first release, only the current `develop` branch is.

## Reporting a vulnerability

Please report it privately, not in a public issue or pull request.

1. **Preferred: GitHub private vulnerability reporting.** Open the Security tab of this repository and
   choose "Report a vulnerability", or go to
   <https://github.com/clamfleet/clamfleet/security/advisories/new>. Only the maintainers (the repository administrators) see the report.
2. **Or write to hi@madalin.me.**

Include what you can of:

- the version (`clamfleet-agent version`, `clamfleet-server version`) and the distribution;
- what you did, what happened, and what you expected;
- the component (agent, server, the console, the packages) and the configuration that matters;
- a proof of concept, if you have one.

**Please remove personal data first.** Detection file paths, host names, email addresses and tokens
are personal or secret data: replace them with placeholders in logs and screenshots. A report that
needs the real value to be understood is fine, and you can tell us so.

## What to expect

ClamFleet has one maintainer, so these are modest targets that one person can keep:

- **an acknowledgement within 7 days**;
- **an assessment within 14 days**: whether we consider it a vulnerability, and how severe;
- **a fix or a mitigation within 90 days**, sooner for something serious.

We ask you to keep the details private until a fix is released, or until 90 days have passed,
whichever is first (coordinated disclosure). If a fix needs longer, we will tell you why and agree a
date with you. You will be credited in the advisory unless you prefer not to be.

We publish each fixed vulnerability as a GitHub security advisory, and request a CVE through GitHub
when it qualifies.

## Verifying what you download

Releases are built from signed tags. The checksums and the `.rpm` packages are signed with the
project's release key (`deploy/release/clamfleet-release.asc`);
[docs/install.md](docs/install.md#verifying-a-download) describes how to verify a download.

**Release key** (`ClamFleet Release <hi@madalin.me>`, RSA-4096, both keys expire 2028-11-19):

- Primary (certify only): `EEF3 BD8A 0FDA 41C0 C451 8B44 36E3 A39F 1BE2 6893`
- Signing subkey: `9ADD 4EBC D2FA 7C59 7280 D078 5605 86D7 BCFD 57AF`

The README repeats this list, but it is a copy in the same repository. The independent channels, the
maintainer's website and keys.openpgp.org, **will list** the fingerprint (neither does yet), so that a
change to this repository alone cannot replace it unnoticed. Compare the key file with those once they do.
