<!--
SPDX-License-Identifier: AGPL-3.0-only
SPDX-FileCopyrightText: The ClamFleet Authors
-->

# Vendored static assets

The console serves its own assets: no CDN, no third-party request from the
browser (GDPR, and the CSP allows only `'self'`).

| File | What | Version | Licence | SHA-256 |
|---|---|---|---|---|
| `htmx-2.0.11.min.js` | htmx, unmodified `dist/htmx.min.js` of the npm package `htmx.org` | 2.0.11 | 0BSD | `d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717` |
| `app.css` | The console's own stylesheet | n/a | AGPL-3.0-only | n/a |

`htmx-2.0.11.min.js` carries no licence header of its own (it is minified); this
file covers it. Source: <https://registry.npmjs.org/htmx.org/-/htmx.org-2.0.11.tgz>,
npm integrity
`sha512-Thx/WtpeOQqSrqBCw/A1cwGJGg4UrVa3+sW0GmrM3p4gJgO89ecH4qtbnyzDDWFvBTqjnIMCgELTNt636dtamA==`
(checked by `npm pack`). `TestStaticHtmxPinned` fails when a byte of the file differs from the
SHA-256 above, so an edit or a swap of the file cannot go unnoticed.

To upgrade: download the new version from the npm registry, check its integrity, copy
`dist/htmx.min.js` to `htmx-<version>.min.js` (the file name carries the version, which is what
makes the one-day cache in the response headers safe), update this table, the template reference
in `templates/layout.html` and the constant in `web_test.go`.

htmx is configured for the strict Content-Security-Policy in `templates/layout.html` through
`<meta name="htmx-config">`: no `eval`, no inline styles, no script tags in responses, and no
history snapshots in the browser's storage (the pages hold fleet data and one-time tokens).
