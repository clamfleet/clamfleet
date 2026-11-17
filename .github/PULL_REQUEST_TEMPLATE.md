## What and why

<!-- What does this change, and what problem does it solve? The commit messages hold the detail. -->

## Evidence

**What would be true if this were broken, and what did you run to show it is not?**

<!-- A passing pipeline proves only the tests that exist. Name the test that fails if this change is wrong, and say you watched it fail. -->

## Tests not written, and why

<!-- "None skipped" is an answer. An unstated skip looks like an oversight. -->

## Checklist

- [ ] `make ci` passes (or `make check` where you cannot run the rest, and I say so above)
- [ ] every commit is signed off (`git commit -s`)
- [ ] docs and the `Unreleased` section of CHANGELOG.md are updated
- [ ] no payload, configuration key or alert payload changed, or the issue that decided it is linked
- [ ] no detection paths, tokens, host names or email addresses in the description, logs or screenshots
