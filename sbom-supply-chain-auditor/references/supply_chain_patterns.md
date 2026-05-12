# Supply Chain Audit Patterns

## JavaScript

- `preinstall`, `install`, `postinstall`, and `prepare` scripts execute during dependency install.
- `latest`, `*`, caret, and tilde ranges reduce build reproducibility.
- Remote dependency URLs should be pinned to immutable references.

## Python

- Requirements without `==` are not pinned.
- Direct `http`, `https`, or `git+` dependencies need integrity review.
- Hash-pinned installs are preferred for high-assurance workflows.

## General Manifests

- Plain HTTP artifact URLs can be modified in transit.
- Secret-like values in manifests should be rotated and moved to a secret manager.
