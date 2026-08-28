---
name: sbom-supply-chain-auditor
description: Audit dependency manifests and lockfiles for SBOM extraction, risky install scripts, unpinned versions, remote/git dependency sources, dependency-confusion and typosquat/known-malicious package names, lockfile integrity gaps, copyleft license risk, and secret-like values.
---

# SBOM Supply Chain Auditor

## Purpose

Use after source recovery or on application repos to identify dependency and supply-chain risks.

## Workflow

1. Run `python sbom-supply-chain-auditor/scripts/analyze_supply_chain.py <target> --out output/sbom-supply-chain-auditor`.
2. Review `findings.json` and `REPORT.md`.
3. Use findings to prioritize dependency pinning, secret rotation, and package trust review.

## Coverage

- **Install-time execution** — npm `preinstall`/`install`/`postinstall`/`prepare` scripts.
- **Version hygiene** — floating/unpinned npm & Python versions; `file:` local deps.
- **Remote sources** — `git+`/`http(s)` deps (high unless pinned to a commit hash).
- **Dependency confusion** — scoped `@scope/pkg` that may resolve from the public registry.
- **Typosquat / malware** — names one edit from popular packages, and a curated known-malicious list (critical).
- **Lockfile integrity** — `package-lock.json` entries missing integrity hashes.
- **License risk** — missing license, or copyleft/restrictive (AGPL/GPL/SSPL/UNLICENSED).
- **Secrets** — password/token/secret-like values in manifests.

> Heuristic, not a CVE feed. Typosquat/known-malicious lists are a curated subset — pair with a vulnerability database for full coverage.

## Outputs

- `findings.json`
- `REPORT.md`

## Anti-Patterns

- Do not claim CVE coverage without integrating a vulnerability database.
- Do not auto-update dependencies from this skill.
