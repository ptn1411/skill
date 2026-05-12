---
name: sbom-supply-chain-auditor
description: Audit dependency manifests and lockfiles for SBOM extraction, risky install scripts, unpinned versions, remote dependency sources, and secret-like values.
---

# SBOM Supply Chain Auditor

## Purpose

Use after source recovery or on application repos to identify dependency and supply-chain risks.

## Workflow

1. Run `python sbom-supply-chain-auditor/scripts/analyze_supply_chain.py <target> --out output/sbom-supply-chain-auditor`.
2. Review `findings.json` and `REPORT.md`.
3. Use findings to prioritize dependency pinning, secret rotation, and package trust review.

## Outputs

- `findings.json`
- `REPORT.md`

## Anti-Patterns

- Do not claim CVE coverage without integrating a vulnerability database.
- Do not auto-update dependencies from this skill.
