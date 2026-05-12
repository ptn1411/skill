---
name: container-cloud-auditor
description: Audit Docker, Compose, Kubernetes, Terraform, and cloud configuration for exposed services, privileged runtime settings, hardcoded secrets, and risky infrastructure defaults.
---

# Container Cloud Auditor

## Purpose

Use for authorized review of container and cloud deployment artifacts in recovered source, app repos, or exported infrastructure bundles.

## Workflow

1. Run `python container-cloud-auditor/scripts/analyze_container_cloud.py <target> --out output/container-cloud-auditor`.
2. Review `findings.json` and `REPORT.md`.
3. Chain findings into remediation or pentest report generation.

## Outputs

- `findings.json`
- `REPORT.md`

## Anti-Patterns

- Do not scan live cloud accounts from this skill.
- Do not treat regex evidence as proof without human validation.
