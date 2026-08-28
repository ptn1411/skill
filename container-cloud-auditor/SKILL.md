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

## Coverage

Files are auto-classified (Dockerfile / Compose / Kubernetes / Terraform) so each rule applies in the right context. ~30 rules across:

- **Dockerfile** — `:latest`/unpinned base, `USER root` / no non-root USER, remote `ADD`, pipe-to-shell installs, secrets in `ENV`/`ARG`, missing `HEALTHCHECK`.
- **Compose / containers** — `privileged`, host networking, added capabilities (`SYS_ADMIN`/`ALL`), mounted `docker.sock`, `:latest` images.
- **Kubernetes** — `hostNetwork`/`hostPID`/`hostIPC`, `hostPath`, `allowPrivilegeEscalation`, `runAsNonRoot: false`, `readOnlyRootFilesystem: false`, dangerous capabilities, `automountServiceAccountToken`, `LoadBalancer` exposure, missing resource limits / securityContext.
- **Terraform / cloud** — public S3 ACL, `0.0.0.0/0` ingress, wildcard IAM (`*` / `*:*`), encryption disabled, `publicly_accessible`.
- **Secrets (any file)** — AWS/Google keys, private-key blocks, Slack tokens, hardcoded credentials.

## Outputs

- `findings.json`
- `REPORT.md`

## Anti-Patterns

- Do not scan live cloud accounts from this skill.
- Do not treat regex evidence as proof without human validation.
