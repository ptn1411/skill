# Container And Cloud Audit Patterns

## Container Runtime

- `privileged: true` grants broad host access.
- `USER root` or `user: root` keeps the container running with elevated privileges.
- Host path mounts can expose sensitive host directories.

## Kubernetes

- `type: LoadBalancer` exposes services externally.
- `hostNetwork: true` places pods on the node network namespace.
- `allowPrivilegeEscalation: true` permits privilege escalation inside the container.
- `runAsNonRoot: false` disables a common hardening control.

## Cloud And Terraform

- `0.0.0.0/0` on ingress rules should be reviewed.
- Static access keys such as `AKIA...` should be rotated and removed from source.
