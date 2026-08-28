#!/usr/bin/env python3
"""Audit Docker, Kubernetes, Terraform, and cloud deployment configuration."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


SKILL = "container-cloud-auditor"
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIG_NAMES = {
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "kubernetes.yml",
    "kubernetes.yaml",
    "terraform.tf",
    "main.tf",
    "variables.tf",
}


def iter_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if (path.name in CONFIG_NAMES or path.name.startswith("Dockerfile")
                or path.suffix in {".tf", ".yaml", ".yml"}):
            files.append(path)
    return sorted(files)


def detect_type(path: Path, text: str) -> str:
    """Classify a config file so rules apply to the right technology."""
    name = path.name.lower()
    if path.suffix == ".tf":
        return "terraform"
    if name.startswith("dockerfile"):
        return "dockerfile"
    if "compose" in name:
        return "compose"
    if re.search(r"^\s*apiVersion\s*:", text, re.M) and re.search(r"^\s*kind\s*:", text, re.M):
        return "k8s"
    if re.search(r"^\s*services\s*:", text, re.M):
        return "compose"
    if re.search(r"^\s*FROM\s+\S+", text, re.M):
        return "dockerfile"
    return "generic"


# (id, severity, category, title, pattern, recommendation, filetypes|None)
LINE_RULES = [
    # --- containers / kubernetes ---
    ("CC-001", "high", "container", "Privileged container enabled",
     r"privileged\s*:\s*true", "Remove privileged mode; grant specific Linux capabilities instead.", None),
    ("CC-002", "medium", "container", "Dockerfile sets USER root",
     r"^USER\s+root\b", "Use a dedicated non-root USER.", {"dockerfile"}),
    ("CC-003", "medium", "kubernetes", "Externally exposed Service (LoadBalancer)",
     r"type\s*:\s*LoadBalancer", "Confirm exposure is required; restrict loadBalancerSourceRanges.", {"k8s"}),
    ("CC-004", "high", "kubernetes", "Pod uses host network",
     r"hostNetwork\s*:\s*true", "Disable hostNetwork unless explicitly required.", {"k8s"}),
    ("CC-007", "high", "kubernetes", "Privilege escalation allowed",
     r"allowPrivilegeEscalation\s*:\s*true", "Set allowPrivilegeEscalation: false.", {"k8s"}),
    ("CC-008", "medium", "kubernetes", "Non-root execution disabled",
     r"runAsNonRoot\s*:\s*false", "Set runAsNonRoot: true.", {"k8s"}),
    ("CC-016", "high", "kubernetes", "Pod shares host PID/IPC namespace",
     r"host(PID|IPC)\s*:\s*true", "Disable hostPID/hostIPC.", {"k8s"}),
    ("CC-017", "high", "kubernetes", "hostPath volume mount",
     r"hostPath\s*:", "Avoid hostPath; use PVCs / configMaps / secrets.", {"k8s"}),
    ("CC-018", "high", "kubernetes", "Dangerous Linux capability added",
     r"-\s*[\"']?(SYS_ADMIN|NET_ADMIN|ALL|SYS_PTRACE)[\"']?\s*$",
     "Drop all capabilities and add only the minimum required.", {"k8s"}),
    ("CC-019", "medium", "kubernetes", "Writable root filesystem",
     r"readOnlyRootFilesystem\s*:\s*false", "Set readOnlyRootFilesystem: true.", {"k8s"}),
    ("CC-020", "low", "kubernetes", "Service account token auto-mounted",
     r"automountServiceAccountToken\s*:\s*true", "Set to false unless the pod calls the API.", {"k8s"}),
    ("CC-023", "medium", "container", "Unpinned container image (:latest)",
     r"image\s*:\s*\S+:latest", "Pin the image to a digest or fixed version.", {"k8s", "compose"}),
    ("CC-015", "high", "container", "Host network mode (compose)",
     r"network_mode\s*:\s*[\"']?host", "Avoid host networking.", {"compose"}),
    ("CC-037", "high", "container", "Dangerous capability added (compose)",
     r"-\s*[\"']?(SYS_ADMIN|NET_ADMIN|ALL)[\"']?\s*$", "Drop caps; add the minimum required.", {"compose"}),
    ("CC-038", "high", "container", "Docker socket mounted into container",
     r"/var/run/docker\.sock", "Mounting docker.sock grants host takeover; remove it.", None),
    # --- dockerfile build hygiene ---
    ("CC-009", "medium", "container", "Unpinned base image (:latest)",
     r"^FROM\s+\S+:latest", "Pin the base image to a digest or fixed version.", {"dockerfile"}),
    ("CC-010", "high", "container", "Remote ADD fetch",
     r"^ADD\s+https?://", "Use COPY or a checksum-verified download.", {"dockerfile"}),
    ("CC-011", "high", "container", "Pipe-to-shell install",
     r"(curl|wget)\s+[^|]*\|\s*(sudo\s+)?(sh|bash)", "Download, verify checksum, then execute.", {"dockerfile"}),
    ("CC-012", "high", "secret", "Secret baked into image (ENV/ARG)",
     r"^(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|API_?KEY|ACCESS_KEY)\w*\s*[=\s]",
     "Pass secrets at runtime; never bake them into image layers.", {"dockerfile"}),
    # --- cloud / terraform ---
    ("CC-005", "high", "cloud", "Open ingress CIDR (0.0.0.0/0)",
     r"0\.0\.0\.0/0", "Restrict ingress CIDR to trusted ranges.", None),
    ("CC-025", "critical", "cloud", "Public S3 ACL",
     r"acl\s*=\s*\"public-read(-write)?\"", "Make the bucket private; use scoped bucket policies.", {"terraform"}),
    ("CC-027", "high", "cloud", "Wildcard IAM permission",
     r"\"(Action|Resource)\"\s*:\s*\"\*\"|=\s*\"\*:\*\"", "Scope IAM actions/resources to least privilege.", {"terraform"}),
    ("CC-028", "high", "cloud", "Encryption at rest disabled",
     r"(storage_)?encrypted\s*=\s*false", "Enable encryption at rest.", {"terraform"}),
    ("CC-029", "medium", "cloud", "Publicly accessible resource",
     r"publicly_accessible\s*=\s*true", "Set publicly_accessible = false.", {"terraform"}),
    # --- secrets (any file type) ---
    ("CC-006", "critical", "secret", "AWS access key",
     r"AKIA[0-9A-Z]{16}", "Rotate the key and move it to a secret manager.", None),
    ("CC-032", "critical", "secret", "Google API key",
     r"AIza[0-9A-Za-z_\-]{35}", "Rotate the key; store it in a secret manager.", None),
    ("CC-033", "critical", "secret", "Private key material",
     r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "Remove the key; rotate it immediately.", None),
    ("CC-034", "high", "secret", "Slack token",
     r"xox[baprs]-[0-9A-Za-z-]{10,}", "Revoke the token; use a secret manager.", None),
    ("CC-035", "high", "secret", "Hardcoded credential",
     r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[\"'][^\"'$\{\s]{6,}[\"']",
     "Move to a secret manager / variable and rotate.", None),
]
COMPILED_RULES = [(fid, sev, cat, title, re.compile(pat, re.I), rec, ft)
                  for (fid, sev, cat, title, pat, rec, ft) in LINE_RULES]


def finding(
    fid: str,
    severity: str,
    category: str,
    title: str,
    path: Path | str,
    line_no: int,
    evidence: str,
    recommendation: str,
) -> dict:
    return {
        "id": fid,
        "severity": severity,
        "category": category,
        "title": title,
        "file": str(path),
        "line": line_no,
        "evidence": evidence.strip(),
        "recommendation": recommendation,
    }


def scan_file_level(ftype: str, text: str, rel) -> list[dict]:
    """Whole-file (multi-line) checks that a single line can't express."""
    results = []
    if ftype == "dockerfile":
        if not re.search(r"^\s*USER\s+(?!root\b)\S+", text, re.M | re.I):
            results.append(finding("CC-013", "medium", "container", "Image runs as root (no non-root USER)",
                                    rel, 1, "no USER instruction", "Add a non-root USER instruction."))
        if not re.search(r"^\s*HEALTHCHECK", text, re.M | re.I):
            results.append(finding("CC-014", "low", "container", "No HEALTHCHECK defined",
                                    rel, 1, "no HEALTHCHECK", "Add a HEALTHCHECK for liveness/observability."))
    if ftype == "k8s":
        if re.search(r"^\s*containers\s*:", text, re.M) and not re.search(r"\blimits\s*:", text):
            results.append(finding("CC-040", "medium", "kubernetes", "No resource limits set",
                                    rel, 1, "containers without limits",
                                    "Set resources.limits (cpu/memory) to prevent noisy-neighbour/DoS."))
        if re.search(r"^\s*containers\s*:", text, re.M) and not re.search(r"securityContext\s*:", text):
            results.append(finding("CC-041", "low", "kubernetes", "No securityContext defined",
                                    rel, 1, "no securityContext",
                                    "Add a securityContext (runAsNonRoot, drop caps, readOnlyRootFilesystem)."))
    return results


def scan_file(path: Path, root: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    rel = path.relative_to(root) if root.is_dir() else path.name
    ftype = detect_type(path, text)
    results = []

    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for fid, sev, cat, title, rx, rec, ftypes in COMPILED_RULES:
            if ftypes is not None and ftype not in ftypes:
                continue
            if rx.search(stripped):
                results.append(finding(fid, sev, cat, title, rel, idx, line, rec))
    results.extend(scan_file_level(ftype, text, rel))
    return results


def summarize(files: list[Path], findings: list[dict]) -> dict:
    highest = "info"
    for item in findings:
        if SEVERITY_ORDER[item["severity"]] > SEVERITY_ORDER[highest]:
            highest = item["severity"]
    return {"files_scanned": len(files), "findings_count": len(findings), "highest_severity": highest}


def analyze_path(target: Path | str) -> dict:
    root = Path(target)
    files = iter_files(root)
    findings = []
    scan_root = root if root.is_dir() else root.parent
    for path in files:
        findings.extend(scan_file(path, scan_root))
    return {
        "target": str(root),
        "skill": SKILL,
        "summary": summarize(files, findings),
        "findings": findings,
        "artifacts": [],
    }


def write_outputs(result: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "findings.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# Container Cloud Auditor Report",
        "",
        f"- Target: `{result['target']}`",
        f"- Files scanned: {result['summary']['files_scanned']}",
        f"- Findings: {result['summary']['findings_count']}",
        f"- Highest severity: {result['summary']['highest_severity']}",
        "",
        "## Findings",
    ]
    for item in result["findings"]:
        lines.extend(
            [
                f"### {item['id']} - {item['title']} [{item['severity']}]",
                f"- File: `{item['file']}`",
                f"- Line: {item['line']}",
                f"- Evidence: `{item['evidence']}`",
                f"- Recommendation: {item['recommendation']}",
                "",
            ]
        )
    if not result["findings"]:
        lines.append("No findings.")
    (out_dir / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit Docker, Kubernetes, Terraform, and cloud config files.")
    parser.add_argument("target")
    parser.add_argument("--out", default="output/container-cloud-auditor")
    args = parser.parse_args()
    result = analyze_path(args.target)
    write_outputs(result, Path(args.out))
    print(f"[+] Findings: {result['summary']['findings_count']}")
    print(f"[+] Report: {Path(args.out) / 'REPORT.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
