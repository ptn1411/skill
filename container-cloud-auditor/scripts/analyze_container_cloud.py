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
        if path.is_file() and (path.name in CONFIG_NAMES or path.suffix in {".tf", ".yaml", ".yml"}):
            files.append(path)
    return sorted(files)


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


def scan_file(path: Path, root: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    rel = path.relative_to(root) if root.is_dir() else path.name
    results = []

    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if re.search(r"privileged\s*:\s*true", stripped, re.I):
            results.append(finding("CC-001", "high", "container", "Privileged container enabled", rel, idx, line, "Remove privileged mode and use specific Linux capabilities."))
        if re.search(r"user\s*:\s*[\"']?root[\"']?$", stripped, re.I) or re.search(r"USER\s+root\b", stripped):
            results.append(finding("CC-002", "medium", "container", "Container runs as root", rel, idx, line, "Use a non-root runtime user."))
        if re.search(r"type\s*:\s*LoadBalancer", stripped, re.I):
            results.append(finding("CC-003", "medium", "kubernetes", "Externally exposed Kubernetes service", rel, idx, line, "Confirm exposure is required and restrict source ranges."))
        if re.search(r"hostNetwork\s*:\s*true", stripped, re.I):
            results.append(finding("CC-004", "high", "kubernetes", "Pod uses host network", rel, idx, line, "Disable hostNetwork unless explicitly required."))
        if re.search(r"0\.0\.0\.0/0", stripped):
            results.append(finding("CC-005", "high", "cloud", "Open network CIDR", rel, idx, line, "Restrict ingress CIDR to trusted ranges."))
        if re.search(r"AKIA[0-9A-Z]{16}", stripped):
            results.append(finding("CC-006", "critical", "secret", "AWS access key pattern", rel, idx, line, "Rotate the key and move secrets to a secret manager."))
        if re.search(r"allowPrivilegeEscalation\s*:\s*true", stripped, re.I):
            results.append(finding("CC-007", "high", "kubernetes", "Privilege escalation allowed", rel, idx, line, "Set allowPrivilegeEscalation to false."))
        if re.search(r"runAsNonRoot\s*:\s*false", stripped, re.I):
            results.append(finding("CC-008", "medium", "kubernetes", "Non-root execution disabled", rel, idx, line, "Set runAsNonRoot to true where possible."))
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
