#!/usr/bin/env python3
"""Audit dependency manifests and lockfiles for supply-chain risk signals."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


SKILL = "sbom-supply-chain-auditor"
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "pyproject.toml",
    "pom.xml",
    "build.gradle",
    "Cargo.toml",
    "Cargo.lock",
    "packages.config",
}


def iter_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name in MANIFEST_NAMES or path.suffix == ".csproj":
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


def scan_package_json(path: Path, rel: Path | str) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError as exc:
        return [finding("SC-000", "low", "npm", "Malformed package.json", rel, exc.lineno, str(exc), "Fix package.json so dependency tooling can parse it.")]

    results = []
    scripts = data.get("scripts", {})
    for name in ("preinstall", "install", "postinstall", "prepare"):
        if name in scripts:
            results.append(finding("SC-001", "medium", "npm", "Package install script present", rel, 1, f"{name}: {scripts[name]}", "Review install-time code execution before trusting this package."))

    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for dep, version in data.get(section, {}).items():
            version_text = str(version)
            if version_text in {"latest", "*"} or version_text.startswith(("^", "~")):
                results.append(finding("SC-002", "low", "npm", "Floating npm dependency version", rel, 1, f"{dep}: {version_text}", "Pin exact versions for reproducible builds."))
            if re.search(r"^(http|https|git\+)", version_text, re.I):
                results.append(finding("SC-007", "medium", "npm", "Remote npm dependency source", rel, 1, f"{dep}: {version_text}", "Pin remote dependencies to immutable commits or trusted registries."))
    return results


def scan_requirements(path: Path, rel: Path | str) -> list[dict]:
    results = []
    for idx, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "==" not in stripped and not stripped.startswith(("-r ", "--")):
            results.append(finding("SC-003", "low", "python", "Unpinned Python requirement", rel, idx, line, "Pin package versions with hashes for repeatable installs."))
        if re.search(r"(http|https|git\+)", stripped, re.I):
            results.append(finding("SC-004", "medium", "python", "Remote dependency source", rel, idx, line, "Verify remote dependency integrity and pin commits."))
    return results


def scan_text_manifest(path: Path, rel: Path | str) -> list[dict]:
    results = []
    for idx, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        if re.search(r"http://", line):
            results.append(finding("SC-005", "medium", "dependency", "Plain HTTP dependency reference", rel, idx, line, "Use HTTPS and verify artifact checksums."))
        if re.search(r"(password|token|secret)\s*[:=]", line, re.I):
            results.append(finding("SC-006", "high", "secret", "Secret-like value in manifest", rel, idx, line, "Remove secrets from source and rotate exposed credentials."))
    return results


def scan_file(path: Path, root: Path) -> list[dict]:
    rel = path.relative_to(root) if root.is_dir() else path.name
    if path.name == "package.json":
        return scan_package_json(path, rel)
    if path.name == "requirements.txt":
        return scan_requirements(path, rel)
    return scan_text_manifest(path, rel)


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
        "# SBOM Supply Chain Auditor Report",
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
    parser = argparse.ArgumentParser(description="Audit dependency manifests and lockfiles.")
    parser.add_argument("target")
    parser.add_argument("--out", default="output/sbom-supply-chain-auditor")
    args = parser.parse_args()
    result = analyze_path(args.target)
    write_outputs(result, Path(args.out))
    print(f"[+] Findings: {result['summary']['findings_count']}")
    print(f"[+] Report: {Path(args.out) / 'REPORT.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
