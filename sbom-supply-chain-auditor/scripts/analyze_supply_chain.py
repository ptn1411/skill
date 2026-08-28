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


# Curated known-malicious npm typosquat package names (historical incidents).
KNOWN_MALICIOUS = {
    "crossenv", "cross-env.js", "babelcli", "ffmepg", "gruntcli", "jquey",
    "mariadb", "mssql-node", "mssql.js", "mysqljs", "nodecaffe", "nodefabric",
    "node-fabric", "nodeffmpeg", "nodemailer-js", "nodemailer.js", "nodesqlite",
    "node-sqlite", "node-tkinter", "sqlite.js", "sqliter", "sqlserver", "loadsh",
    "fabric-js", "shadound", "smb", "tensorflowjs", "openvpn",
}
# Popular packages used to flag edit-distance-1 typosquats.
POPULAR_NPM = {
    "react", "lodash", "express", "request", "axios", "chalk", "commander",
    "debug", "moment", "async", "bluebird", "underscore", "jquery", "webpack",
    "vue", "angular", "typescript", "eslint", "jest", "mocha", "dotenv", "uuid",
    "glob", "yargs", "colors", "node-fetch", "ws", "redis", "mongoose", "pg",
    "mysql", "sequelize", "cors", "body-parser", "passport", "jsonwebtoken",
    "bcrypt", "nodemailer", "socket.io", "cross-env", "next", "webpack-cli",
}
POPULAR_PYPI = {
    "requests", "numpy", "pandas", "flask", "django", "urllib3", "setuptools",
    "pillow", "scipy", "boto3", "six", "pytest", "click", "jinja2", "sqlalchemy",
    "cryptography", "certifi", "idna", "wheel", "pyyaml", "beautifulsoup4",
    "matplotlib", "scikit-learn", "tensorflow", "torch", "fastapi", "aiohttp",
}
# License identifiers that carry copyleft / usage risk for redistribution.
RISKY_LICENSES = re.compile(r"\b(AGPL|GPL-2|GPL-3|GPLv2|GPLv3|SSPL|CC-BY-NC|WTFPL|UNLICENSED)\b", re.I)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def check_dep_name(name: str, version: str, rel: Path | str, ecosystem: str) -> list[dict]:
    """Typosquat, known-malicious, and dependency-confusion heuristics for one dependency."""
    results = []
    base = name.lower().lstrip("@").split("/")[-1]
    popular = POPULAR_NPM if ecosystem == "npm" else POPULAR_PYPI
    if base in KNOWN_MALICIOUS:
        results.append(finding("SC-010", "critical", ecosystem, "Known-malicious package name",
                               rel, 1, f"{name}: {version}",
                               "This name matches a historical malware typosquat — remove and verify."))
    elif base not in popular:
        for good in popular:
            if abs(len(base) - len(good)) <= 1 and levenshtein(base, good) == 1:
                results.append(finding("SC-011", "medium", ecosystem, "Possible typosquat dependency",
                                       rel, 1, f"{name} (near '{good}')",
                                       f"Name is one edit from popular package '{good}' — confirm it is intended."))
                break
    # Dependency confusion: scoped/internal-looking name that may resolve from the public registry.
    if ecosystem == "npm" and name.startswith("@"):
        results.append(finding("SC-012", "medium", "npm", "Scoped package — dependency-confusion risk",
                               rel, 1, name,
                               "Ensure this scope resolves only from your private registry (.npmrc/publishConfig)."))
    return results


def scan_lockfile(path: Path, rel: Path | str) -> list[dict]:
    """npm lockfile: flag entries missing integrity hashes (tamper risk)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError as exc:
        return [finding("SC-000", "low", "npm", "Malformed lockfile", rel, exc.lineno, str(exc),
                        "Regenerate the lockfile.")]
    results = []
    packages = data.get("packages") or data.get("dependencies") or {}
    missing = 0
    for key, meta in packages.items():
        if not key or not isinstance(meta, dict):
            continue
        if meta.get("resolved") and not meta.get("integrity"):
            missing += 1
    if missing:
        results.append(finding("SC-013", "medium", "npm", "Lockfile entries missing integrity hash",
                               rel, 1, f"{missing} package(s) without integrity",
                               "Regenerate the lockfile so every entry has an integrity hash."))
    return results


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

    lic = data.get("license") or data.get("licenses")
    lic_text = json.dumps(lic) if isinstance(lic, (list, dict)) else str(lic or "")
    if not lic:
        results.append(finding("SC-008", "low", "license", "No license declared", rel, 1, "license: (missing)", "Declare a license; missing licenses block safe redistribution."))
    elif RISKY_LICENSES.search(lic_text):
        results.append(finding("SC-009", "medium", "license", "Copyleft / restrictive license", rel, 1, f"license: {lic_text}", "Review license obligations before redistribution."))

    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for dep, version in data.get(section, {}).items():
            version_text = str(version)
            if version_text in {"latest", "*"} or version_text.startswith(("^", "~")):
                results.append(finding("SC-002", "low", "npm", "Floating npm dependency version", rel, 1, f"{dep}: {version_text}", "Pin exact versions for reproducible builds."))
            if re.search(r"^(http|https|git\+)", version_text, re.I):
                sev = "medium" if re.search(r"#[0-9a-f]{7,40}$", version_text, re.I) else "high"
                results.append(finding("SC-007", sev, "npm", "Remote npm dependency source", rel, 1, f"{dep}: {version_text}", "Pin remote dependencies to an immutable commit hash or a trusted registry."))
            if version_text.startswith("file:"):
                results.append(finding("SC-014", "low", "npm", "Local file dependency", rel, 1, f"{dep}: {version_text}", "Local path deps are unverifiable in CI — confirm this is intended."))
            results.extend(check_dep_name(dep, version_text, rel, "npm"))
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
        m = re.match(r"^([A-Za-z0-9._-]+)", stripped)
        if m and not stripped.startswith(("-r ", "--", "http", "git+")):
            name = m.group(1)
            version = stripped[len(name):]
            results.extend(check_dep_name(name, version, rel, "pypi"))
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
    if path.name == "package-lock.json":
        return scan_lockfile(path, rel)
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
