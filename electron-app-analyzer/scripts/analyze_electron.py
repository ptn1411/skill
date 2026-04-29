#!/usr/bin/env python3
"""
Static Electron application security triage.

Scans extracted Electron apps or source trees for package metadata, ASAR
artifacts, BrowserWindow webPreferences, preload/IPC exposure, update configs,
and sanitized endpoints.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


JS_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml"}
MAX_FILE_BYTES = 5_000_000

URL_RE = re.compile(r"https?://[^\s\"'<>`)]+", re.IGNORECASE)
PATH_RE = re.compile(
    r"(?<![\w])/("
    r"api|admin|auth|login|logout|graphql|rest|v\d+|update|download|releases"
    r")(?:/[A-Za-z0-9._~%+\-]*)*(?:\?[^\s\"'<>`)]+)?",
    re.IGNORECASE,
)

SENSITIVE_QUERY_KEYS = {
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "auth",
    "authorization",
    "code",
    "license",
}

SECRET_PATTERNS = [
    re.compile(r"sk_(?:live|test)_[A-Za-z0-9_\-]{10,}", re.I),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}", re.I),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}", re.I),
    re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    re.compile(r"(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|authorization|license)[\"']?\s*[:=]\s*[\"'])([^\"']{4,})([\"'])"),
]

FINDING_PATTERNS = [
    ("nodeIntegration enabled", re.compile(r"nodeIntegration\s*:\s*true", re.I)),
    ("contextIsolation disabled", re.compile(r"contextIsolation\s*:\s*false", re.I)),
    ("enableRemoteModule enabled", re.compile(r"enableRemoteModule\s*:\s*true", re.I)),
    ("webSecurity disabled", re.compile(r"webSecurity\s*:\s*false", re.I)),
    ("allowRunningInsecureContent enabled", re.compile(r"allowRunningInsecureContent\s*:\s*true", re.I)),
    ("sandbox disabled", re.compile(r"sandbox\s*:\s*false", re.I)),
    ("unsafe eval usage", re.compile(r"\beval\s*\(|\bFunction\s*\(", re.I)),
    ("document cookie access", re.compile(r"document\.cookie", re.I)),
    ("shell.openExternal usage", re.compile(r"shell\.openExternal\s*\(", re.I)),
    ("remote module import", re.compile(r"require\s*\(\s*['\"]electron['\"]\s*\)\.remote|remote\s*=", re.I)),
]


def unique(values: Iterable[str]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def redact_value(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        if pattern.groups >= 3:
            redacted = pattern.sub(lambda m: f"{m.group(1)}<redacted>{m.group(3)}", redacted)
        else:
            redacted = pattern.sub("<redacted>", redacted)
    return redacted


def redact_endpoint(endpoint: str) -> str:
    endpoint = redact_value(endpoint)
    parts = urlsplit(endpoint)
    if not parts.query:
        return endpoint
    query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in SENSITIVE_QUERY_KEYS:
            query.append((key, "<redacted>"))
        else:
            query.append((key, redact_value(value)))
    safe_query = urlencode(query).replace("%3Credacted%3E", "<redacted>")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, safe_query, parts.fragment))


def read_text(path: Path) -> str:
    if path.stat().st_size > MAX_FILE_BYTES:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def iter_interesting_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in JS_SUFFIXES or path.name in {"package.json", "app-update.yml", "latest.yml"}:
            files.append(path)
    return files


def extract_endpoints(text: str) -> list[str]:
    endpoints = []
    for url in URL_RE.findall(text):
        endpoints.append(redact_endpoint(url))
    for match in PATH_RE.finditer(text):
        endpoints.append(redact_endpoint(match.group(0)))
    return unique(endpoints)


def analyze_package_json(path: Path) -> dict:
    try:
        data = json.loads(read_text(path))
    except Exception:
        return {}
    return {
        "name": data.get("name", ""),
        "version": data.get("version", ""),
        "main": data.get("main", ""),
        "electron_dependency": bool(
            "electron" in data.get("dependencies", {}) or "electron" in data.get("devDependencies", {})
        ),
        "scripts": sorted(data.get("scripts", {}).keys()) if isinstance(data.get("scripts"), dict) else [],
    }


def detect_ipc_exposure(text: str) -> list[str]:
    findings = []
    if re.search(r"contextBridge\.exposeInMainWorld\s*\([^)]*ipcRenderer", text, re.I | re.S):
        findings.append("ipcRenderer exposed broadly")
    if re.search(r"window\.[A-Za-z0-9_$]+\s*=\s*ipcRenderer", text, re.I):
        findings.append("ipcRenderer exposed broadly")
    if re.search(r"ipcRenderer\.(?:send|invoke|on)\s*\(", text, re.I):
        findings.append("ipcRenderer used in renderer/preload")
    if re.search(r"ipcMain\.(?:handle|on)\s*\(", text, re.I):
        findings.append("ipcMain handlers present")
    return findings


def analyze_path(input_path: Path | str) -> dict:
    root = Path(input_path)
    files = iter_interesting_files(root)
    base = root if root.is_dir() else root.parent

    artifacts = []
    findings = []
    endpoints = []
    file_hits: dict[str, list[str]] = {}
    packages = []

    scan_root = root if root.is_dir() else root.parent
    for asar in scan_root.rglob("*.asar") if scan_root.exists() else []:
        artifacts.append(rel(asar, scan_root))
        findings.append("ASAR package present")

    for path in files:
        relative = rel(path, base)
        if path.name == "package.json":
            pkg = analyze_package_json(path)
            if pkg:
                packages.append({"file": relative, **pkg})
                findings.append("package.json")

        if path.name.lower() in {"app-update.yml", "latest.yml"}:
            findings.append("auto-update config")

        text = read_text(path)
        if not text:
            continue

        local_findings = []
        for label, pattern in FINDING_PATTERNS:
            if pattern.search(text):
                local_findings.append(label)
        local_findings.extend(detect_ipc_exposure(text))

        if local_findings:
            file_hits[relative] = unique(local_findings)
            findings.extend(local_findings)

        endpoints.extend(extract_endpoints(text))

    return {
        "root": str(root),
        "files": [rel(path, base) for path in files],
        "artifacts": unique(artifacts),
        "packages": packages,
        "findings": unique(findings),
        "file_findings": file_hits,
        "endpoints": unique(endpoints),
    }


def write_outputs(result: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "electron_analysis.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "findings.json").write_text(json.dumps(result["file_findings"], indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "endpoints.json").write_text(json.dumps(result["endpoints"], indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# Electron App Analysis Report",
        "",
        f"Root: `{result['root']}`",
        f"Files analyzed: {len(result['files'])}",
        f"Artifacts: {', '.join(result['artifacts']) if result['artifacts'] else 'none'}",
        "",
        "## Findings",
    ]
    lines.extend(f"- {finding}" for finding in result["findings"] if finding != "package.json")
    lines.extend(["", "## Affected Files"])
    for file, items in result["file_findings"].items():
        lines.append(f"- `{file}`: {', '.join(items)}")
    lines.extend(["", "## Endpoints"])
    lines.extend(f"- `{endpoint}`" for endpoint in result["endpoints"][:200])
    lines.extend(["", "## Notes", "- Values are redacted by default. Do not run recovered endpoints or secrets against live services."])
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze an authorized Electron app package or extracted source tree")
    parser.add_argument("path", help="Electron source/extracted directory, app.asar path, or file")
    parser.add_argument("--out", default="electron-analysis", help="Output directory")
    parser.add_argument("--json", action="store_true", help="Print JSON summary to stdout")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        parser.error(f"path not found: {target}")

    result = analyze_path(target)
    write_outputs(result, Path(args.out))
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"[+] Files analyzed: {len(result['files'])}")
        print(f"[+] Findings: {len(result['findings'])}")
        print(f"[+] Endpoints: {len(result['endpoints'])}")
        print(f"[+] Report: {Path(args.out) / 'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
