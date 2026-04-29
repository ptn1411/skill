#!/usr/bin/env python3
"""
Static JavaScript deobfuscation triage.

The script extracts encoded strings, endpoints, sourcemaps, and common
obfuscation indicators. Output is redacted by default.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


STRING_PATTERNS = [
    re.compile(r'"((?:\\.|[^"\\])*)"'),
    re.compile(r"'((?:\\.|[^'\\])*)'"),
    re.compile(r"`((?:\\.|[^`\\])*)`"),
]

URL_RE = re.compile(r"https?://[^\s\"'<>`)]+", re.IGNORECASE)
PATH_RE = re.compile(
    r"(?<![\w])/("
    r"api|admin|auth|login|logout|graphql|rest|wp-json|v\d+|@vite|_next|assets|static"
    r")(?:/[A-Za-z0-9._~%+\-]*)*(?:\?[^\s\"'<>`)]+)?",
    re.IGNORECASE,
)
SOURCEMAP_RE = re.compile(r"sourceMappingURL=([^\s]+)")

INDICATOR_PATTERNS = {
    "eval": re.compile(r"\beval\s*\("),
    "Function": re.compile(r"\bFunction\s*\("),
    "atob": re.compile(r"\batob\s*\("),
    "decodeURIComponent": re.compile(r"\bdecodeURIComponent\s*\("),
    "string-array": re.compile(r"(?:var|let|const)\s+_0x[a-f0-9]+\s*=\s*\[", re.I),
    "control-flow-flattening": re.compile(r"while\s*\(\s*!!\[\]\s*\)|switch\s*\(", re.I),
    "webpack": re.compile(r"__webpack_require__|webpackJsonp|webpackChunk", re.I),
    "vite": re.compile(r"/@vite/client|import\.meta\.env", re.I),
    "CryptoJS": re.compile(r"CryptoJS\.(?:AES|DES|TripleDES|RC4)\.decrypt", re.I),
    "WebCrypto": re.compile(r"crypto\.subtle\.(?:decrypt|importKey|deriveKey)", re.I),
    "WebAssembly": re.compile(r"WebAssembly\.(?:instantiate|compile)", re.I),
    "cookie-access": re.compile(r"document\.cookie", re.I),
    "storage-access": re.compile(r"(?:localStorage|sessionStorage)\.", re.I),
}

SECRET_PATTERNS = [
    re.compile(r"sk_(?:live|test)_[A-Za-z0-9_\-]{10,}", re.I),
    re.compile(r"sk\d?_[A-Za-z0-9_\-]{12,}", re.I),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}", re.I),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}", re.I),
    re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    re.compile(r"(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|authorization|license)[\"']?\s*[:=]\s*[\"'])([^\"']{4,})([\"'])"),
]

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


def decode_js_escapes(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        seq = match.group(0)
        if seq.startswith("\\x"):
            return chr(int(seq[2:], 16))
        if seq.startswith("\\u"):
            return chr(int(seq[2:], 16))
        mapping = {
            "\\n": "\n",
            "\\r": "\r",
            "\\t": "\t",
            "\\b": "\b",
            "\\f": "\f",
            "\\/": "/",
            "\\\\": "\\",
            '\\"': '"',
            "\\'": "'",
            "\\`": "`",
        }
        return mapping.get(seq, seq[1:])

    return re.sub(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\.", replace, value)


def extract_strings(source: str) -> list[str]:
    values: list[str] = []
    for pattern in STRING_PATTERNS:
        for match in pattern.finditer(source):
            decoded = decode_js_escapes(match.group(1))
            if decoded:
                values.append(decoded)
    return unique(values)


def unique(values: Iterable[str]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def is_printable_text(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126)
    return printable / len(data) > 0.85


def maybe_base64_decode(value: str) -> str | None:
    candidate = value.strip()
    if len(candidate) < 8 or len(candidate) > 12000:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", candidate):
        return None
    padded = candidate + "=" * (-len(candidate) % 4)
    for altchars in (None, b"-_"):
        try:
            decoded = base64.b64decode(padded.encode(), altchars=altchars, validate=False)
        except Exception:
            continue
        if is_printable_text(decoded):
            try:
                return decoded.decode("utf-8", errors="replace")
            except Exception:
                return decoded.decode("latin-1", errors="replace")
    return None


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


def extract_endpoints(values: Iterable[str]) -> list[str]:
    endpoints: list[str] = []
    for value in values:
        for url in URL_RE.findall(value):
            endpoints.append(redact_endpoint(url))
        for match in PATH_RE.finditer(value):
            endpoints.append(redact_endpoint(match.group(0)))
    return unique(endpoints)


def detect_indicators(source: str) -> list[str]:
    return [name for name, pattern in INDICATOR_PATTERNS.items() if pattern.search(source)]


def analyze_source(source: str, source_name: str = "<memory>") -> dict:
    raw_strings = extract_strings(source)
    decoded_items = []
    decoded_values = []

    for value in raw_strings:
        decoded = maybe_base64_decode(value)
        if decoded and decoded != value:
            decoded_values.append(decoded)
            decoded_items.append(
                {
                    "encoding": "base64/base64url",
                    "value": redact_value(decoded),
                }
            )

    searchable_values = [source, *raw_strings, *decoded_values]
    endpoints = extract_endpoints(searchable_values)
    sourcemaps = unique(SOURCEMAP_RE.findall(source))
    indicators = detect_indicators(source)

    interesting_strings = []
    for value in [*raw_strings, *decoded_values]:
        if any(token in value.lower() for token in ("api", "token", "secret", "key", "auth", "http", "/admin", "/login")):
            interesting_strings.append(redact_endpoint(value))

    result = {
        "source": source_name,
        "summary": {
            "strings": len(raw_strings),
            "decoded_strings": len(decoded_items),
            "endpoints": len(endpoints),
            "indicators": len(indicators),
            "sourcemaps": len(sourcemaps),
        },
        "indicators": indicators,
        "endpoints": endpoints,
        "sourcemaps": sourcemaps,
        "decoded_strings": decoded_items,
        "interesting_strings": unique(interesting_strings)[:100],
    }
    return result


def analyze_path(path: Path) -> dict:
    source = path.read_text(encoding="utf-8", errors="replace")
    return analyze_source(source, source_name=str(path))


def iter_js_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    suffixes = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".map"}
    return [p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in suffixes]


def merge_results(results: list[dict]) -> dict:
    endpoints = unique(ep for result in results for ep in result["endpoints"])
    indicators = unique(ind for result in results for ind in result["indicators"])
    sourcemaps = unique(sm for result in results for sm in result["sourcemaps"])
    strings = unique(s for result in results for s in result["interesting_strings"])
    return {
        "files": len(results),
        "summary": {
            "endpoints": len(endpoints),
            "indicators": len(indicators),
            "sourcemaps": len(sourcemaps),
            "interesting_strings": len(strings),
        },
        "indicators": indicators,
        "endpoints": endpoints,
        "sourcemaps": sourcemaps,
        "interesting_strings": strings,
        "files_detail": results,
    }


def write_outputs(result: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "js_analysis.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "endpoints.json").write_text(json.dumps(result["endpoints"], indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "strings.json").write_text(json.dumps(result["interesting_strings"], indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# JavaScript Analysis Report",
        "",
        f"Files analyzed: {result['files']}",
        f"Indicators: {', '.join(result['indicators']) if result['indicators'] else 'none'}",
        f"Sourcemaps: {len(result['sourcemaps'])}",
        "",
        "## Endpoints",
    ]
    lines.extend(f"- `{endpoint}`" for endpoint in result["endpoints"][:200])
    lines.extend(["", "## Interesting Strings"])
    lines.extend(f"- `{value}`" for value in result["interesting_strings"][:100])
    lines.extend(["", "## Notes", "- Values are redacted by default. Do not use recovered credentials against live services."])
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze authorized obfuscated JavaScript safely")
    parser.add_argument("path", help="JavaScript file or directory")
    parser.add_argument("--out", default="js-analysis", help="Output directory")
    parser.add_argument("--json", action="store_true", help="Print JSON summary to stdout")
    args = parser.parse_args()

    input_path = Path(args.path)
    if not input_path.exists():
        parser.error(f"path not found: {input_path}")

    files = iter_js_files(input_path)
    if not files:
        parser.error(f"no JavaScript-like files found under: {input_path}")

    results = [analyze_path(path) for path in files]
    merged = merge_results(results)
    write_outputs(merged, Path(args.out))

    if args.json:
        print(json.dumps(merged, indent=2, ensure_ascii=False))
    else:
        print(f"[+] Analyzed {len(files)} file(s)")
        print(f"[+] Endpoints: {merged['summary']['endpoints']}")
        print(f"[+] Indicators: {', '.join(merged['indicators']) if merged['indicators'] else 'none'}")
        print(f"[+] Report: {Path(args.out) / 'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
