#!/usr/bin/env python3
"""
audit_license.py — Defensive license/entitlement robustness audit.

Static analysis over a (recovered or owned) source tree. It maps the license
validation surface, flags DESIGN weaknesses that make a check easy to abuse, and
produces hardening guidance plus an allow/deny test scaffold.

It does NOT generate keygens, patches, or working bypasses — it explains where a
control is weak and how to strengthen it (see MASTER_POLICY.md §2).

Usage:
    python audit_license.py <source_dir> --out output/license-audit
    python audit_license.py output/dotnet-decompiled --out output/license-audit
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

SOURCE_EXT = {".cs", ".js", ".ts", ".jsx", ".tsx", ".java", ".py", ".cpp", ".c",
              ".cc", ".go", ".vb", ".kt", ".swift", ".php", ".rb"}

LICENSE_KEYWORD = re.compile(
    r"(?i)\b(licen[cs]e|activation|activate|serial|product[_-]?key|registration|"
    r"trial|entitlement|subscription|hwid|machine[_-]?id|expire|expiry|genuine)\b")

# Weakness rules: (compiled regex, severity, category, title, why, fix)
RULES = [
    (re.compile(r"(?i)\b(is|check|verify|validate)[_a-z0-9]*"
                r"(licen[cs]e|activ|trial|serial|genuine|registered)"),
     "high", "client-side-gate", "Client-side validation gate",
     "A boolean check that lives in the client can be observed and tampered; "
     "an attacker forces it true without the real secret.",
     "Move the authoritative check server-side; the client should only render "
     "the server's signed allow/deny decision."),

    (re.compile(r"(?i)(return\s+(true|false)\b[^\n]*licen|licen[^\n]*return\s+(true|false)\b)"),
     "high", "boolean-return", "License decision returned as a bare boolean",
     "A single bool return is the classic one-instruction bypass target.",
     "Return a verified, signed entitlement object with expiry; fail closed on any error."),

    (re.compile(r"-----BEGIN (?:RSA )?PUBLIC KEY-----"),
     "medium", "embedded-pubkey", "Embedded public key",
     "A pinned public key means signature checks are done locally and can be "
     "swapped along with the check.",
     "Verify entitlement signatures server-side; if local, protect the key and "
     "the verify path with tamper-evidence."),

    (re.compile(r"(?i)(secret|hmac|api[_-]?key|priv(ate)?[_-]?key)[a-z0-9_]*\s*[=:]\s*['\"][^'\"]{8,}"),
     "high", "hardcoded-secret", "Hardcoded secret / key material",
     "Any secret shipped in the client is recoverable and lets an attacker mint "
     "valid-looking licenses.",
     "Remove client-side secrets; keep signing keys server-side and rotate them."),

    (re.compile(r"(?i)(serial|licen[cs]e|product[_-]?key)\s*(==|===|\.equals?\s*\(|\.compare)"),
     "medium", "static-compare", "Static key comparison",
     "Comparing the key to a constant/known value makes the accept condition "
     "trivially discoverable.",
     "Validate via server-side signature/HMAC over user+expiry, not string equality."),

    (re.compile(r"(?i)\b(md5|sha1)\b"),
     "medium", "weak-crypto", "Weak hash in licensing path",
     "MD5/SHA-1 are collision-prone and unsuitable for license integrity.",
     "Use SHA-256+ and an authenticated signature (Ed25519/RSA-PSS) verified server-side."),

    (re.compile(r"(?i)(HKEY_|registry|regedit|LocalAppData|%APPDATA%|\.lic\b|\.dat\b|trial.*(date|start))"),
     "low", "local-trial-state", "Local trial / activation state",
     "Trial or activation state kept locally (registry/file) can be reset or "
     "rolled back to extend usage.",
     "Track trial/activation server-side keyed to an account/device; treat local "
     "state as a cache only."),
]

SERVER_HINT = re.compile(r"(?i)(https?://|fetch\(|axios|HttpClient|requests\.|WebClient|"
                         r"socket|grpc|/api/|verifyOnline|activationServer)")


def scan(source_dir: Path):
    files = [p for p in source_dir.rglob("*") if p.is_file() and p.suffix.lower() in SOURCE_EXT]
    license_files = []
    findings = []
    server_seen = False

    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if not LICENSE_KEYWORD.search(text):
            continue
        license_files.append(f)
        lines = text.splitlines()
        if SERVER_HINT.search(text):
            server_seen = True
        for i, line in enumerate(lines, 1):
            for rx, sev, cat, title, why, fix in RULES:
                if rx.search(line):
                    findings.append({
                        "file": str(f), "line": i, "severity": sev, "category": cat,
                        "title": title, "why": why, "fix": fix,
                        "snippet": line.strip()[:160],
                    })
    return files, license_files, findings, server_seen


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def build_report(source_dir: Path, license_files, findings, server_seen) -> str:
    L = [f"# License Robustness Audit — `{source_dir}`", "",
         "_Defensive review of the license/entitlement validation surface. "
         "No bypass or keygen is produced — weaknesses are described so they can be fixed._", ""]

    # Validation surface
    L.append("## 1. Validation surface")
    if license_files:
        L.append(f"License-related logic found in {len(license_files)} file(s):")
        for f in sorted(set(license_files)):
            L.append(f"- `{f}`")
    else:
        L.append("No obvious license logic found by keyword scan. It may be obfuscated, "
                 "native, or server-side.")
    L.append("")
    L.append(f"**Server-side validation signal:** "
             f"{'detected (good)' if server_seen else 'NOT detected — validation looks client-local (weakness)'}")
    L.append("")

    # Weaknesses
    L.append("## 2. Weaknesses (abuse-case view)")
    if findings:
        from collections import Counter
        c = Counter(f["severity"] for f in findings)
        L.append("**By severity:** " + "  ".join(
            f"{k}: {c[k]}" for k in sorted(c, key=lambda s: SEV_ORDER.get(s, 9))))
        L.append("")
        by_cat = defaultdict(list)
        for f in findings:
            by_cat[(f["severity"], f["category"], f["title"], f["why"], f["fix"])].append(f)
        for (sev, cat, title, why, fix), items in sorted(
                by_cat.items(), key=lambda kv: SEV_ORDER.get(kv[0][0], 9)):
            L.append(f"### [{sev.upper()}] {title}  ({len(items)}×)")
            L.append(f"- **Why it's abusable:** {why}")
            L.append(f"- **Hardening fix:** {fix}")
            L.append("- **Locations:**")
            for it in items[:8]:
                L.append(f"  - `{it['file']}:{it['line']}` — `{it['snippet']}`")
            if len(items) > 8:
                L.append(f"  - … {len(items)-8} more")
            L.append("")
    else:
        L.append("No specific weakness patterns matched. Review the surface manually.")
        L.append("")

    # Hardening
    L.append("## 3. Hardening plan")
    L += [
        "1. **Authoritative check server-side.** The client shows a decision; it never *makes* it.",
        "2. **Signed, short-lived entitlements.** Server issues an Ed25519/RSA-PSS token (user, features, expiry); client verifies signature and fails closed.",
        "3. **No secrets in the client.** Keep signing keys server-side; rotate on leak.",
        "4. **Bind to account/device server-side** for trial/activation state; local files are cache only.",
        "5. **Tamper-evidence & telemetry.** Log verification failures and anomalies for detection; don't rely on silent client checks.",
        "6. **Fail closed.** Any error in the license path denies access, never grants it.",
        "",
    ]

    # Test plan
    L.append("## 4. Allow/deny test plan")
    L += [
        "Prove the legitimate path behaves correctly (a generated scaffold is written to "
        "`test_license_behavior.py`):",
        "- valid entitlement → access granted",
        "- expired entitlement → denied",
        "- tampered/invalid signature → denied",
        "- missing/malformed license → denied (fail closed)",
        "- server unreachable → denied or documented offline-grace policy",
        "",
    ]
    return "\n".join(L)


TEST_SCAFFOLD = '''"""
test_license_behavior.py — generated allow/deny scaffold (defensive).

Fill in `evaluate_license(...)` to call YOUR real validation entry point, then
these tests prove the legitimate path grants/denies correctly. This verifies
robustness — it is not a bypass.
"""
import pytest

def evaluate_license(token: str) -> bool:
    """TODO: call your real server-side-verified license check here."""
    raise NotImplementedError

@pytest.mark.parametrize("token,expected", [
    ("VALID_SIGNED_ENTITLEMENT", True),
    ("EXPIRED_ENTITLEMENT", False),
    ("TAMPERED_SIGNATURE", False),
    ("", False),                # missing -> fail closed
    ("garbage", False),         # malformed -> fail closed
])
def test_allow_deny(token, expected):
    assert evaluate_license(token) is expected
'''


def main() -> int:
    ap = argparse.ArgumentParser(description="Defensive license robustness audit.")
    ap.add_argument("source", help="Source directory (owned or recovered).")
    ap.add_argument("--out", default="output/license-audit")
    args = ap.parse_args()

    src = Path(args.source)
    if not src.exists() or not src.is_dir():
        print(f"[!] Source dir not found: {src}", file=sys.stderr)
        return 1

    files, license_files, findings, server_seen = scan(src)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "license_findings.json").write_text(
        json.dumps({"source": str(src), "files_scanned": len(files),
                    "license_files": [str(f) for f in license_files],
                    "server_validation": server_seen, "findings": findings}, indent=2),
        encoding="utf-8")
    (out / "LICENSE_AUDIT.md").write_text(
        build_report(src, license_files, findings, server_seen), encoding="utf-8")
    (out / "test_license_behavior.py").write_text(TEST_SCAFFOLD, encoding="utf-8")

    print(f"[+] Scanned {len(files)} source file(s); {len(license_files)} touch licensing.")
    print(f"[+] {len(findings)} weakness signal(s).")
    print(f"[+] {out / 'LICENSE_AUDIT.md'}")
    print(f"[+] {out / 'test_license_behavior.py'} (fill in evaluate_license)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
