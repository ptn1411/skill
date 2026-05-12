#!/usr/bin/env python3
"""
find_patch_targets.py — Scan decompiled .NET source to identify license check methods.

Finds methods that validate licenses, check trials, compare serials, and call
license servers. Outputs a JSON list of patch targets with method signatures,
file locations, and recommended patch strategy.

Usage:
    python find_patch_targets.py decompiled/ --out targets.json
    python find_patch_targets.py decompiled/ --verbose
"""

import argparse
import json
import re
import sys
from pathlib import Path


# Methods that return bool and relate to licensing
BOOL_LICENSE_PATTERNS = [
    (re.compile(r'(?:public|private|internal|protected)\s+(?:static\s+)?bool\s+(\w*(?:IsValid|IsRegistered|IsLicensed|IsActivated|IsTrial|IsExpired|CheckLicense|ValidateLicense|VerifyLicense|HasLicense|CanUse|IsAuthorized)\w*)\s*\(', re.I),
     'bool-license-check', 'force-true'),
    (re.compile(r'(?:public|private|internal|protected)\s+(?:static\s+)?bool\s+(\w*(?:IsTrialExpired|IsBlocked|IsBlacklisted|NeedsActivation|HasExpired)\w*)\s*\(', re.I),
     'bool-expiry-check', 'force-false'),
]

# Methods that validate keys/serials
KEY_VALIDATION_PATTERNS = [
    (re.compile(r'(?:public|private|internal|protected)\s+(?:static\s+)?\w+\s+(\w*(?:ValidateKey|CheckKey|VerifyKey|ValidateSerial|CheckSerial|DecryptLicense|ParseLicense)\w*)\s*\(', re.I),
     'key-validation', 'force-true'),
]

# License status enums/properties
STATUS_PATTERNS = [
    (re.compile(r'(?:public|private|internal|protected)\s+(?:static\s+)?(?:LicenseStatus|LicenseType|ActivationStatus)\s+(\w+)\s*\{?\s*get', re.I),
     'license-status-property', 'patch-return'),
]

# Network license calls
NETWORK_PATTERNS = [
    (re.compile(r'(?:HttpClient|WebRequest|RestClient|HttpWebRequest).*(?:license|activate|verify|register|auth)', re.I),
     'network-license-call', 'nop-or-mock'),
]

# String comparison for key validation
STRCMP_PATTERNS = [
    (re.compile(r'(?:string\.(?:Equals|Compare)|==\s*["\']|\.Equals\s*\().*(?:key|serial|license|activation|code)', re.I),
     'string-comparison', 'patch-strcmp'),
]

# DateTime checks (trial expiry)
DATETIME_PATTERNS = [
    (re.compile(r'DateTime\.(?:Now|UtcNow|Today)\s*[><=]', re.I),
     'datetime-expiry', 'patch-datetime'),
    (re.compile(r'TimeSpan|\.TotalDays|\.AddDays|DateDiff', re.I),
     'timespan-trial', 'patch-datetime'),
]

# Anti-tamper / integrity
ANTITAMPER_PATTERNS = [
    (re.compile(r'<Module>.*\.cctor|static\s+\w+\(\)\s*\{.*(?:hash|integrity|tamper|checksum)', re.I | re.DOTALL),
     'anti-tamper-cctor', 'nop-cctor'),
    (re.compile(r'(?:Assembly\.GetExecutingAssembly|GetCallingAssembly).*(?:Hash|Checksum|Signature|PublicKey)', re.I),
     'integrity-check', 'nop'),
]


def extract_class_context(content: str, line_no: int) -> str:
    """Find the class name containing the given line."""
    lines = content.splitlines()
    for i in range(line_no - 1, -1, -1):
        m = re.search(r'(?:class|struct|interface)\s+(\w+)', lines[i])
        if m:
            return m.group(1)
    return 'Unknown'


def scan_file(filepath: Path) -> list[dict]:
    """Scan a single .cs file for patch targets."""
    targets = []
    try:
        content = filepath.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return targets

    lines = content.splitlines()
    all_patterns = (
        BOOL_LICENSE_PATTERNS + KEY_VALIDATION_PATTERNS + STATUS_PATTERNS +
        STRCMP_PATTERNS + DATETIME_PATTERNS + ANTITAMPER_PATTERNS
    )

    for line_no, line in enumerate(lines, 1):
        # Check structured patterns (method signatures)
        for pattern, category, strategy in all_patterns:
            m = pattern.search(line)
            if m:
                method_name = m.group(1) if m.lastindex else m.group(0)[:80]
                class_name = extract_class_context(content, line_no)
                targets.append({
                    'file': str(filepath),
                    'line': line_no,
                    'class': class_name,
                    'method': method_name,
                    'category': category,
                    'strategy': strategy,
                    'context': line.strip()[:200],
                })

        # Check network patterns (not method signatures, just call sites)
        for pattern, category, strategy in NETWORK_PATTERNS:
            if pattern.search(line):
                class_name = extract_class_context(content, line_no)
                targets.append({
                    'file': str(filepath),
                    'line': line_no,
                    'class': class_name,
                    'method': '(call site)',
                    'category': category,
                    'strategy': strategy,
                    'context': line.strip()[:200],
                })

    return targets


def deduplicate_targets(targets: list[dict]) -> list[dict]:
    """Remove duplicate entries for same method."""
    seen = set()
    deduped = []
    for t in targets:
        key = (t['class'], t['method'], t['category'])
        if key not in seen:
            seen.add(key)
            deduped.append(t)
    return deduped


def main() -> int:
    ap = argparse.ArgumentParser(description="Find .NET license check methods to patch")
    ap.add_argument('source_dir', help='Directory with decompiled .cs files')
    ap.add_argument('--out', default='patch_targets.json', help='Output JSON file')
    ap.add_argument('--verbose', action='store_true', help='Show all findings')
    args = ap.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        print(f"[!] Not found: {source_dir}", file=sys.stderr)
        return 1

    cs_files = list(source_dir.rglob('*.cs'))
    print(f"[*] Scanning {len(cs_files)} .cs files for patch targets...")

    all_targets = []
    for f in cs_files:
        all_targets.extend(scan_file(f))

    targets = deduplicate_targets(all_targets)

    # Group by strategy
    by_strategy = {}
    for t in targets:
        by_strategy.setdefault(t['strategy'], []).append(t)

    # Write output
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(targets, indent=2, ensure_ascii=False), encoding='utf-8')

    print(f"\n[+] Found {len(targets)} patch targets:")
    for strategy, items in sorted(by_strategy.items()):
        print(f"    {strategy:20s} : {len(items)} targets")
        if args.verbose:
            for item in items:
                print(f"      {item['class']}::{item['method']} @ {Path(item['file']).name}:{item['line']}")

    if targets:
        print(f"\n[*] Recommended patch order:")
        priority = ['nop-cctor', 'force-true', 'force-false', 'patch-strcmp', 'patch-datetime', 'nop-or-mock', 'patch-return']
        for i, p in enumerate(priority, 1):
            if p in by_strategy:
                count = len(by_strategy[p])
                print(f"    {i}. {p} ({count} targets)")

    print(f"\n[+] Targets saved: {out_path}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
