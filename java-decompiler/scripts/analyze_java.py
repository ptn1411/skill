#!/usr/bin/env python3
"""
analyze_java.py — Analyse decompiled Java source for license logic, secrets, and endpoints.

Scans .java source files for license validation patterns, hardcoded API keys,
network endpoints, crypto usage, and common library dependencies.

Usage:
    python analyze_java.py output/java-decompiled --out output/java-analysis
    python analyze_java.py output/java-decompiled/src --out output/java-analysis --verbose
"""

import argparse
import json
import re
import sys
from pathlib import Path


# --- License detection --------------------------------------------------------

LICENSE_FUNCTION_PATTERNS = [
    re.compile(r'(?:public|private|protected)\s+(?:static\s+)?(?:boolean|Boolean|int|String)\s+'
               r'((?:check|validate|verify|is)[A-Z_]\w*(?:[Ll]icen[sc]e|[Kk]ey|[Ss]erial|[Rr]egist|[Aa]ctivat)\w*)\s*\('),
    re.compile(r'(?:public|private|protected)\s+(?:static\s+)?(?:boolean|Boolean)\s+'
               r'(is(?:Licensed|Registered|Activated|Valid|Trial|Expired|Pro|Premium))\s*\('),
    re.compile(r'(?:public|private|protected)\s+\w+\s+'
               r'((?:license|serial|activation|registration)[A-Z]\w*)\s*\('),
]

LICENSE_STRING_PATTERNS = [
    (re.compile(r'"(?:[Ii]nvalid|[Ww]rong|[Bb]ad)\s*(?:license|key|serial|code|registration)"'), 'validation-error'),
    (re.compile(r'"(?:[Ll]icense|[Kk]ey|[Ss]erial)\s*(?:expired|invalid|not found)"'), 'expiry-error'),
    (re.compile(r'"(?:[Ee]nter|[Pp]rovide|[Ii]nput)\s*(?:your\s+)?(?:license|serial|activation)"'), 'license-prompt'),
    (re.compile(r'"(?:[Tt]rial|[Dd]emo)\s*(?:period|version|expired|mode|ended)"'), 'trial-check'),
    (re.compile(r'"(?:[Rr]egistered|[Ll]icensed|[Aa]ctivated)\s*(?:to|user|version)"'), 'license-status'),
    (re.compile(r'"(?:[Dd]ays?\s*remaining|expires?\s*(?:on|in|at))"'), 'expiry-info'),
    (re.compile(r'"(?:[Pp]urchase|[Bb]uy|[Uu]pgrade)\s*(?:license|premium|pro|full)"'), 'purchase-prompt'),
]

LICENSE_IMPORT_PATTERNS = [
    (re.compile(r'import\s+(com\.aspose\.\w+)'), 'Aspose (commercial)'),
    (re.compile(r'import\s+(com\.jetbrains\.\w+)'), 'JetBrains'),
    (re.compile(r'import\s+(com\.intellij\.\w+)'), 'IntelliJ'),
    (re.compile(r'import\s+(de\.schlichtherle\.license\.\w+)'), 'TrueLicense'),
    (re.compile(r'import\s+(com\.license4j\.\w+)'), 'License4J'),
    (re.compile(r'import\s+(net\.nicholaswilliams\.java\.licensing\.\w+)'), 'License3j'),
    (re.compile(r'import\s+(com\.verhas\.licensor\.\w+)'), 'License3j (verhas)'),
    (re.compile(r'import\s+(eu\.hansolo\.fx\.licensing\.\w+)'), 'FXLicensing'),
]


def find_license_logic(content: str, filepath: str) -> list[dict]:
    """Find license-related code patterns."""
    findings = []

    # Function patterns
    for pat in LICENSE_FUNCTION_PATTERNS:
        for m in pat.finditer(content):
            line_no = content[:m.start()].count('\n') + 1
            findings.append({
                'type': 'license-function',
                'name': m.group(1),
                'file': filepath,
                'line': line_no,
                'context': content[max(0, m.start() - 20):m.end() + 80].strip(),
            })

    # String patterns
    for pat, kind in LICENSE_STRING_PATTERNS:
        for m in pat.finditer(content):
            line_no = content[:m.start()].count('\n') + 1
            findings.append({
                'type': kind,
                'match': m.group()[:100],
                'file': filepath,
                'line': line_no,
            })

    # Import patterns (license libraries)
    for pat, lib_name in LICENSE_IMPORT_PATTERNS:
        for m in pat.finditer(content):
            findings.append({
                'type': 'license-library',
                'library': lib_name,
                'import': m.group(1),
                'file': filepath,
            })

    return findings


# --- Secret detection ---------------------------------------------------------

SECRET_PATTERNS = [
    (re.compile(r'"((?:sk|pk|rk)[-_](?:live|test|prod)[-_][A-Za-z0-9]{10,})"'), 'stripe-key'),
    (re.compile(r'"(AIza[A-Za-z0-9_-]{35})"'), 'google-api-key'),
    (re.compile(r'"(gh[ps]_[A-Za-z0-9]{36,})"'), 'github-token'),
    (re.compile(r'"(xox[bpsa]-[A-Za-z0-9-]{10,})"'), 'slack-token'),
    (re.compile(r'"(AKIA[A-Z0-9]{16})"'), 'aws-access-key'),
    (re.compile(r'"(ya29\.[A-Za-z0-9_-]+)"'), 'google-oauth-token'),
    (re.compile(r'"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"'), 'jwt-token'),
    (re.compile(r'(?:password|passwd|secret|api_?key|apikey|token|auth)\s*=\s*"([^"]{8,})"', re.IGNORECASE), 'hardcoded-secret'),
    (re.compile(r'(?:private\s+(?:static\s+)?(?:final\s+)?String\s+\w*(?:KEY|SECRET|TOKEN|PASS)\w*\s*=\s*"([^"]{8,})")', re.IGNORECASE), 'hardcoded-constant'),
]


def find_secrets(content: str, filepath: str) -> list[dict]:
    """Find hardcoded secrets and API keys."""
    findings = []
    for pat, kind in SECRET_PATTERNS:
        for m in pat.finditer(content):
            value = m.group(1)
            line_no = content[:m.start()].count('\n') + 1
            findings.append({
                'type': kind,
                'value': value[:80],
                'file': filepath,
                'line': line_no,
            })
    return findings


# --- Endpoint detection -------------------------------------------------------

ENDPOINT_PATTERNS = [
    re.compile(r'"(https?://[a-zA-Z0-9._/\-:@?=&%#+]{5,})"'),
    re.compile(r'@(?:GET|POST|PUT|DELETE|PATCH)\s*\(\s*"([^"]+)"'),  # JAX-RS
    re.compile(r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?"([^"]+)"'),  # Spring
    re.compile(r'@(?:Get|Post|Put|Delete)Mapping\s*\(\s*"([^"]+)"'),  # Spring
    re.compile(r'\.(?:get|post|put|delete)\s*\(\s*"(/[^"]+)"'),  # REST client
]


def find_endpoints(content: str, filepath: str) -> list[dict]:
    """Find API endpoints and URLs."""
    findings = []
    seen = set()
    for pat in ENDPOINT_PATTERNS:
        for m in pat.finditer(content):
            url = m.group(1)
            if url in seen or 'w3.org' in url or 'schemas.' in url or 'xmlns' in url:
                continue
            seen.add(url)
            line_no = content[:m.start()].count('\n') + 1
            findings.append({
                'url': url[:200],
                'file': filepath,
                'line': line_no,
            })
    return findings


# --- Crypto usage detection ---------------------------------------------------

CRYPTO_PATTERNS = [
    (re.compile(r'(?:import\s+)?(?:javax\.crypto\.)?Cipher\.getInstance\s*\(\s*"([^"]+)"'), 'cipher'),
    (re.compile(r'(?:import\s+)?(?:java\.security\.)?MessageDigest\.getInstance\s*\(\s*"([^"]+)"'), 'hash'),
    (re.compile(r'(?:import\s+)?(?:javax\.crypto\.)?Mac\.getInstance\s*\(\s*"([^"]+)"'), 'hmac'),
    (re.compile(r'(?:import\s+)?(?:java\.security\.)?KeyFactory\.getInstance\s*\(\s*"([^"]+)"'), 'key-factory'),
    (re.compile(r'(?:import\s+)?(?:java\.security\.)?Signature\.getInstance\s*\(\s*"([^"]+)"'), 'signature'),
    (re.compile(r'SecretKeySpec\s*\(\s*"([^"]+)"'), 'secret-key'),
    (re.compile(r'new\s+(?:javax\.crypto\.spec\.)?IvParameterSpec\s*\('), 'iv-spec'),
    (re.compile(r'KeyPairGenerator\.getInstance\s*\(\s*"([^"]+)"'), 'keypair-gen'),
]


def find_crypto_usage(content: str, filepath: str) -> list[dict]:
    """Find cryptographic API usage."""
    findings = []
    for pat, kind in CRYPTO_PATTERNS:
        for m in pat.finditer(content):
            algo = m.group(1) if pat.groups else None
            line_no = content[:m.start()].count('\n') + 1
            findings.append({
                'type': kind,
                'algorithm': algo,
                'file': filepath,
                'line': line_no,
                'context': content[max(0, m.start() - 10):m.end() + 50].strip()[:150],
            })
    return findings


# --- Dependency / import analysis ---------------------------------------------

def analyze_imports(content: str, filepath: str) -> list[str]:
    """Extract import statements for dependency analysis."""
    imports = []
    for m in re.finditer(r'^import\s+([\w.]+(?:\.\*)?)\s*;', content, re.MULTILINE):
        imports.append(m.group(1))
    return imports


def categorize_imports(all_imports: list[str]) -> dict:
    """Categorize imports by domain."""
    categories = {
        'crypto': [], 'network': [], 'database': [], 'ui': [],
        'serialization': [], 'logging': [], 'testing': [], 'other': [],
    }

    for imp in set(all_imports):
        if any(k in imp for k in ('javax.crypto', 'java.security', 'bouncycastle', 'crypto')):
            categories['crypto'].append(imp)
        elif any(k in imp for k in ('java.net', 'http', 'okhttp', 'retrofit', 'apache.http', 'socket')):
            categories['network'].append(imp)
        elif any(k in imp for k in ('sql', 'jdbc', 'hibernate', 'jpa', 'mongo', 'redis')):
            categories['database'].append(imp)
        elif any(k in imp for k in ('javax.swing', 'javafx', 'awt', 'android.widget', 'android.view')):
            categories['ui'].append(imp)
        elif any(k in imp for k in ('gson', 'jackson', 'json', 'xml', 'jaxb', 'protobuf')):
            categories['serialization'].append(imp)
        elif any(k in imp for k in ('log4j', 'slf4j', 'logging', 'logger')):
            categories['logging'].append(imp)
        elif any(k in imp for k in ('junit', 'test', 'mock', 'assert')):
            categories['testing'].append(imp)

    return {k: sorted(v) for k, v in categories.items() if v}


# --- HWID / machine binding detection ----------------------------------------

HWID_PATTERNS = [
    (re.compile(r'(?:NetworkInterface|getHardwareAddress|getMacAddress)', re.IGNORECASE), 'mac-address'),
    (re.compile(r'(?:getHostName|InetAddress\.getLocalHost)', re.IGNORECASE), 'hostname'),
    (re.compile(r'(?:System\.getenv|System\.getProperty)\s*\(\s*"([^"]*(?:user|os|arch|name)[^"]*)"', re.IGNORECASE), 'system-property'),
    (re.compile(r'(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\([^)]*(?:wmic|dmidecode|ioreg|hwinfo)'), 'hardware-query'),
    (re.compile(r'(?:serialNumber|motherboard|processor|bios)', re.IGNORECASE), 'hardware-id'),
    (re.compile(r'(?:UUID\.randomUUID|MachineIdentifier|DeviceId)', re.IGNORECASE), 'uuid-binding'),
]


def find_hwid_binding(content: str, filepath: str) -> list[dict]:
    """Find hardware ID / machine binding logic."""
    findings = []
    for pat, kind in HWID_PATTERNS:
        for m in pat.finditer(content):
            line_no = content[:m.start()].count('\n') + 1
            findings.append({
                'type': kind,
                'match': m.group()[:100],
                'file': filepath,
                'line': line_no,
            })
    return findings


# --- Serial format detection --------------------------------------------------

SERIAL_FORMAT_PATTERNS = [
    re.compile(r'"([A-Z0-9]{4,5}-[A-Z0-9]{4,5}(?:-[A-Z0-9]{4,5}){1,5})"'),
    re.compile(r'Pattern\.compile\s*\(\s*"([^"]*[A-Z0-9].*?-.*?)"'),
    re.compile(r'\.matches\s*\(\s*"([^"]*\\w.*?-.*?)"'),
    re.compile(r'\.split\s*\(\s*"-"\s*\)[^;]*\.length\s*==\s*(\d+)'),
]


def find_serial_formats(content: str, filepath: str) -> list[dict]:
    """Find serial key format definitions."""
    findings = []
    for pat in SERIAL_FORMAT_PATTERNS:
        for m in pat.finditer(content):
            line_no = content[:m.start()].count('\n') + 1
            findings.append({
                'format_or_pattern': m.group(1) if pat.groups else m.group(),
                'file': filepath,
                'line': line_no,
            })
    return findings


# --- Main analysis ------------------------------------------------------------

def analyze_directory(source_dir: Path, verbose: bool = False) -> dict:
    """Analyse all Java source files in a directory."""
    all_license = []
    all_secrets = []
    all_endpoints = []
    all_crypto = []
    all_imports = []
    all_hwid = []
    all_serials = []
    files_analyzed = []

    # Find all .java files
    java_files = sorted(source_dir.rglob('*.java'))
    print(f"[*] Scanning {len(java_files)} Java source files...")

    for f in java_files:
        try:
            content = f.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue

        rel = str(f.relative_to(source_dir))
        files_analyzed.append(rel)

        license_hits = find_license_logic(content, rel)
        secret_hits = find_secrets(content, rel)
        endpoint_hits = find_endpoints(content, rel)
        crypto_hits = find_crypto_usage(content, rel)
        import_hits = analyze_imports(content, rel)
        hwid_hits = find_hwid_binding(content, rel)
        serial_hits = find_serial_formats(content, rel)

        all_license.extend(license_hits)
        all_secrets.extend(secret_hits)
        all_endpoints.extend(endpoint_hits)
        all_crypto.extend(crypto_hits)
        all_imports.extend(import_hits)
        all_hwid.extend(hwid_hits)
        all_serials.extend(serial_hits)

        if verbose and (license_hits or secret_hits):
            print(f"  [{'+' if license_hits else '-'}] {rel}: "
                  f"{len(license_hits)} license, {len(secret_hits)} secrets")

    # Categorize imports
    import_categories = categorize_imports(all_imports)

    # Print summary
    print(f"\n[+] License logic: {len(all_license)} findings")
    for f in all_license[:8]:
        if f['type'] == 'license-function':
            print(f"    [func] {f['name']}  ({f['file']}:{f['line']})")
        elif f['type'] == 'license-library':
            print(f"    [lib]  {f['library']}  ({f['import']})")
        else:
            print(f"    [{f['type']}] {f.get('match', '')[:60]}")

    if all_secrets:
        print(f"[+] Secrets: {len(all_secrets)} findings")
        for s in all_secrets[:5]:
            print(f"    [{s['type']}] {s['value'][:40]}...  ({s['file']}:{s['line']})")

    if all_endpoints:
        print(f"[+] Endpoints: {len(all_endpoints)}")
        for e in all_endpoints[:5]:
            print(f"    {e['url'][:80]}")

    if all_crypto:
        print(f"[+] Crypto usage: {len(all_crypto)}")
        for c in all_crypto[:5]:
            print(f"    [{c['type']}] {c.get('algorithm', 'N/A')}  ({c['file']}:{c['line']})")

    if all_hwid:
        print(f"[+] HWID binding: {len(all_hwid)} patterns")
        for h in all_hwid[:5]:
            print(f"    [{h['type']}] {h['match'][:60]}")

    if all_serials:
        print(f"[+] Serial formats: {len(all_serials)}")
        for s in all_serials[:3]:
            print(f"    {s['format_or_pattern']}")

    if import_categories.get('crypto'):
        print(f"[+] Crypto imports: {len(import_categories['crypto'])}")

    return {
        'files_analyzed': len(files_analyzed),
        'license': all_license,
        'secrets': all_secrets,
        'endpoints': all_endpoints,
        'crypto': all_crypto,
        'hwid': all_hwid,
        'serial_formats': all_serials,
        'import_categories': import_categories,
        'keygen_strategy': determine_keygen_strategy(all_license, all_crypto, all_hwid, all_serials),
    }


def determine_keygen_strategy(license: list, crypto: list, hwid: list, serials: list) -> dict:
    """Recommend a keygen strategy based on analysis."""
    has_rsa = any(c['type'] in ('signature', 'key-factory', 'keypair-gen') for c in crypto)
    has_hash = any(c['type'] == 'hash' for c in crypto)
    has_hmac = any(c['type'] == 'hmac' for c in crypto)
    has_cipher = any(c['type'] == 'cipher' for c in crypto)
    has_hwid = bool(hwid)
    has_serials = bool(serials)

    if has_rsa:
        strategy = 'rsa-signed'
        complexity = 'high'
        notes = ['RSA signature verification detected — need private key or weak key factoring']
    elif has_hmac and has_hwid:
        strategy = 'hwid-hash'
        complexity = 'medium'
        notes = ['HMAC + HWID binding — extract shared secret from binary']
    elif has_cipher:
        strategy = 'encrypted-license'
        complexity = 'high'
        notes = ['Encrypted license file — extract AES/DES key from binary']
    elif has_hash and has_serials:
        strategy = 'serial-checksum'
        complexity = 'low'
        notes = ['Hash-based serial validation — reversible checksum likely']
    elif has_serials:
        strategy = 'serial-checksum'
        complexity = 'low'
        notes = ['Serial format detected — analyse check algorithm']
    elif has_hwid:
        strategy = 'hwid-hash'
        complexity = 'medium'
        notes = ['HWID binding without clear crypto — may use simple hash']
    else:
        strategy = 'unknown'
        complexity = 'unknown'
        notes = ['No clear license algorithm — manual analysis needed']

    return {
        'strategy': strategy,
        'complexity': complexity,
        'notes': notes,
        'has_rsa': has_rsa,
        'has_hmac': has_hmac,
        'has_cipher': has_cipher,
        'has_hwid': has_hwid,
        'has_serial_format': has_serials,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyse decompiled Java source")
    ap.add_argument('source_dir', help='Directory with decompiled .java files')
    ap.add_argument('--out', required=True, help='Output directory')
    ap.add_argument('--verbose', action='store_true', help='Verbose per-file output')
    args = ap.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        print(f"[!] Not found: {source_dir}", file=sys.stderr)
        return 1

    analysis = analyze_directory(source_dir, args.verbose)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / 'java_analysis.json'
    json_path.write_text(json.dumps(analysis, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"\n[+] Analysis: {json_path}")

    # Keygen strategy
    ks = analysis['keygen_strategy']
    print(f"\n{'=' * 50}")
    print(f"[+] Keygen strategy: {ks['strategy']} (complexity: {ks['complexity']})")
    for note in ks['notes']:
        print(f"    -> {note}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
