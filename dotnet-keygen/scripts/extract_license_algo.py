#!/usr/bin/env python3
"""
extract_license_algo.py — Extract license validation algorithm from decompiled .NET source.

Scans for: serial format, crypto parameters (RSA/AES/HMAC), validation logic,
license libraries, HWID binding, feature flags.

Usage:
    python extract_license_algo.py decompiled/ --out license_info.json
    python extract_license_algo.py decompiled/ --verbose
"""

import argparse
import json
import re
import sys
from pathlib import Path


# --- Serial format detection ---

SERIAL_FORMAT_PATTERNS = [
    (re.compile(r'''["\']([A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})["\']'''),
     '5x5', 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'),
    (re.compile(r'''["\']([A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})["\']'''),
     '4x5', 'XXXXX-XXXXX-XXXXX-XXXXX'),
    (re.compile(r'''["\']([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})["\']'''),
     '4x4', 'XXXX-XXXX-XXXX-XXXX'),
    (re.compile(r'Regex\s*\(\s*@?"([^"]+)"\s*\).*(?:key|serial|license|code)', re.I),
     'regex-defined', None),
    (re.compile(r'\.Length\s*[!=><]+\s*(\d{2,3}).*(?:key|serial|license)', re.I),
     'length-check', None),
]

# --- Crypto parameter extraction ---

RSA_PATTERNS = [
    (re.compile(r'RSACryptoServiceProvider|RSA\.Create|RSAParameters', re.I), 'rsa-usage'),
    (re.compile(r'<Modulus>([A-Za-z0-9+/=]{40,})</Modulus>', re.I), 'rsa-modulus-xml'),
    (re.compile(r'<Exponent>([A-Za-z0-9+/=]+)</Exponent>', re.I), 'rsa-exponent-xml'),
    (re.compile(r'''(?:Modulus|modulus)\s*=\s*["\']([A-Za-z0-9+/=]{40,})["\']'''), 'rsa-modulus-str'),
    (re.compile(r'''PublicKey\s*=\s*["\']([A-Za-z0-9+/=]{40,})["\']'''), 'rsa-pubkey-str'),
    (re.compile(r'FromXmlString\s*\(\s*@?"(<RSAKeyValue>[^"]+</RSAKeyValue>)"', re.I | re.DOTALL), 'rsa-xml-import'),
    (re.compile(r'-----BEGIN\s+(?:RSA\s+)?PUBLIC\s+KEY-----'), 'rsa-pem'),
]

AES_PATTERNS = [
    (re.compile(r'AesCryptoServiceProvider|Aes\.Create|RijndaelManaged', re.I), 'aes-usage'),
    (re.compile(r'''(?:Key|key|aesKey|AESKey)\s*=\s*(?:new\s+byte\[\]\s*\{([^}]+)\}|Encoding\.\w+\.GetBytes\s*\(\s*["\']([^"\']+)["\'])'''), 'aes-key'),
    (re.compile(r'''(?:IV|iv|aesIV|initVector)\s*=\s*(?:new\s+byte\[\]\s*\{([^}]+)\}|Encoding\.\w+\.GetBytes\s*\(\s*["\']([^"\']+)["\'])'''), 'aes-iv'),
]

HMAC_PATTERNS = [
    (re.compile(r'HMAC(?:SHA(?:256|512|1)|MD5)', re.I), 'hmac-usage'),
    (re.compile(r'''(?:hmacKey|secretKey|signingKey|SharedSecret)\s*=\s*["\']([^"\']{8,})["\']''', re.I), 'hmac-secret'),
]

HASH_PATTERNS = [
    (re.compile(r'(?:MD5|SHA1|SHA256|SHA512)\.(?:Create|ComputeHash|HashData)', re.I), 'hash-usage'),
    (re.compile(r'''(?:salt|Salt|SALT)\s*=\s*["\']([^"\']+)["\']'''), 'hash-salt'),
]

# --- License library detection ---

LICENSE_LIB_PATTERNS = [
    (re.compile(r'Cryptlex|LexActivator|LexFloatClient', re.I), 'Cryptlex'),
    (re.compile(r'LimeLM|TurboActivate|TurboFloat', re.I), 'LimeLM/TurboActivate'),
    (re.compile(r'Infralution\.Licensing', re.I), 'Infralution'),
    (re.compile(r'SoftwareKey|InstantLicense', re.I), 'SoftwareKey'),
    (re.compile(r'DevExpress\.Utils\.About|DXperience', re.I), 'DevExpress'),
    (re.compile(r'Telerik\.Licensing', re.I), 'Telerik'),
    (re.compile(r'ComponentSource|Aspose\.License', re.I), 'Aspose'),
    (re.compile(r'Standard\.Licensing|Portable\.Licensing', re.I), 'Standard.Licensing (OSS)'),
]

# --- HWID detection ---

HWID_PATTERNS = [
    (re.compile(r'MachineGuid|HKLM.*Cryptography.*MachineGuid', re.I), 'registry-machine-guid'),
    (re.compile(r'ManagementObjectSearcher.*Win32_(?:Processor|DiskDrive|BaseBoard|BIOS)', re.I), 'wmi-hardware'),
    (re.compile(r'NetworkInterface.*GetPhysicalAddress|MacAddress', re.I), 'mac-address'),
    (re.compile(r'Environment\.MachineName|Environment\.UserName', re.I), 'environment-info'),
    (re.compile(r'GetVolumeInformation|DriveInfo|volumeSerial', re.I), 'disk-serial'),
    (re.compile(r'(?:GetHash|ComputeHash|MD5|SHA).*(?:machineId|hwid|deviceId|fingerprint)', re.I), 'hwid-hash'),
]

# --- Validation logic ---

VALIDATION_PATTERNS = [
    (re.compile(r'(?:checksum|CheckDigit|Luhn|Mod\d{2,3}|VerifyChecksum)', re.I), 'checksum-algo'),
    (re.compile(r'\.Substring\s*\(\s*\d+\s*,\s*\d+\s*\).*(?:int\.Parse|Convert\.ToInt)', re.I), 'positional-digit'),
    (re.compile(r'(?:XOR|xor|\^).*(?:key|serial|license|byte)', re.I), 'xor-validation'),
    (re.compile(r'base64|Convert\.(?:FromBase64|ToBase64)', re.I), 'base64-encoding'),
    (re.compile(r'BitConverter\.ToString|\.ToString\s*\(\s*"[xX]\d"', re.I), 'hex-encoding'),
]

# --- Feature flags ---

FEATURE_PATTERNS = [
    (re.compile(r'(?:enum\s+\w*(?:License|Edition|Tier|Plan)\w*|LicenseType|EditionType)\s*\{([^}]+)\}', re.I | re.DOTALL), 'feature-enum'),
    (re.compile(r'''(?:Features?|Edition|Tier|Plan)\s*[=.]+\s*["\'](\w+)["\']''', re.I), 'feature-string'),
    (re.compile(r'(?:featureMask|featureFlags|features)\s*[&|]\s*(0x[0-9a-fA-F]+|\d+)', re.I), 'feature-bitmask'),
]


def scan_file(filepath: Path) -> dict:
    """Scan a single file for all license-related patterns."""
    try:
        content = filepath.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return {}

    findings = {
        'serial_formats': [],
        'crypto': {'rsa': [], 'aes': [], 'hmac': [], 'hash': []},
        'license_library': None,
        'hwid': [],
        'validation': [],
        'features': [],
    }

    lines = content.splitlines()
    fname = str(filepath)

    for line_no, line in enumerate(lines, 1):
        # Serial formats
        for pattern, format_type, format_str in SERIAL_FORMAT_PATTERNS:
            m = pattern.search(line)
            if m:
                findings['serial_formats'].append({
                    'file': fname, 'line': line_no,
                    'type': format_type,
                    'format': format_str or m.group(1),
                    'context': line.strip()[:200],
                })

        # RSA
        for pattern, ptype in RSA_PATTERNS:
            m = pattern.search(line)
            if m:
                value = m.group(1) if m.lastindex else None
                findings['crypto']['rsa'].append({
                    'file': fname, 'line': line_no,
                    'type': ptype, 'value': value,
                    'context': line.strip()[:300],
                })

        # AES
        for pattern, ptype in AES_PATTERNS:
            m = pattern.search(line)
            if m:
                value = m.group(1) or (m.group(2) if m.lastindex >= 2 else None)
                findings['crypto']['aes'].append({
                    'file': fname, 'line': line_no,
                    'type': ptype, 'value': value,
                    'context': line.strip()[:300],
                })

        # HMAC
        for pattern, ptype in HMAC_PATTERNS:
            m = pattern.search(line)
            if m:
                value = m.group(1) if m.lastindex else None
                findings['crypto']['hmac'].append({
                    'file': fname, 'line': line_no,
                    'type': ptype, 'value': value,
                    'context': line.strip()[:200],
                })

        # Hash
        for pattern, ptype in HASH_PATTERNS:
            m = pattern.search(line)
            if m:
                value = m.group(1) if m.lastindex else None
                findings['crypto']['hash'].append({
                    'file': fname, 'line': line_no,
                    'type': ptype, 'value': value,
                    'context': line.strip()[:200],
                })

        # License library
        for pattern, lib_name in LICENSE_LIB_PATTERNS:
            if pattern.search(line):
                findings['license_library'] = {
                    'name': lib_name,
                    'file': fname, 'line': line_no,
                    'context': line.strip()[:200],
                }

        # HWID
        for pattern, hwid_type in HWID_PATTERNS:
            if pattern.search(line):
                findings['hwid'].append({
                    'file': fname, 'line': line_no,
                    'type': hwid_type,
                    'context': line.strip()[:200],
                })

        # Validation logic
        for pattern, val_type in VALIDATION_PATTERNS:
            if pattern.search(line):
                findings['validation'].append({
                    'file': fname, 'line': line_no,
                    'type': val_type,
                    'context': line.strip()[:200],
                })

        # Features
        for pattern, feat_type in FEATURE_PATTERNS:
            m = pattern.search(line)
            if m:
                value = m.group(1) if m.lastindex else None
                findings['features'].append({
                    'file': fname, 'line': line_no,
                    'type': feat_type,
                    'value': value,
                    'context': line.strip()[:200],
                })

    return findings


def merge_findings(all_findings: list[dict]) -> dict:
    """Merge findings from multiple files into a single report."""
    merged = {
        'serial_formats': [],
        'crypto': {'rsa': [], 'aes': [], 'hmac': [], 'hash': []},
        'license_library': None,
        'hwid': [],
        'validation': [],
        'features': [],
    }

    seen_serial = set()
    for f in all_findings:
        for sf in f.get('serial_formats', []):
            key = (sf['type'], sf.get('format', ''))
            if key not in seen_serial:
                seen_serial.add(key)
                merged['serial_formats'].append(sf)

        for ctype in ('rsa', 'aes', 'hmac', 'hash'):
            merged['crypto'][ctype].extend(f.get('crypto', {}).get(ctype, []))

        if f.get('license_library') and not merged['license_library']:
            merged['license_library'] = f['license_library']

        merged['hwid'].extend(f.get('hwid', []))
        merged['validation'].extend(f.get('validation', []))
        merged['features'].extend(f.get('features', []))

    return merged


def determine_license_type(info: dict) -> dict:
    """Analyze findings to determine overall license type and keygen strategy."""
    analysis = {
        'type': 'unknown',
        'complexity': 'low',
        'keygen_strategy': 'serial-checksum',
        'requires_private_key': False,
        'hwid_bound': False,
        'time_limited': False,
        'online_validation': False,
        'notes': [],
    }

    # Check crypto complexity
    rsa = info['crypto']['rsa']
    aes = info['crypto']['aes']
    hmac = info['crypto']['hmac']

    if rsa:
        analysis['type'] = 'rsa-signed'
        analysis['complexity'] = 'high'
        analysis['keygen_strategy'] = 'rsa-signed'
        analysis['requires_private_key'] = True
        has_modulus = any(r['type'] in ('rsa-modulus-xml', 'rsa-modulus-str') for r in rsa)
        if has_modulus:
            analysis['notes'].append('RSA modulus found — check key size. Keys <= 512 bits may be factorable.')
        analysis['notes'].append('Need private key to generate valid signatures. Check for weak keys or key leaks.')

    elif aes:
        analysis['type'] = 'aes-encrypted'
        analysis['complexity'] = 'medium'
        analysis['keygen_strategy'] = 'hwid-hash'
        has_key = any(a['type'] == 'aes-key' and a.get('value') for a in aes)
        if has_key:
            analysis['notes'].append('AES key extracted from source — can decrypt/encrypt license data.')
            analysis['requires_private_key'] = False

    elif hmac:
        analysis['type'] = 'hmac-signed'
        analysis['complexity'] = 'medium'
        analysis['keygen_strategy'] = 'hwid-hash'
        has_secret = any(h['type'] == 'hmac-secret' and h.get('value') for h in hmac)
        if has_secret:
            analysis['notes'].append('HMAC secret extracted — can generate valid signatures.')
            analysis['requires_private_key'] = False

    elif info['serial_formats']:
        analysis['type'] = 'serial-key'
        analysis['complexity'] = 'low'
        analysis['keygen_strategy'] = 'serial-checksum'
        analysis['notes'].append('Simple serial key format — likely checksum-based validation.')

    # HWID binding
    if info['hwid']:
        analysis['hwid_bound'] = True
        hwid_types = list(set(h['type'] for h in info['hwid']))
        analysis['notes'].append(f'HWID binding detected: {", ".join(hwid_types)}')

    # Feature flags
    if info['features']:
        feat_types = list(set(f['type'] for f in info['features']))
        analysis['notes'].append(f'Feature flags detected: {", ".join(feat_types)}')

    # License library
    if info['license_library']:
        lib = info['license_library']['name']
        analysis['notes'].append(f'License library: {lib}')
        if lib in ('Cryptlex', 'LimeLM/TurboActivate'):
            analysis['online_validation'] = True
            analysis['notes'].append('Commercial license library with online validation — may need server emulation.')

    return analysis


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract license validation algorithm from decompiled .NET")
    ap.add_argument('source_dir', help='Directory with decompiled .cs files')
    ap.add_argument('--out', default='license_info.json', help='Output JSON file')
    ap.add_argument('--verbose', action='store_true', help='Show detailed findings')
    args = ap.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        print(f"[!] Not found: {source_dir}", file=sys.stderr)
        return 1

    cs_files = list(source_dir.rglob('*.cs'))
    config_files = list(source_dir.rglob('*.config')) + list(source_dir.rglob('*.json'))
    all_files = cs_files + config_files
    print(f"[*] Scanning {len(all_files)} files ({len(cs_files)} .cs)...")

    all_findings = []
    for f in all_files:
        findings = scan_file(f)
        if any(findings.values()):
            all_findings.append(findings)

    info = merge_findings(all_findings)
    analysis = determine_license_type(info)

    result = {
        'analysis': analysis,
        'serial_formats': info['serial_formats'],
        'crypto': info['crypto'],
        'license_library': info['license_library'],
        'hwid_methods': info['hwid'],
        'validation_logic': info['validation'],
        'features': info['features'],
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')

    print(f"\n[+] License analysis complete:")
    print(f"    Type            : {analysis['type']}")
    print(f"    Complexity      : {analysis['complexity']}")
    print(f"    Keygen strategy : {analysis['keygen_strategy']}")
    print(f"    Private key req : {analysis['requires_private_key']}")
    print(f"    HWID bound      : {analysis['hwid_bound']}")
    print(f"    Online check    : {analysis['online_validation']}")

    if info['serial_formats']:
        print(f"\n[+] Serial formats found:")
        for sf in info['serial_formats'][:5]:
            print(f"    {sf['type']}: {sf.get('format', 'custom')}")

    crypto_count = sum(len(v) for v in info['crypto'].values())
    if crypto_count:
        print(f"\n[+] Crypto parameters: {crypto_count} items")
        for ctype, items in info['crypto'].items():
            if items:
                print(f"    {ctype}: {len(items)} entries")
                if args.verbose:
                    for item in items[:3]:
                        val = item.get('value', '')
                        if val:
                            print(f"      {item['type']}: {val[:80]}...")

    if analysis['notes']:
        print(f"\n[*] Notes:")
        for note in analysis['notes']:
            print(f"    - {note}")

    print(f"\n[+] Output: {out_path}")
    print(f"[*] Next: python generate_keygen.py {out_path} --out keygen.py")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
