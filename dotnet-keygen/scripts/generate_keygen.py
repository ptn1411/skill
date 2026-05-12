#!/usr/bin/env python3
"""
generate_keygen.py — Generate a standalone keygen from extracted license info or template.

Reads the output of extract_license_algo.py and generates a self-contained
Python keygen script. Alternatively, use --template for common patterns.

Usage:
    python generate_keygen.py license_info.json --out keygen.py
    python generate_keygen.py --template serial-checksum --format "XXXXX-XXXXX-XXXXX-XXXXX" --out keygen.py
    python generate_keygen.py --template hwid-hash --algo sha256 --secret "key" --out keygen.py
    python generate_keygen.py --template rsa-signed --pubkey key.pem --out keygen.py
    python generate_keygen.py --template time-based --days 365 --out keygen.py
    python generate_keygen.py --template feature-flags --features "pro,enterprise" --out keygen.py
"""

import argparse
import json
import sys
from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent.parent / 'templates'

AVAILABLE_TEMPLATES = [
    'serial-checksum',
    'rsa-signed',
    'hwid-hash',
    'time-based',
    'feature-flags',
]


def load_template(name: str) -> str:
    """Load a keygen template."""
    filename = name.replace('-', '_') + '.py'
    path = TEMPLATES_DIR / filename
    if not path.exists():
        print(f"[!] Template not found: {path}", file=sys.stderr)
        return ''
    return path.read_text(encoding='utf-8')


def customize_serial_checksum(template: str, serial_format: str, charset: str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') -> str:
    """Customize serial checksum template."""
    template = template.replace("'XXXXX-XXXXX-XXXXX-XXXXX'", f"'{serial_format}'")
    template = template.replace("CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'",
                                f"CHARSET = '{charset}'")

    # Calculate group size and count from format
    groups = serial_format.split('-')
    group_size = len(groups[0]) if groups else 5
    group_count = len(groups)
    template = template.replace('GROUP_SIZE = 5', f'GROUP_SIZE = {group_size}')
    template = template.replace('GROUP_COUNT = 4', f'GROUP_COUNT = {group_count}')

    return template


def customize_hwid_hash(template: str, algo: str = 'sha256', secret: str = '') -> str:
    """Customize HWID hash template."""
    template = template.replace("HASH_ALGO = 'sha256'", f"HASH_ALGO = '{algo}'")
    if secret:
        template = template.replace("SHARED_SECRET = 'CHANGE_ME'", f"SHARED_SECRET = '{secret}'")
    return template


def customize_time_based(template: str, days: int = 365) -> str:
    """Customize time-based template."""
    template = template.replace('DEFAULT_DAYS = 365', f'DEFAULT_DAYS = {days}')
    return template


def customize_feature_flags(template: str, features: list[str]) -> str:
    """Customize feature flags template."""
    feature_dict = {}
    for i, f in enumerate(features):
        feature_dict[f.strip()] = 1 << i

    feature_str = json.dumps(feature_dict, indent=4)
    template = template.replace(
        "FEATURES = {\n    'free': 0x00,\n    'pro': 0x01,\n    'enterprise': 0x03,\n}",
        f"FEATURES = {feature_str}"
    )
    return template


def generate_from_license_info(info_path: Path) -> str:
    """Generate keygen from extracted license info JSON."""
    info = json.loads(info_path.read_text(encoding='utf-8'))
    analysis = info.get('analysis', {})
    strategy = analysis.get('keygen_strategy', 'serial-checksum')

    print(f"[*] Strategy: {strategy}")
    print(f"[*] Type: {analysis.get('type', 'unknown')}")

    template = load_template(strategy)
    if not template:
        print(f"[!] No template for strategy: {strategy}")
        print(f"[*] Falling back to serial-checksum")
        template = load_template('serial-checksum')

    # Apply extracted parameters
    if strategy == 'serial-checksum':
        formats = info.get('serial_formats', [])
        if formats:
            fmt = formats[0].get('format', 'XXXXX-XXXXX-XXXXX-XXXXX')
            template = customize_serial_checksum(template, fmt)

    elif strategy == 'hwid-hash':
        hmac_items = info.get('crypto', {}).get('hmac', [])
        secret = ''
        for item in hmac_items:
            if item.get('value'):
                secret = item['value']
                break
        hash_items = info.get('crypto', {}).get('hash', [])
        algo = 'sha256'
        for item in hash_items:
            if 'SHA512' in item.get('context', ''):
                algo = 'sha512'
            elif 'SHA1' in item.get('context', ''):
                algo = 'sha1'
            elif 'MD5' in item.get('context', ''):
                algo = 'md5'
        template = customize_hwid_hash(template, algo, secret)

    elif strategy == 'rsa-signed':
        rsa_items = info.get('crypto', {}).get('rsa', [])
        for item in rsa_items:
            if item.get('value') and item['type'] in ('rsa-modulus-xml', 'rsa-modulus-str'):
                template = template.replace("RSA_MODULUS = None", f"RSA_MODULUS = '{item['value']}'")
            if item.get('value') and item['type'] == 'rsa-exponent-xml':
                template = template.replace("RSA_EXPONENT = 'AQAB'", f"RSA_EXPONENT = '{item['value']}'")

    # Add extracted info as comment header
    header = [
        '# Auto-generated keygen',
        f'# License type: {analysis.get("type", "unknown")}',
        f'# Complexity: {analysis.get("complexity", "unknown")}',
        f'# HWID bound: {analysis.get("hwid_bound", False)}',
        f'# Source: {info_path.name}',
        '#',
    ]
    for note in analysis.get('notes', []):
        header.append(f'# Note: {note}')
    header.append('')

    template = '\n'.join(header) + template

    return template


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate keygen from license info or template")
    ap.add_argument('license_info', nargs='?', help='License info JSON from extract_license_algo.py')
    ap.add_argument('--template', choices=AVAILABLE_TEMPLATES, help='Use a keygen template')
    ap.add_argument('--format', default='XXXXX-XXXXX-XXXXX-XXXXX', help='Serial format for serial-checksum')
    ap.add_argument('--algo', default='sha256', help='Hash algo for hwid-hash')
    ap.add_argument('--secret', default='', help='Shared secret for hwid-hash')
    ap.add_argument('--pubkey', help='RSA public key file for rsa-signed')
    ap.add_argument('--days', type=int, default=365, help='Default days for time-based')
    ap.add_argument('--features', help='Comma-separated features for feature-flags')
    ap.add_argument('--out', help='Output keygen script')
    ap.add_argument('--list', action='store_true', help='List available templates')
    args = ap.parse_args()

    if args.list:
        print("[*] Available keygen templates:")
        for t in AVAILABLE_TEMPLATES:
            filename = t.replace('-', '_') + '.py'
            path = TEMPLATES_DIR / filename
            exists = "+" if path.exists() else "-"
            print(f"    [{exists}] {t}")
        return 0

    if not args.out:
        print("[!] --out is required (unless --list)", file=sys.stderr)
        return 1

    script = ''

    if args.license_info:
        info_path = Path(args.license_info)
        if not info_path.exists():
            print(f"[!] Not found: {info_path}", file=sys.stderr)
            return 1
        print(f"[*] Generating from: {info_path.name}")
        script = generate_from_license_info(info_path)

    elif args.template:
        print(f"[*] Using template: {args.template}")
        script = load_template(args.template)
        if not script:
            return 1

        if args.template == 'serial-checksum':
            script = customize_serial_checksum(script, args.format)
        elif args.template == 'hwid-hash':
            script = customize_hwid_hash(script, args.algo, args.secret)
        elif args.template == 'time-based':
            script = customize_time_based(script, args.days)
        elif args.template == 'feature-flags' and args.features:
            feats = [f.strip() for f in args.features.split(',')]
            script = customize_feature_flags(script, feats)

    else:
        print("[!] Specify license_info JSON or --template", file=sys.stderr)
        return 1

    if not script:
        print("[!] Failed to generate keygen script", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(script, encoding='utf-8')

    print(f"\n[+] Keygen generated: {out_path}")
    print(f"[*] Test: python {out_path} --count 5")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
