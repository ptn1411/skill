#!/usr/bin/env python3
"""Time-based license generator with encoded expiry date."""

import argparse
import base64
import hashlib
import struct
from datetime import datetime, timedelta

DEFAULT_DAYS = 365
SECRET_SEED = 'LICENSE_SECRET_2024'


def encode_date(dt: datetime) -> str:
    """Encode a date into a license-friendly string."""
    timestamp = int(dt.timestamp())
    packed = struct.pack('<I', timestamp)
    # XOR with secret-derived bytes for light obfuscation
    key_bytes = hashlib.md5(SECRET_SEED.encode()).digest()[:4]
    xored = bytes(a ^ b for a, b in zip(packed, key_bytes))
    return base64.b32encode(xored).decode('ascii').rstrip('=')


def decode_date(encoded: str) -> datetime:
    """Decode a date from license string."""
    padded = encoded + '=' * (-len(encoded) % 8)
    xored = base64.b32decode(padded)
    key_bytes = hashlib.md5(SECRET_SEED.encode()).digest()[:4]
    packed = bytes(a ^ b for a, b in zip(xored, key_bytes))
    timestamp = struct.unpack('<I', packed)[0]
    return datetime.fromtimestamp(timestamp)


def compute_check(issue_code: str, expiry_code: str) -> str:
    """Compute check portion of license key."""
    combined = f"{issue_code}:{expiry_code}:{SECRET_SEED}"
    h = hashlib.sha256(combined.encode()).hexdigest().upper()
    return h[:8]


def generate_license(days: int = DEFAULT_DAYS, start: datetime = None) -> dict:
    """Generate a time-based license key."""
    issue_date = start or datetime.now(tz=None)
    expiry_date = issue_date + timedelta(days=days)

    issue_code = encode_date(issue_date)
    expiry_code = encode_date(expiry_date)
    check = compute_check(issue_code, expiry_code)

    key = f"{issue_code}-{expiry_code}-{check}"

    return {
        'key': key,
        'issued': issue_date.strftime('%Y-%m-%d'),
        'expiry': expiry_date.strftime('%Y-%m-%d'),
        'days': days,
    }


def validate_license(key: str) -> dict:
    """Validate a time-based license key."""
    parts = key.strip().split('-')
    if len(parts) != 3:
        return {'valid': False, 'error': 'Invalid format (expected 3 parts)'}

    issue_code, expiry_code, check = parts

    # Verify checksum
    expected_check = compute_check(issue_code, expiry_code)
    if check.upper() != expected_check.upper():
        return {'valid': False, 'error': 'Invalid checksum'}

    try:
        issue_date = decode_date(issue_code)
        expiry_date = decode_date(expiry_code)
    except Exception as e:
        return {'valid': False, 'error': f'Date decode failed: {e}'}

    now = datetime.now(tz=None)
    expired = now > expiry_date

    return {
        'valid': not expired,
        'issued': issue_date.strftime('%Y-%m-%d'),
        'expiry': expiry_date.strftime('%Y-%m-%d'),
        'expired': expired,
        'days_remaining': max(0, (expiry_date - now).days),
    }


def main():
    ap = argparse.ArgumentParser(description="Time-based license generator")
    ap.add_argument('--days', type=int, default=DEFAULT_DAYS, help='License validity days')
    ap.add_argument('--count', type=int, default=1, help='Number of keys')
    ap.add_argument('--perpetual', action='store_true', help='Generate perpetual license (100 years)')
    ap.add_argument('--validate', help='Validate a key')
    args = ap.parse_args()

    if args.validate:
        result = validate_license(args.validate)
        print(f"Key    : {args.validate}")
        for k, v in result.items():
            print(f"{k:8s}: {v}")
        return

    days = 36500 if args.perpetual else args.days

    for i in range(args.count):
        lic = generate_license(days)
        print(f"Key {i+1}  : {lic['key']}")
        print(f"  Issued : {lic['issued']}")
        print(f"  Expiry : {lic['expiry']}")
        print(f"  Days   : {lic['days']}")
        print()


if __name__ == '__main__':
    main()
