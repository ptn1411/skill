#!/usr/bin/env python3
"""Serial key generator with checksum validation."""

import argparse
import random
import string

CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
GROUP_SIZE = 5
GROUP_COUNT = 4
FORMAT = 'XXXXX-XXXXX-XXXXX-XXXXX'


def compute_checksum(key_chars: str, modulus: int = 97) -> int:
    """Compute check value from key characters."""
    total = 0
    for i, c in enumerate(key_chars):
        total += ord(c) * (i + 1)
    return total % modulus


def generate_key() -> str:
    """Generate a single valid serial key."""
    # Generate random groups except the check digit portion
    groups = []
    for g in range(GROUP_COUNT):
        if g < GROUP_COUNT - 1:
            group = ''.join(random.choices(CHARSET, k=GROUP_SIZE))
        else:
            # Last group: first chars random, last char is check digit
            base = ''.join(random.choices(CHARSET, k=GROUP_SIZE - 1))
            all_chars = '-'.join(groups) + '-' + base
            checksum = compute_checksum(all_chars.replace('-', ''))
            check_char = CHARSET[checksum % len(CHARSET)]
            group = base + check_char
        groups.append(group)

    return '-'.join(groups)


def validate_key(key: str) -> bool:
    """Validate a serial key."""
    parts = key.strip().upper().split('-')
    if len(parts) != GROUP_COUNT:
        return False
    if any(len(p) != GROUP_SIZE for p in parts):
        return False
    if any(c not in CHARSET for p in parts for c in p):
        return False

    # Verify check digit
    all_chars = ''.join(parts)
    base_chars = all_chars[:-1]
    check_char = all_chars[-1]
    expected = CHARSET[compute_checksum(base_chars) % len(CHARSET)]
    return check_char == expected


def main():
    ap = argparse.ArgumentParser(description="Serial key generator")
    ap.add_argument('--count', type=int, default=1, help='Number of keys to generate')
    ap.add_argument('--validate', help='Validate a key')
    args = ap.parse_args()

    if args.validate:
        valid = validate_key(args.validate)
        print(f"Key: {args.validate}")
        print(f"Valid: {valid}")
        return

    for _ in range(args.count):
        key = generate_key()
        valid = validate_key(key)
        print(f"{key}  [{'OK' if valid else 'FAIL'}]")


if __name__ == '__main__':
    main()
