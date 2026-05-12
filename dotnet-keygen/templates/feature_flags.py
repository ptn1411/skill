#!/usr/bin/env python3
"""Feature-flag license generator with encoded bitmask."""

import argparse
import base64
import hashlib
import json
import struct

FEATURES = {
    'free': 0x00,
    'pro': 0x01,
    'enterprise': 0x03,
}

SECRET = 'FEATURE_KEY_SECRET'


def encode_features(feature_mask: int, name: str) -> str:
    """Encode feature mask and name into a license key."""
    # Pack: feature_mask (2 bytes) + name hash (4 bytes)
    name_hash = struct.unpack('<I', hashlib.md5(name.encode()).digest()[:4])[0]
    payload = struct.pack('<HI', feature_mask, name_hash)

    # XOR obfuscation
    key_bytes = hashlib.sha256(SECRET.encode()).digest()[:6]
    xored = bytes(a ^ b for a, b in zip(payload, key_bytes))

    # Compute signature
    sig_input = xored + SECRET.encode()
    sig = hashlib.sha256(sig_input).hexdigest()[:8].upper()

    # Format as base32 + signature
    encoded = base64.b32encode(xored).decode('ascii').rstrip('=')
    return f"{encoded}-{sig}"


def decode_features(key: str) -> dict:
    """Decode feature flags from license key."""
    parts = key.strip().split('-')
    if len(parts) != 2:
        return {'valid': False, 'error': 'Invalid format'}

    encoded, sig = parts

    try:
        padded = encoded + '=' * (-len(encoded) % 8)
        xored = base64.b32decode(padded)
    except Exception:
        return {'valid': False, 'error': 'Decode failed'}

    # Verify signature
    sig_input = xored + SECRET.encode()
    expected_sig = hashlib.sha256(sig_input).hexdigest()[:8].upper()
    if sig.upper() != expected_sig:
        return {'valid': False, 'error': 'Invalid signature'}

    # Decrypt
    key_bytes = hashlib.sha256(SECRET.encode()).digest()[:6]
    payload = bytes(a ^ b for a, b in zip(xored, key_bytes))

    feature_mask = struct.unpack('<H', payload[:2])[0]
    name_hash = struct.unpack('<I', payload[2:6])[0]

    # Resolve feature names
    active_features = []
    for fname, fmask in FEATURES.items():
        if fmask != 0 and (feature_mask & fmask) == fmask:
            active_features.append(fname)
    if not active_features and feature_mask == 0:
        active_features = ['free']

    return {
        'valid': True,
        'feature_mask': hex(feature_mask),
        'features': active_features,
        'name_hash': hex(name_hash),
    }


def get_feature_mask(feature_names: list[str]) -> int:
    """Combine feature names into a bitmask."""
    mask = 0
    for name in feature_names:
        name_lower = name.strip().lower()
        if name_lower in FEATURES:
            mask |= FEATURES[name_lower]
        else:
            print(f"[!] Unknown feature: {name}")
    return mask


def main():
    ap = argparse.ArgumentParser(description="Feature-flag license generator")
    ap.add_argument('--name', default='Licensed User', help='Licensee name')
    ap.add_argument('--features', default='pro', help='Comma-separated features')
    ap.add_argument('--count', type=int, default=1, help='Number of keys')
    ap.add_argument('--validate', help='Validate a key')
    ap.add_argument('--list-features', action='store_true', help='List available features')
    args = ap.parse_args()

    if args.list_features:
        print("[*] Available features:")
        for name, mask in FEATURES.items():
            print(f"    {name:15s} : 0x{mask:04X}")
        return

    if args.validate:
        result = decode_features(args.validate)
        print(f"Key: {args.validate}")
        for k, v in result.items():
            print(f"  {k}: {v}")
        return

    feature_names = [f.strip() for f in args.features.split(',')]
    mask = get_feature_mask(feature_names)

    print(f"Name     : {args.name}")
    print(f"Features : {', '.join(feature_names)} (mask: 0x{mask:04X})")
    print()

    for i in range(args.count):
        key = encode_features(mask, args.name)
        print(f"Key {i+1}: {key}")

        # Self-verify
        check = decode_features(key)
        if check['valid']:
            print(f"  Verified: {check['features']}")
        print()


if __name__ == '__main__':
    main()
