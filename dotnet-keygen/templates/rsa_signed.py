#!/usr/bin/env python3
"""RSA-signed license generator.

For apps that validate license data against an RSA public key.
Requires either:
1. The private key (leaked or generated from weak public key)
2. A factorable public key (< 512 bits)

If the app's RSA modulus is weak, use factordb.com or msieve to factor it,
then reconstruct the private key.
"""

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timedelta

RSA_MODULUS = None
RSA_EXPONENT = 'AQAB'

try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
    HAS_CRYPTO = True
except ImportError:
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes, serialization
        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False


def generate_weak_keypair(bits: int = 512):
    """Generate a weak RSA keypair for testing."""
    try:
        from Crypto.PublicKey import RSA
        key = RSA.generate(bits)
        return key
    except ImportError:
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        return key


def create_license_data(name: str, email: str, features: str = 'pro',
                        days: int = 36500) -> dict:
    """Create license data payload."""
    now = datetime.utcnow()
    expiry = now + timedelta(days=days)
    return {
        'name': name,
        'email': email,
        'features': features,
        'issued': now.strftime('%Y-%m-%d'),
        'expiry': expiry.strftime('%Y-%m-%d'),
        'type': 'perpetual' if days >= 36500 else 'subscription',
    }


def sign_license_pycrypto(license_data: dict, private_key) -> str:
    """Sign license data using PyCryptodome."""
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256

    data_json = json.dumps(license_data, sort_keys=True)
    h = SHA256.new(data_json.encode('utf-8'))
    signature = pkcs1_15.new(private_key).sign(h)

    license_blob = {
        'data': license_data,
        'signature': base64.b64encode(signature).decode('ascii'),
    }
    return base64.b64encode(json.dumps(license_blob).encode('utf-8')).decode('ascii')


def sign_license_cryptography(license_data: dict, private_key) -> str:
    """Sign license data using cryptography library."""
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    data_json = json.dumps(license_data, sort_keys=True).encode('utf-8')
    signature = private_key.sign(data_json, padding.PKCS1v15(), hashes.SHA256())

    license_blob = {
        'data': license_data,
        'signature': base64.b64encode(signature).decode('ascii'),
    }
    return base64.b64encode(json.dumps(license_blob).encode('utf-8')).decode('ascii')


def generate_license(name: str, email: str, features: str = 'pro',
                     days: int = 36500, private_key_path: str = None) -> str:
    """Generate a signed license."""
    license_data = create_license_data(name, email, features, days)

    if private_key_path:
        key_data = open(private_key_path, 'rb').read()
        try:
            from Crypto.PublicKey import RSA
            key = RSA.import_key(key_data)
            return sign_license_pycrypto(license_data, key)
        except ImportError:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            key = load_pem_private_key(key_data, password=None)
            return sign_license_cryptography(license_data, key)

    # No private key — generate a weak test key
    print("[!] No private key provided — generating weak test keypair")
    print("[i] For real keygen, extract/factor the app's RSA key first")
    try:
        from Crypto.PublicKey import RSA
        key = RSA.generate(512)
        return sign_license_pycrypto(license_data, key)
    except ImportError:
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=512)
        return sign_license_cryptography(license_data, key)


def main():
    ap = argparse.ArgumentParser(description="RSA-signed license generator")
    ap.add_argument('--name', default='Licensed User', help='Licensee name')
    ap.add_argument('--email', default='user@example.com', help='Licensee email')
    ap.add_argument('--features', default='pro', help='Feature tier')
    ap.add_argument('--days', type=int, default=36500, help='License validity days')
    ap.add_argument('--private-key', help='PEM private key file')
    ap.add_argument('--count', type=int, default=1, help='Number of licenses')
    args = ap.parse_args()

    if not HAS_CRYPTO:
        print("[!] Install: pip install pycryptodome  (or: pip install cryptography)")
        sys.exit(1)

    for i in range(args.count):
        license_str = generate_license(
            args.name, args.email, args.features, args.days, args.private_key)
        print(f"\n--- License {i+1} ---")
        print(f"Name    : {args.name}")
        print(f"Email   : {args.email}")
        print(f"Features: {args.features}")
        print(f"License : {license_str}")


if __name__ == '__main__':
    main()
