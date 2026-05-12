#!/usr/bin/env python3
"""HWID-bound license generator with shared secret."""

import argparse
import hashlib
import hmac
import platform
import subprocess
import sys

HASH_ALGO = 'sha256'
SHARED_SECRET = 'CHANGE_ME'


def get_machine_guid_windows() -> str:
    """Get Windows MachineGuid from registry."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r'SOFTWARE\Microsoft\Cryptography',
        )
        guid, _ = winreg.QueryValueEx(key, 'MachineGuid')
        winreg.CloseKey(key)
        return guid
    except Exception:
        return ''


def get_machine_guid_linux() -> str:
    """Get Linux machine ID."""
    for path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
        try:
            with open(path) as f:
                return f.read().strip()
        except Exception:
            continue
    return ''


def get_hwid() -> str:
    """Get hardware ID for current machine."""
    if sys.platform == 'win32':
        guid = get_machine_guid_windows()
        if guid:
            return guid
        try:
            out = subprocess.check_output(
                ['wmic', 'csproduct', 'get', 'UUID'],
                text=True, stderr=subprocess.DEVNULL,
            )
            for line in out.strip().splitlines()[1:]:
                if line.strip():
                    return line.strip()
        except Exception:
            pass
    else:
        guid = get_machine_guid_linux()
        if guid:
            return guid

    return platform.node()


def generate_license(hwid: str, secret: str = SHARED_SECRET,
                     algo: str = HASH_ALGO) -> str:
    """Generate HWID-bound license key."""
    h = hmac.new(
        secret.encode('utf-8'),
        hwid.encode('utf-8'),
        getattr(hashlib, algo),
    )
    digest = h.hexdigest().upper()

    # Format as serial key groups
    groups = [digest[i:i+5] for i in range(0, min(len(digest), 25), 5)]
    return '-'.join(groups)


def validate_license(key: str, hwid: str, secret: str = SHARED_SECRET,
                     algo: str = HASH_ALGO) -> bool:
    """Validate a license key against HWID."""
    expected = generate_license(hwid, secret, algo)
    return key.upper().replace('-', '') == expected.upper().replace('-', '')


def main():
    ap = argparse.ArgumentParser(description="HWID-bound license generator")
    ap.add_argument('--hwid', help='Hardware ID (auto-detect if omitted)')
    ap.add_argument('--secret', default=SHARED_SECRET, help='Shared secret')
    ap.add_argument('--algo', default=HASH_ALGO, help='Hash algorithm')
    ap.add_argument('--count', type=int, default=1, help='Number of keys')
    ap.add_argument('--validate', help='Validate a key')
    ap.add_argument('--show-hwid', action='store_true', help='Show current machine HWID')
    args = ap.parse_args()

    hwid = args.hwid or get_hwid()

    if args.show_hwid:
        print(f"HWID: {hwid}")
        return

    if args.validate:
        valid = validate_license(args.validate, hwid, args.secret, args.algo)
        print(f"Key  : {args.validate}")
        print(f"HWID : {hwid}")
        print(f"Valid: {valid}")
        return

    print(f"HWID  : {hwid}")
    print(f"Algo  : {args.algo}")
    print(f"Secret: {args.secret[:4]}{'*' * (len(args.secret) - 4)}")
    print()

    for i in range(args.count):
        key = generate_license(hwid, args.secret, args.algo)
        print(f"Key {i+1}: {key}")


if __name__ == '__main__':
    main()
