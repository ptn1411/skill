#!/usr/bin/env python3
"""
extract_keygen_data.py — Specialized tool to extract data needed for keygen development.
Targets: HWID patterns, hashing constants, and license-related strings in Nuitka binaries.

Usage:
    python extract_keygen_data.py --pyd main_app.pyd
    python extract_keygen_data.py --pyd main_app.pyd --out keygen_info.txt
"""
import argparse
import re
import struct
import sys
import hashlib
from pathlib import Path

# Common strings used in license/keygen logic
LICENSE_KEYWORDS = [
    'license', 'activate', 'activation', 'serial', 'keygen', 'registration',
    'hwid', 'machine_id', 'machineguid', 'uuid', 'mac_address', 'hardware_id',
    'trial', 'expired', 'subscription', 'auth_token', 'signature'
]

# Common hashing/encryption constants
HASH_CONSTANTS = {
    'MD5_Padding': b'\x80' + b'\x00' * 63,
    'SHA1_Constants': [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
    'SHA256_Constants': [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
}

# Patterns for identifying HWID retrieval in Python scripts (compiled by Nuitka)
HWID_PATTERNS = [
    rb'wmic\s+csproduct\s+get\s+uuid',
    rb'wmic\s+diskdrive\s+get\s+serialnumber',
    rb'wmic\s+baseboard\s+get\s+serialnumber',
    rb'Software\\Microsoft\\Cryptography', # MachineGuid location
    rb'MachineGuid',
    rb'getnode', # uuid.getnode()
    rb'get_mac',
]

def find_patterns(data, patterns, results, label):
    results.append(f"\n--- Searching for {label} ---")
    found_count = 0
    for pat in patterns:
        for m in re.finditer(re.escape(pat) if isinstance(pat, bytes) else pat, data):
            results.append(f"  [+] Found '{pat.decode() if isinstance(pat, bytes) else pat}' at 0x{m.start():08x}")
            found_count += 1
    if found_count == 0:
        results.append(f"  [-] No {label} patterns found.")

def find_license_strings(data, results):
    results.append("\n--- License-related Strings ---")
    found_strings = []
    # Search for ASCII strings
    for m in re.finditer(rb'[\x20-\x7e]{4,}', data):
        s = m.group().decode('ascii', errors='ignore')
        if any(kw in s.lower() for kw in LICENSE_KEYWORDS):
            results.append(f"  0x{m.start():08x}: {s}")
            found_strings.append(s)
    
    # Search for UTF-16 strings (common in Windows binaries)
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}', data):
        try:
            s = m.group().decode('utf-16le')
            if any(kw in s.lower() for kw in LICENSE_KEYWORDS):
                results.append(f"  0x{m.start():08x} (UTF-16): {s}")
                found_strings.append(s)
        except:
            pass
    
    if not found_strings:
        results.append("  [-] No license-related strings found.")

def find_hash_constants(data, results):
    results.append("\n--- Hashing Algorithm Constants ---")
    
    # Check for SHA256 initialization constants (Little Endian)
    sha256_bytes = b"".join(struct.pack("<I", c) for c in HASH_CONSTANTS['SHA256_Constants'])
    idx = data.find(sha256_bytes)
    if idx != -1:
        results.append(f"  [!] Found SHA256 initialization constants at 0x{idx:08x}")
    
    # Check for MD5 constants (roughly, search for 0x67452301)
    md5_init = struct.pack("<I", 0x67452301)
    for m in re.finditer(re.escape(md5_init), data):
        # Verify if next few are standard MD5/SHA1 init
        if data[m.start():m.start()+16] == b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10':
             results.append(f"  [!] Found MD5/SHA1 standard IV at 0x{m.start():08x}")

def main():
    ap = argparse.ArgumentParser(description="Extract keygen-related data from Nuitka .pyd")
    ap.add_argument('--pyd', required=True, help='.pyd file to analyze')
    ap.add_argument('--out', default='keygen_extraction.txt', help='Output results file')
    args = ap.parse_args()

    pyd_path = Path(args.pyd)
    if not pyd_path.exists():
        print(f"Error: {pyd_path} not found.")
        sys.exit(1)

    data = pyd_path.read_bytes()
    results = [
        "Keygen Data Extraction Report",
        "=" * 40,
        f"File: {pyd_path.name}",
        f"Size: {len(data)} bytes",
        "=" * 40
    ]

    find_license_strings(data, results)
    find_patterns(data, HWID_PATTERNS, results, "HWID/System ID Patterns")
    find_hash_constants(data, results)

    # Search for potential "Secret Salts" or "Master Keys"
    # Long, high-entropy strings near license keywords
    results.append("\n--- Potential Secret Salts / Master Keys ---")
    for m in re.finditer(rb'[\x21-\x7e]{16,64}', data):
        s = m.group().decode('ascii', errors='ignore')
        # Filter out common stuff
        if not any(x in s for x in ['Py_', 'Nuitka', 'Error', 'Exception', 'http']):
            # Check entropy (simplified)
            if len(set(s)) > len(s) * 0.7:
                results.append(f"  0x{m.start():08x}: {s}")

    Path(args.out).write_text('\n'.join(results), encoding='utf-8')
    print(f"[+] Keygen data extraction complete. Results saved to: {args.out}")

if __name__ == "__main__":
    main()
