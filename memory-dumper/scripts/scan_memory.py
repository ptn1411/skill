#!/usr/bin/env python3
"""
scan_memory.py — Scan memory dump for secrets, keys, tokens, and strings.

Extracts printable strings (UTF-8 + UTF-16LE), identifies license keys,
API tokens, crypto key candidates (entropy analysis), and URLs.
Optional cross-reference with known strings from static analysis.

Usage:
    python scan_memory.py dumps/target.dmp --out analysis/
    python scan_memory.py dumps/target.dmp --min-entropy 4.5 --key-size 16,32
    python scan_memory.py dumps/target.dmp --cross-ref nuitka_strings.txt --out xref/
"""

import argparse
import json
import math
import re
import struct
import sys
from collections import Counter
from pathlib import Path

CHUNK_SIZE = 64 * 1024 * 1024  # 64MB chunks for large dumps


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in counts.values() if c > 0
    )


def extract_strings_utf8(data: bytes, min_len: int = 6) -> list[tuple[int, str]]:
    """Extract printable ASCII/UTF-8 strings."""
    pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
    results = []
    for m in pattern.finditer(data):
        try:
            s = m.group().decode('utf-8', errors='ignore')
            results.append((m.start(), s))
        except Exception:
            continue
    return results


def extract_strings_utf16(data: bytes, min_len: int = 6) -> list[tuple[int, str]]:
    """Extract UTF-16LE strings (common in Windows processes)."""
    pattern = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % min_len)
    results = []
    for m in pattern.finditer(data):
        try:
            s = m.group().decode('utf-16-le', errors='ignore')
            if s.strip():
                results.append((m.start(), s))
        except Exception:
            continue
    return results


LICENSE_PATTERNS = [
    # XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
    (re.compile(r'[A-Z0-9]{5}(?:-[A-Z0-9]{5}){3,}'), 'serial-key'),
    # Base64 license blobs (40+ chars)
    (re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'), 'base64-blob'),
    # UUID format
    (re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I), 'uuid'),
    # Hex license keys (32+ chars)
    (re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{32,64}(?![0-9a-fA-F])'), 'hex-key'),
]

TOKEN_PATTERNS = [
    (re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*'), 'bearer-token'),
    (re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+'), 'jwt'),
    (re.compile(r'(?:sk|pk|api|key)[-_][A-Za-z0-9]{20,}'), 'api-key'),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), 'github-pat'),
    (re.compile(r'xox[bpras]-[A-Za-z0-9\-]+'), 'slack-token'),
    (re.compile(r'AKIA[A-Z0-9]{16}'), 'aws-access-key'),
]

URL_PATTERN = re.compile(r'https?://[^\s<>"\'`\x00-\x1f]{8,200}')

CRYPTO_CONSTANTS = {
    b'\x63\x7c\x77\x7b': 'AES S-box',
    b'\xd7\x6a\xa4\x78': 'SHA-256 init',
    b'\x01\x23\x45\x67': 'MD5 init',
    b'\x52\x09\x06\xa8': 'SHA-512 init (first 4 bytes of H0)',
}


def find_license_keys(strings: list[tuple[int, str]]) -> list[dict]:
    """Find license key patterns in extracted strings."""
    keys = []
    seen = set()
    for offset, s in strings:
        for pattern, key_type in LICENSE_PATTERNS:
            for m in pattern.finditer(s):
                val = m.group()
                if val not in seen and len(val) >= 15:
                    seen.add(val)
                    keys.append({
                        'offset': offset + m.start(),
                        'type': key_type,
                        'value': val[:200],
                        'context': s[max(0, m.start()-20):m.end()+20][:100],
                    })
    return keys


def find_tokens(strings: list[tuple[int, str]]) -> list[dict]:
    """Find API tokens and auth credentials."""
    tokens = []
    seen = set()
    for offset, s in strings:
        for pattern, token_type in TOKEN_PATTERNS:
            for m in pattern.finditer(s):
                val = m.group()
                if val not in seen:
                    seen.add(val)
                    tokens.append({
                        'offset': offset + m.start(),
                        'type': token_type,
                        'value': val[:200],
                    })
    return tokens


def find_urls(strings: list[tuple[int, str]]) -> list[dict]:
    """Find HTTP(S) URLs."""
    urls = []
    seen = set()
    for offset, s in strings:
        for m in URL_PATTERN.finditer(s):
            url = m.group().rstrip('.,;:)]}')
            if url not in seen:
                seen.add(url)
                urls.append({
                    'offset': offset + m.start(),
                    'url': url,
                })
    return urls


def find_crypto_keys(data: bytes, key_sizes: list[int], min_entropy: float) -> list[dict]:
    """Find high-entropy blocks that could be crypto keys."""
    candidates = []

    # Check for known crypto constants
    for marker, name in CRYPTO_CONSTANTS.items():
        pos = 0
        while True:
            pos = data.find(marker, pos)
            if pos == -1:
                break
            candidates.append({
                'offset': pos,
                'type': 'crypto-constant',
                'name': name,
                'entropy': shannon_entropy(data[pos:pos+16]),
                'hex_preview': data[pos:pos+32].hex(),
            })
            pos += 1

    # Scan for high-entropy blocks at aligned offsets
    for key_size in key_sizes:
        step = 16
        for offset in range(0, len(data) - key_size, step):
            block = data[offset:offset + key_size]
            ent = shannon_entropy(block)
            if ent >= min_entropy:
                # Check it's not just ASCII text
                printable = sum(1 for b in block if 0x20 <= b <= 0x7e)
                if printable / key_size < 0.8:
                    candidates.append({
                        'offset': offset,
                        'type': f'key-candidate-{key_size*8}bit',
                        'entropy': round(ent, 3),
                        'hex_preview': block[:32].hex() + ('...' if key_size > 32 else ''),
                    })

    # Deduplicate overlapping candidates
    candidates.sort(key=lambda x: x['offset'])
    deduped = []
    last_end = -1
    for c in candidates:
        if c['offset'] > last_end or c['type'] == 'crypto-constant':
            deduped.append(c)
            size = next((ks for ks in key_sizes if str(ks*8) in c.get('type', '')), 16)
            last_end = c['offset'] + size

    return deduped[:500]


def cross_reference(memory_strings: list[tuple[int, str]], ref_path: Path) -> list[dict]:
    """Cross-reference memory strings with known strings from static analysis."""
    ref_strings = set()
    for line in ref_path.read_text(encoding='utf-8', errors='ignore').splitlines():
        line = line.strip()
        if len(line) >= 4:
            ref_strings.add(line)

    matches = []
    seen = set()
    for offset, s in memory_strings:
        for ref in ref_strings:
            if ref in s and ref not in seen:
                seen.add(ref)
                matches.append({
                    'offset': offset,
                    'matched_ref': ref[:200],
                    'memory_context': s[:200],
                })
                break
    return matches


def scan_dump(dump_path: Path, key_sizes: list[int], min_entropy: float,
              cross_ref_path: Path | None = None) -> dict:
    """Full scan of a memory dump file."""
    file_size = dump_path.stat().st_size
    print(f"[*] Scanning: {dump_path.name} ({file_size / (1024*1024):.1f} MB)")

    all_strings_utf8 = []
    all_strings_utf16 = []
    all_crypto = []

    offset = 0
    chunk_num = 0
    with open(dump_path, 'rb') as f:
        while True:
            data = f.read(CHUNK_SIZE)
            if not data:
                break
            chunk_num += 1
            print(f"[*] Chunk {chunk_num} ({len(data) / (1024*1024):.0f} MB)...")

            utf8 = extract_strings_utf8(data)
            all_strings_utf8.extend((off + offset, s) for off, s in utf8)

            utf16 = extract_strings_utf16(data)
            all_strings_utf16.extend((off + offset, s) for off, s in utf16)

            crypto = find_crypto_keys(data, key_sizes, min_entropy)
            for c in crypto:
                c['offset'] += offset
            all_crypto.extend(crypto)

            offset += len(data)

    print(f"[*] Strings: {len(all_strings_utf8)} UTF-8, {len(all_strings_utf16)} UTF-16")

    all_strings = all_strings_utf8 + all_strings_utf16

    print("[*] Finding license keys...")
    license_keys = find_license_keys(all_strings)

    print("[*] Finding tokens...")
    tokens = find_tokens(all_strings)

    print("[*] Finding URLs...")
    urls = find_urls(all_strings)

    xref_matches = []
    if cross_ref_path and cross_ref_path.exists():
        print(f"[*] Cross-referencing with {cross_ref_path.name}...")
        xref_matches = cross_reference(all_strings, cross_ref_path)

    return {
        'dump_file': str(dump_path),
        'dump_size': file_size,
        'strings_utf8': len(all_strings_utf8),
        'strings_utf16': len(all_strings_utf16),
        'license_keys': license_keys,
        'tokens': tokens,
        'urls': urls,
        'crypto_candidates': all_crypto[:200],
        'cross_ref_matches': xref_matches,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan memory dump for secrets and keys")
    ap.add_argument('dump_file', help='Memory dump file to scan')
    ap.add_argument('--out', default='memory-analysis', help='Output directory')
    ap.add_argument('--min-entropy', type=float, default=4.5,
                    help='Min Shannon entropy for key candidates (default: 4.5)')
    ap.add_argument('--key-size', default='16,32',
                    help='Expected key sizes in bytes, comma-separated (default: 16,32)')
    ap.add_argument('--cross-ref', help='Cross-reference with known strings file')
    ap.add_argument('--json', action='store_true', help='JSON output only')
    args = ap.parse_args()

    dump_path = Path(args.dump_file)
    if not dump_path.exists():
        print(f"[!] Not found: {dump_path}", file=sys.stderr)
        return 1

    key_sizes = [int(x) for x in args.key_size.split(',')]
    cross_ref = Path(args.cross_ref) if args.cross_ref else None

    results = scan_dump(dump_path, key_sizes, args.min_entropy, cross_ref)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / 'scan_results.json').write_text(
        json.dumps(results, indent=2, ensure_ascii=False, default=str),
        encoding='utf-8',
    )

    if not args.json:
        print(f"\n[+] Memory scan complete:")
        print(f"    Dump size       : {results['dump_size'] / (1024*1024):.1f} MB")
        print(f"    Strings (UTF-8) : {results['strings_utf8']}")
        print(f"    Strings (UTF-16): {results['strings_utf16']}")
        print(f"    License keys    : {len(results['license_keys'])}")
        print(f"    API tokens      : {len(results['tokens'])}")
        print(f"    Crypto candidates: {len(results['crypto_candidates'])}")
        print(f"    URLs            : {len(results['urls'])}")
        if cross_ref:
            print(f"    Cross-ref hits  : {len(results['cross_ref_matches'])}")
        print(f"    Report: {out_dir / 'scan_results.json'}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
