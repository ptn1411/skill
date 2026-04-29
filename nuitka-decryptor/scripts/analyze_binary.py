#!/usr/bin/env python3
"""
analyze_binary.py — Deep binary analysis of Nuitka .pyd files
Surfaces key candidates: printable strings, high-entropy byte sequences,
base64-like strings, Nuitka function name patterns.

Usage:
    python analyze_binary.py --pyd config_loader.pyd
    python analyze_binary.py --pyd config_loader.pyd --out analysis.txt
    python analyze_binary.py --pyd a.pyd --pyd b.pyd --out analysis.txt
"""
import argparse
import re
import struct
import sys
from pathlib import Path


INTERESTING_KW = [
    'key', 'secret', 'encrypt', 'decrypt', 'cipher',
    'pass', 'token', 'salt', 'iv', 'nonce', 'aes', 'xor',
    'config', 'load', 'read', 'parse', 'json', 'open', 'file',
    'base64', 'b64', 'decode', 'encode', 'manifest',
]

SKIP_KW = [
    'PyObject', 'PyDict', 'PyErr', 'PyUnicode', 'PyBytes', 'PyList',
    'PyTuple', 'PyFloat', 'PyLong', 'PyModule', 'PyType', 'PyMethod',
    'compiled_', 'PyImport', 'PyEval', 'PyNumber', 'PySequence',
    'PyCallable', 'PyMapping', 'PyFrame', 'PADDING', 'VirtualProtect',
    'boolean indicating', 'positional argument', 'object is not',
    'object has no', 'must be', 'cannot', 'coroutine', 'generator',
    'Nuitka', 'exception', 'function', 'method', 'attribute',
    'GCC:', 'runtime failure', 'DllMain', '.dll',
]

FUNC_PATTERNS = [
    b'uload_encrypted', b'udecrypt', b'uencrypt', b'uread_config',
    b'uload_config', b'uparse_config', b'uget_key', b'uread_encrypted',
    b'udecode_source', b'uload_source', b'uimport_encrypted',
    b'uexec_encrypted', b'uload_module', b'uget_encryption_key',
    b'ub64decode', b'ub64encode', b'uxor', b'uimport_module',
    b'usource_loader', b'aload_encrypted', b'adecrypt',
    b'aread_config', b'aload_config', b'aget_key',
]


def analyze(filepath: Path, results: list):
    data = filepath.read_bytes()
    bn = filepath.name
    results += [f"\n{'='*60}", f"Analyzing: {bn} ({len(data):,} bytes)", f"{'='*60}"]

    # 1. Interesting printable strings
    results.append("\n--- Strings containing key/encrypt/decode keywords ---")
    for m in re.finditer(rb'[\x20-\x7e]{4,}', data):
        s = m.group().decode('ascii')
        if any(kw in s.lower() for kw in INTERESTING_KW):
            results.append(f"  0x{m.start():08x}: {s}")

    # 2. High-entropy 16/32-byte candidates
    results.append("\n--- Potential key-sized constants (16 or 32 bytes) ---")
    for key_len in [16, 32]:
        for i in range(len(data) - key_len):
            if i > 0 and data[i - 1] == 0 and (i + key_len >= len(data) or data[i + key_len] == 0):
                candidate = data[i:i + key_len]
                if len(set(candidate)) >= key_len * 0.6 and all(b != 0 for b in candidate):
                    results.append(f"  0x{i:08x} ({key_len}B): {candidate.hex()}  {repr(candidate)}")

    # 3. Base64-like strings
    results.append("\n--- Base64-like strings (20–100 chars) ---")
    for m in re.finditer(rb'[A-Za-z0-9+/=]{20,100}', data):
        results.append(f"  0x{m.start():08x}: {m.group().decode('ascii')}")

    # 4. Nuitka function name patterns
    results.append("\n--- Nuitka function-related patterns ---")
    for pat in FUNC_PATTERNS:
        positions = [m.start() for m in re.finditer(re.escape(pat), data)]
        if positions:
            results.append(f"  '{pat.decode()}' at: {[hex(o) for o in positions]}")

    # 5. Long ASCII strings (potential embedded keys, skip boilerplate)
    results.append("\n--- Long ASCII strings (32–200 chars, filtered) ---")
    for m in re.finditer(rb'[\x20-\x7e]{32,200}', data):
        s = m.group().decode('ascii')
        if not any(sk in s for sk in SKIP_KW):
            results.append(f"  0x{m.start():08x}: {s[:120]}")

    # 6. PE resource section strings
    results.append("\n--- Strings in .rsrc section ---")
    try:
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
        sec_off = e_lfanew + 24 + opt_size
        for i in range(num_sections):
            so = sec_off + i * 40
            name = data[so:so + 8].rstrip(b'\0').decode('ascii', errors='ignore')
            if name == '.rsrc':
                r_off = struct.unpack_from('<I', data, so + 20)[0]
                r_sz = struct.unpack_from('<I', data, so + 16)[0]
                rsrc = data[r_off:r_off + r_sz]
                for m in re.finditer(rb'[\x20-\x7e]{8,}', rsrc):
                    results.append(f"  0x{m.start():04x}: {m.group().decode('ascii')[:100]}")
                break
    except Exception as e:
        results.append(f"  (PE parse error: {e})")


def main():
    ap = argparse.ArgumentParser(description="Analyze Nuitka .pyd for embedded keys")
    ap.add_argument('--pyd', required=True, action='append', metavar='FILE',
                    help='.pyd file to analyze (repeat for multiple)')
    ap.add_argument('--out', default='binary_analysis.txt',
                    help='Output file (default: binary_analysis.txt)')
    args = ap.parse_args()

    results = ["Nuitka Binary Analysis", "=" * 60]
    for pyd_path in args.pyd:
        p = Path(pyd_path)
        if not p.exists():
            print(f"[!] Not found: {p}", file=sys.stderr)
            continue
        analyze(p, results)

    out = Path(args.out)
    out.write_text('\n'.join(results), encoding='utf-8')
    print(f"[+] Analysis written to: {out}")
    print(f"    Lines: {len(results)}")

    # Quick summary to stdout
    key_hits = [r for r in results if any(kw in r.lower() for kw in ['key', 'secret', 'token', 'encrypt'])]
    if key_hits:
        print(f"\n[!] {len(key_hits)} potential key-related strings found:")
        for h in key_hits[:10]:
            print(f"    {h.strip()}")


if __name__ == '__main__':
    main()
