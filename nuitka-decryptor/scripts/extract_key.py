#!/usr/bin/env python3
"""
extract_key.py — Extract XOR key from Nuitka .pyd via PE section parsing
and known-plaintext attack on a config .encrypted file.

Usage:
    python extract_key.py --pyd config_loader.pyd --config update_config.json.encrypted
    python extract_key.py --pyd config_loader.pyd --config app.conf.encrypted --out key_extraction.txt
    python extract_key.py --pyd config_loader.pyd --key-hint BT_DEV --config cfg.encrypted
"""
import argparse
import base64
import marshal
import re
import struct
import sys
from pathlib import Path


# ── Helpers ────────────────────────────────────────────────────────────────────

def xor_decrypt(payload_b64: str, key: bytes) -> bytes:
    decoded = base64.b64decode(payload_b64)
    kr = (key * (len(decoded) // len(key) + 1))[:len(decoded)]
    return bytes(a ^ b for a, b in zip(decoded, kr))


def try_key(key: bytes, config_b64: str, results: list) -> bool:
    """Try a candidate key, return True if it produces valid JSON / plaintext."""
    try:
        plain = xor_decrypt(config_b64, key)
        text = plain.decode('utf-8', errors='replace')
        if text.strip().startswith('{') or text.strip().startswith('['):
            try:
                import json; json.loads(text)
                results.append(f"  ✅ VALID JSON with key: {key!r}")
            except Exception:
                results.append(f"  ⚠️  Starts with {{ but not valid JSON — key: {key!r}")
            results.append(f"     Preview: {text[:200]}")
            return True
        printable = sum(32 <= b < 127 for b in plain) / len(plain)
        if printable > 0.85:
            results.append(f"  ✅ High printable ({printable:.0%}) with key: {key!r}")
            results.append(f"     Preview: {text[:200]}")
            return True
    except Exception:
        pass
    return False


def known_plaintext_attack(config_b64: str, max_key_len: int = 32) -> bytes | None:
    """
    Recover key bytes one-by-one using known JSON plaintext.
    JSON always starts with: { \n SPACE SPACE " ...
    """
    decoded = base64.b64decode(config_b64)
    # Candidate first bytes of plaintext
    candidates = [
        b'{\n  "', b'{\n    "', b'{\n"', b'{ "', b'{"',
    ]
    for prefix in candidates:
        key_bytes = bytearray()
        for i, pb in enumerate(prefix):
            if i >= len(decoded):
                break
            key_bytes.append(decoded[i] ^ pb)
        if key_bytes:
            # Try to extend using repeating pattern
            for rep_len in range(1, len(key_bytes) + 1):
                pattern = bytes(key_bytes[:rep_len])
                if try_key(pattern, config_b64, []):
                    return pattern
    return None


def pe_sections(data: bytes) -> dict:
    """Parse PE section table, return dict name → (offset, size)."""
    try:
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        num_sec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
        opt_sz = struct.unpack_from('<H', data, e_lfanew + 20)[0]
        sec_base = e_lfanew + 24 + opt_sz
        sections = {}
        for i in range(num_sec):
            o = sec_base + i * 40
            name = data[o:o + 8].rstrip(b'\0').decode('ascii', errors='ignore')
            va = struct.unpack_from('<I', data, o + 12)[0]
            sz = struct.unpack_from('<I', data, o + 16)[0]
            raw = struct.unpack_from('<I', data, o + 20)[0]
            sections[name] = (raw, sz, va)
        return sections
    except Exception:
        return {}


def find_keys_in_pe(data: bytes, results: list) -> list[str]:
    """Search PE sections for ASCII key-like strings."""
    found = []
    sections = pe_sections(data)
    results.append(f"\nPE sections: {list(sections.keys())}")

    for sec_name, (raw_off, sz, va) in sections.items():
        chunk = data[raw_off:raw_off + sz]
        results.append(f"\n--- Searching {sec_name} ({sz:,} bytes) ---")

        # Look for ASCII strings that look like keys (8–64 chars, mostly alnum + _-)
        for m in re.finditer(rb'[A-Za-z0-9_\-]{8,64}', chunk):
            s = m.group().decode('ascii')
            ratio = sum(c.isalnum() or c in '_-' for c in s) / len(s)
            if ratio > 0.85 and not s.startswith('Py') and not s.startswith('__'):
                found.append(s)
                results.append(f"  0x{m.start():06x}: {s}")

        # Try marshal on .rsrc chunk
        if sec_name == '.rsrc':
            for start in range(0, min(len(chunk), 4096)):
                try:
                    obj = marshal.loads(chunk[start:])
                    results.append(f"\n  !!! Marshal object at rsrc+{start} !!!")
                    results.append(f"      Type: {type(obj).__name__}")
                    results.append(f"      Repr: {repr(obj)[:500]}")
                    if isinstance(obj, (list, tuple, dict)):
                        for v in (obj.values() if isinstance(obj, dict) else obj):
                            if isinstance(v, (str, bytes)) and 4 < len(v) < 64:
                                found.append(str(v))
                    break
                except Exception:
                    pass

    return list(dict.fromkeys(found))  # deduplicate preserving order


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Extract XOR key from Nuitka .pyd")
    ap.add_argument('--pyd', required=True, metavar='FILE', help='.pyd file to analyze')
    ap.add_argument('--config', metavar='FILE', help='.encrypted config file (for known-plaintext)')
    ap.add_argument('--key-hint', metavar='STR', help='Partial key hint (prefix to test)')
    ap.add_argument('--out', default='key_extraction.txt', help='Output log file')
    args = ap.parse_args()

    results = ["Nuitka Key Extraction", "=" * 60]
    confirmed_key = None
    config_b64 = None

    # Load config if provided
    if args.config:
        cfg_path = Path(args.config)
        if not cfg_path.exists():
            print(f"[!] Config not found: {cfg_path}", file=sys.stderr)
        else:
            config_b64 = cfg_path.read_text(encoding='utf-8').strip()
            results.append(f"\nConfig file: {cfg_path} ({len(config_b64)} b64 chars)")

    # Load and parse .pyd
    pyd_path = Path(args.pyd)
    if not pyd_path.exists():
        print(f"[!] .pyd not found: {pyd_path}", file=sys.stderr)
        sys.exit(1)

    data = pyd_path.read_bytes()
    results.append(f"PYD file: {pyd_path.name} ({len(data):,} bytes)")

    # 1. Find key candidates in PE sections
    results.append("\n" + "=" * 60)
    results.append("PHASE 1: PE section key string search")
    candidates = find_keys_in_pe(data, results)
    results.append(f"\nTotal candidate strings: {len(candidates)}")

    # 2. Test candidates against config file
    if config_b64:
        results.append("\n" + "=" * 60)
        results.append("PHASE 2: Test candidates against config file")
        for cand in candidates:
            for key in [cand.encode(), cand.upper().encode(), cand.lower().encode()]:
                if try_key(key, config_b64, results):
                    confirmed_key = key
                    break
            if confirmed_key:
                break

    # 3. Key hint brute-force
    if not confirmed_key and args.key_hint and config_b64:
        results.append("\n" + "=" * 60)
        results.append(f"PHASE 3: Key hint expansion from '{args.key_hint}'")
        hint = args.key_hint.encode()
        if try_key(hint, config_b64, results):
            confirmed_key = hint

    # 4. Known-plaintext attack
    if not confirmed_key and config_b64:
        results.append("\n" + "=" * 60)
        results.append("PHASE 4: Known-plaintext attack (JSON structure)")
        kp_key = known_plaintext_attack(config_b64)
        if kp_key:
            results.append(f"  Known-plaintext recovered key: {kp_key!r}")
            if try_key(kp_key, config_b64, results):
                confirmed_key = kp_key

    # Output
    results.append("\n" + "=" * 60)
    if confirmed_key:
        results.append(f"CONFIRMED KEY: {confirmed_key!r}")
        results.append(f"KEY (string) : {confirmed_key.decode('utf-8', errors='replace')}")
        key_file = Path(args.out).parent / 'key_final.txt'
        key_file.write_text(confirmed_key.decode('utf-8', errors='replace'), encoding='utf-8')
        results.append(f"Key saved to : {key_file}")
    else:
        results.append("KEY NOT CONFIRMED — review candidate strings above")
        results.append("Try running with --key-hint <partial_key>")

    Path(args.out).write_text('\n'.join(results), encoding='utf-8')
    print(f"[+] Extraction log: {args.out}")
    if confirmed_key:
        print(f"[+] KEY FOUND: {confirmed_key!r}")
    else:
        print("[!] Key not confirmed automatically — check output log")


if __name__ == '__main__':
    main()
