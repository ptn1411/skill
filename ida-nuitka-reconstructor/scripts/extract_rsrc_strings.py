#!/usr/bin/env python3
"""
extract_rsrc_strings.py — Extract all string constants from Nuitka PE .rsrc/.rdata sections.

Nuitka compiles Python to C but serializes all string constants (literals, attribute
names, module names, URLs, HTML/JS templates) into the PE .rsrc section. IDA Pro does
NOT map this section, so standard string searches fail. This script reads raw PE bytes
and extracts + categorizes everything.

Usage:
    python extract_rsrc_strings.py --binary target.dll --out strings.json
    python extract_rsrc_strings.py --binary target.dll --sections rsrc,rdata --out strings.json
    python extract_rsrc_strings.py --binary target.dll --ida-analysis ida.json --out strings.json
"""

import argparse
import json
import re
import struct
import sys
from pathlib import Path


# ── PE Parsing ────────────────────────────────────────────────────────────────

def parse_pe_sections(data: bytes) -> dict:
    """Parse PE section table → {name: (raw_offset, raw_size, virtual_addr, virtual_size)}"""
    if data[:2] != b'MZ':
        raise ValueError("Not a valid PE file (missing MZ header)")

    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        raise ValueError("Invalid PE signature")

    num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt_header_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    section_base = e_lfanew + 24 + opt_header_size

    sections = {}
    for i in range(num_sections):
        off = section_base + i * 40
        name = data[off:off + 8].rstrip(b'\x00').decode('ascii', errors='ignore')
        virt_size = struct.unpack_from('<I', data, off + 8)[0]
        virt_addr = struct.unpack_from('<I', data, off + 12)[0]
        raw_size = struct.unpack_from('<I', data, off + 16)[0]
        raw_offset = struct.unpack_from('<I', data, off + 20)[0]
        sections[name] = {
            'raw_offset': raw_offset,
            'raw_size': raw_size,
            'virtual_addr': virt_addr,
            'virtual_size': virt_size,
        }
    return sections


def get_pe_info(data: bytes) -> dict:
    """Extract basic PE metadata."""
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    machine = struct.unpack_from('<H', data, e_lfanew + 4)[0]
    machines = {0x14c: 'x86', 0x8664: 'x86_64', 0xAA64: 'ARM64'}
    opt_magic = struct.unpack_from('<H', data, e_lfanew + 24)[0]
    return {
        'machine': machines.get(machine, f'unknown(0x{machine:x})'),
        'pe_type': 'PE32+' if opt_magic == 0x20b else 'PE32',
        'num_sections': struct.unpack_from('<H', data, e_lfanew + 6)[0],
    }


# ── Nuitka Constant Extraction ───────────────────────────────────────────────

def extract_nuitka_constants(section_bytes: bytes) -> list[dict]:
    """
    Parse Nuitka serialized constants from raw section bytes.

    Nuitka serialization format:
    - 'u' + length(1-4 bytes) + UTF-8 data → unicode string literal
    - 'a' + length(1-4 bytes) + ASCII data → attribute/identifier name
    - 's' → string reference (backreference)
    - 'w' → variable reference
    - Strings appear in source-code order
    """
    constants = []
    i = 0
    n = len(section_bytes)

    while i < n - 2:
        prefix = section_bytes[i:i + 1]

        if prefix in (b'u', b'a'):
            kind = 'unicode' if prefix == b'u' else 'attribute'
            i += 1
            if i >= n:
                break

            length = section_bytes[i]
            i += 1

            if length >= 0x80:
                if i >= n:
                    break
                length = ((length & 0x7F) << 8) | section_bytes[i]
                i += 1

            if length > 0 and length < 10000 and i + length <= n:
                try:
                    s = section_bytes[i:i + length].decode('utf-8', errors='strict')
                    if s.isprintable() or '\n' in s or '\t' in s:
                        constants.append({
                            'type': kind,
                            'value': s,
                            'offset': i - 2,
                            'length': length,
                        })
                except UnicodeDecodeError:
                    pass
                i += length
            else:
                continue
        else:
            i += 1

    return constants


def extract_raw_strings(section_bytes: bytes, min_len: int = 4) -> list[dict]:
    """Fallback: extract all printable strings via regex."""
    strings = []
    for m in re.finditer(rb'[\x20-\x7e\t\n\r]{' + str(min_len).encode() + rb',}', section_bytes):
        try:
            s = m.group().decode('utf-8')
            strings.append({
                'type': 'raw',
                'value': s,
                'offset': m.start(),
                'length': len(m.group()),
            })
        except UnicodeDecodeError:
            pass

    for m in re.finditer(rb'(?:[\x20-\x7e\t\n\r]\x00){' + str(min_len).encode() + rb',}',
                         section_bytes):
        try:
            s = m.group().decode('utf-16-le').strip('\x00')
            if len(s) >= min_len:
                strings.append({
                    'type': 'raw_utf16',
                    'value': s,
                    'offset': m.start(),
                    'length': len(m.group()),
                })
        except (UnicodeDecodeError, ValueError):
            pass

    return strings


# ── Categorization ────────────────────────────────────────────────────────────

IMPORT_PATTERNS = re.compile(
    r'^(tkinter|ttk|os|sys|json|threading|datetime|urllib|http|queue|pathlib|'
    r'subprocess|socket|ssl|hashlib|base64|struct|re|io|time|logging|'
    r'asyncio|aiohttp|requests|playwright|pyotp|cryptography|flask|django|'
    r'fastapi|selenium|beautifulsoup4|bs4|lxml|pandas|numpy|PIL|cv2|'
    r'win32api|win32com|pyautogui|pynput|ctypes|winreg|'
    r'collections|functools|itertools|typing|dataclasses|abc|enum|'
    r'multiprocessing|concurrent|signal|shutil|glob|tempfile|'
    r'csv|sqlite3|xml|html|email|smtplib|ftplib|telnetlib|'
    r'argparse|configparser|getpass|platform|uuid)$'
)

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+|localhost:\d+|/api/\w+')
HTML_JS_PATTERN = re.compile(
    r'<[a-zA-Z][^>]*>|document\.|window\.|function\s*\(|'
    r'querySelector|getElementById|addEventListener|\.click\(\)|'
    r'var |let |const |=>\s*\{|\.then\('
)
FORMAT_STR_PATTERN = re.compile(r'\{[\w.]*\}|%[sdifr]|f".*\{')

NUITKA_SKIP = {
    '__compiled__', '__loader__', '__spec__', '__file__', '__cached__',
    '__builtins__', '__doc__', '__name__', '__package__', '__path__',
    'builtins', 'None', 'True', 'False', 'NotImplemented', 'Ellipsis',
}


def categorize_strings(all_strings: list[dict]) -> dict:
    """Categorize extracted strings by purpose."""
    categories = {
        'imports': [],
        'functions': [],
        'classes': [],
        'urls': [],
        'html_js': [],
        'format_strings': [],
        'error_messages': [],
        'constants': [],
        'nuitka_internal': [],
    }

    seen = set()
    for entry in all_strings:
        val = entry['value'].strip()
        if not val or val in seen or val in NUITKA_SKIP:
            continue
        seen.add(val)

        if val.startswith('Nuitka') or val.startswith('__nuitka') or val.startswith('$module'):
            categories['nuitka_internal'].append(entry)
        elif IMPORT_PATTERNS.match(val):
            categories['imports'].append(entry)
        elif URL_PATTERN.search(val):
            categories['urls'].append(entry)
        elif HTML_JS_PATTERN.search(val) and len(val) > 20:
            categories['html_js'].append(entry)
        elif FORMAT_STR_PATTERN.search(val):
            categories['format_strings'].append(entry)
        elif val[0].isupper() and val.isidentifier() and not val.startswith('Py'):
            categories['classes'].append(entry)
        elif val.isidentifier() and val[0].islower():
            categories['functions'].append(entry)
        elif any(kw in val.lower() for kw in ['error', 'exception', 'failed', 'invalid', 'cannot']):
            categories['error_messages'].append(entry)
        elif len(val) >= 4:
            categories['constants'].append(entry)

    return categories


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Extract string constants from Nuitka PE .rsrc/.rdata sections"
    )
    ap.add_argument('--binary', required=True, help='Target PE file (.dll/.exe/.pyd)')
    ap.add_argument('--sections', default='rsrc,rdata',
                    help='Comma-separated PE sections to scan (default: rsrc,rdata)')
    ap.add_argument('--ida-analysis', help='Optional IDA analysis JSON for cross-referencing')
    ap.add_argument('--min-len', type=int, default=4, help='Minimum string length (default: 4)')
    ap.add_argument('--out', default='extracted_strings.json', help='Output JSON file')
    ap.add_argument('--dump-raw', help='Also dump raw strings to this text file')
    args = ap.parse_args()

    binary_path = Path(args.binary)
    if not binary_path.exists():
        print(f"[!] File not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Reading {binary_path.name} ({binary_path.stat().st_size:,} bytes)")
    data = binary_path.read_bytes()

    pe_info = get_pe_info(data)
    sections = parse_pe_sections(data)
    print(f"[*] PE type: {pe_info['pe_type']} ({pe_info['machine']})")
    print(f"[*] Sections: {list(sections.keys())}")

    target_sections = [s.strip('.').strip() for s in args.sections.split(',')]
    all_strings = []
    section_stats = {}

    for sec_name, sec_info in sections.items():
        clean_name = sec_name.strip('.')
        if clean_name not in target_sections:
            continue

        raw_off = sec_info['raw_offset']
        raw_sz = sec_info['raw_size']
        section_bytes = data[raw_off:raw_off + raw_sz]

        print(f"\n[*] Scanning {sec_name}: offset=0x{raw_off:X}, size={raw_sz:,} bytes")

        nuitka_consts = extract_nuitka_constants(section_bytes)
        raw_strs = extract_raw_strings(section_bytes, args.min_len)

        nuitka_offsets = {c['offset'] for c in nuitka_consts}
        for rs in raw_strs:
            if rs['offset'] not in nuitka_offsets:
                all_strings.append({**rs, 'section': sec_name})

        for nc in nuitka_consts:
            all_strings.append({**nc, 'section': sec_name})

        section_stats[sec_name] = {
            'size': raw_sz,
            'nuitka_constants': len(nuitka_consts),
            'raw_strings': len(raw_strs),
        }
        print(f"    Nuitka constants: {len(nuitka_consts)}")
        print(f"    Raw strings: {len(raw_strs)}")

    categories = categorize_strings(all_strings)

    result = {
        'binary': binary_path.name,
        'binary_size': len(data),
        'pe_info': pe_info,
        'sections': {k: v for k, v in sections.items()},
        'scan_stats': section_stats,
        'categories': {k: v for k, v in categories.items()},
        'category_counts': {k: len(v) for k, v in categories.items()},
        'total_strings': sum(len(v) for v in categories.values()),
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"\n[+] Output: {out_path}")
    print(f"[+] Total unique strings: {result['total_strings']}")
    for cat, count in result['category_counts'].items():
        if count > 0:
            print(f"    {cat}: {count}")

    if args.dump_raw:
        raw_path = Path(args.dump_raw)
        lines = []
        for cat_name, entries in categories.items():
            if not entries:
                continue
            lines.append(f"\n{'='*60}")
            lines.append(f"  {cat_name.upper()} ({len(entries)} strings)")
            lines.append(f"{'='*60}")
            for e in entries:
                val_preview = e['value'][:200].replace('\n', '\\n')
                lines.append(f"  [{e.get('section','?')}+0x{e['offset']:06X}] {val_preview}")
        raw_path.write_text('\n'.join(lines), encoding='utf-8')
        print(f"[+] Raw dump: {raw_path}")

    # Quick highlights
    if categories['urls']:
        print(f"\n[!] Found {len(categories['urls'])} URLs:")
        for u in categories['urls'][:10]:
            print(f"    {u['value'][:120]}")
    if categories['imports']:
        print(f"\n[!] Found {len(categories['imports'])} import modules:")
        mods = sorted(set(e['value'] for e in categories['imports']))
        print(f"    {', '.join(mods[:30])}")


if __name__ == '__main__':
    main()
