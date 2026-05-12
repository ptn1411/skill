#!/usr/bin/env python3
"""
unpack_pyinstaller.py — Extract .pyc files from PyInstaller bundles.

Supports onefile and onedir modes. Uses pyinstxtractor-ng when available,
falls back to built-in CArchive parser. Auto-detects Python version and
fixes stripped .pyc headers.

Usage:
    python unpack_pyinstaller.py target.exe --out unpacked/
    python unpack_pyinstaller.py target.exe --detect-only
    python unpack_pyinstaller.py target_dir/ --out unpacked/
"""

import argparse
import json
import struct
import sys
import zlib
from pathlib import Path

# PyInstaller CArchive magic (at end of file)
MEI_MAGIC = b'MEI\x0c\x0b\x0a\x0b\x0e'

# .pyc magic numbers per Python version
PYC_MAGIC = {
    (3, 6):  b'\x33\x0D\x0D\x0A',
    (3, 7):  b'\x42\x0D\x0D\x0A',
    (3, 8):  b'\x55\x0D\x0D\x0A',
    (3, 9):  b'\x61\x0D\x0D\x0A',
    (3, 10): b'\x6F\x0D\x0D\x0A',
    (3, 11): b'\xA7\x0D\x0D\x0A',
    (3, 12): b'\xCB\x0D\x0D\x0A',
    (3, 13): b'\xF7\x0D\x0D\x0A',
}

# CArchive TOC entry typecodes
TYPECODES = {
    ord('s'): 'SCRIPT',
    ord('m'): 'PYMODULE',
    ord('M'): 'PYPACKAGE',
    ord('b'): 'BINARY',
    ord('z'): 'PYZ',
    ord('Z'): 'ZIPFILE',
    ord('x'): 'DATA',
    ord('o'): 'OPTION',
    ord('d'): 'DEPENDENCY',
    ord('n'): 'SPLASH',
}


def detect_pyinstaller(filepath: Path) -> dict:
    """Detect PyInstaller markers and determine variant."""
    data = filepath.read_bytes()
    result = {
        'is_pyinstaller': False,
        'mode': None,
        'python_version': None,
        'archive_offset': None,
        'file_size': len(data),
    }

    # Check for onedir mode (look for _internal/ subdirectory)
    if filepath.is_dir():
        internal = filepath / '_internal'
        if internal.exists():
            result['is_pyinstaller'] = True
            result['mode'] = 'onedir'
            # Find Python version from DLL
            for dll in filepath.rglob('python3*.dll'):
                name = dll.stem.lower()
                if name.startswith('python3'):
                    ver_str = name.replace('python', '')
                    major = int(ver_str[0])
                    minor = int(ver_str[1:]) if len(ver_str) > 1 else 0
                    result['python_version'] = (major, minor)
                    break
        return result

    # Onefile: search for MEI magic in last 4KB
    tail = data[-4096:]
    mei_pos = tail.rfind(MEI_MAGIC)
    if mei_pos >= 0:
        result['is_pyinstaller'] = True
        result['mode'] = 'onefile'
        # Cookie is 88 bytes before magic (PyInstaller 6.x) or 24 bytes (older)
        abs_mei = len(data) - 4096 + mei_pos
        # Try to parse cookie: magic(8) + pkg_len(4) + toc_offset(4) + toc_len(4) + py_ver(4) + ...
        for cookie_size in [64, 88, 24]:
            cookie_start = abs_mei - cookie_size + 8
            if cookie_start < 0:
                continue
            try:
                cookie = data[cookie_start:abs_mei + 8]
                if len(cookie) >= 24:
                    pkg_len = struct.unpack_from('<I', cookie, 8)[0]
                    toc_off = struct.unpack_from('<I', cookie, 12)[0]
                    toc_len = struct.unpack_from('<I', cookie, 16)[0]
                    py_ver = struct.unpack_from('<I', cookie, 20)[0]
                    if py_ver > 200 and py_ver < 400:
                        result['python_version'] = (py_ver // 100, py_ver % 100)
                        result['archive_offset'] = abs_mei + 8 - pkg_len
                        break
            except Exception:
                continue

    # Fallback: check for PyInstaller strings
    if not result['is_pyinstaller']:
        markers = [b'_MEIPASS', b'pyi_rth_', b'pyiboot', b'PYZ-00.pyz']
        if any(m in data for m in markers):
            result['is_pyinstaller'] = True
            result['mode'] = 'onefile'

    # Detect Python version from embedded python3XX.dll name
    if result['python_version'] is None:
        import re
        m = re.search(rb'python(3\d{1,2})\.dll', data, re.IGNORECASE)
        if m:
            ver_str = m.group(1).decode()
            result['python_version'] = (3, int(ver_str[1:]))

    return result


def parse_toc(data: bytes, toc_offset: int, toc_len: int) -> list[dict]:
    """Parse CArchive Table of Contents."""
    entries = []
    pos = toc_offset
    end = toc_offset + toc_len

    while pos < end:
        try:
            entry_len = struct.unpack_from('<I', data, pos)[0]
            if entry_len < 18 or entry_len > 0x100000:
                break
            compress_type = data[pos + 4]
            data_len = struct.unpack_from('<I', data, pos + 5)[0]
            uncomp_len = struct.unpack_from('<I', data, pos + 9)[0]
            compress_flag = data[pos + 13]
            typecode = data[pos + 14]
            name_bytes = data[pos + 18:pos + entry_len]
            name = name_bytes.split(b'\x00')[0].decode('utf-8', errors='replace')

            entries.append({
                'name': name,
                'type': TYPECODES.get(typecode, f'UNKNOWN({typecode})'),
                'typecode': typecode,
                'data_offset': pos + entry_len,
                'data_len': data_len,
                'uncomp_len': uncomp_len,
                'compressed': compress_flag == 1,
            })
            pos += entry_len
        except Exception:
            break

    return entries


def extract_entry(data: bytes, entry: dict, archive_offset: int) -> bytes:
    """Extract a single TOC entry."""
    offset = archive_offset + entry.get('data_offset', 0)
    raw = data[offset:offset + entry['data_len']]

    if entry['compressed'] and raw:
        try:
            return zlib.decompress(raw)
        except zlib.error:
            return raw
    return raw


def fix_pyc_header(pyc_data: bytes, python_version: tuple) -> bytes:
    """Add or fix .pyc header with correct magic for Python version."""
    magic = PYC_MAGIC.get(python_version)
    if magic is None:
        magic = PYC_MAGIC.get((3, 10))  # default fallback

    # Check if header already present
    if len(pyc_data) >= 4 and pyc_data[:2] in [m[:2] for m in PYC_MAGIC.values()]:
        return pyc_data

    # Build header: magic(4) + flags(4) + timestamp(4) + size(4) = 16 bytes
    header = magic + b'\x00' * 12
    return header + pyc_data


def try_pyinstxtractor(filepath: Path, out_dir: Path) -> bool:
    """Try using pyinstxtractor-ng if available."""
    try:
        import importlib.util
        if importlib.util.find_spec('pyinstxtractor'):
            import subprocess
            result = subprocess.run(
                [sys.executable, '-m', 'pyinstxtractor', str(filepath), '-d', str(out_dir)],
                capture_output=True, text=True, timeout=120,
            )
            return result.returncode == 0
    except Exception:
        pass
    return False


def extract_archive(filepath: Path, out_dir: Path, detection: dict) -> dict:
    """Extract all files from PyInstaller bundle."""
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {'extracted': [], 'failed': [], 'method': 'unknown'}
    python_version = detection.get('python_version') or (3, 10)

    # Try pyinstxtractor-ng first
    if try_pyinstxtractor(filepath, out_dir):
        result['method'] = 'pyinstxtractor-ng'
        for pyc in out_dir.rglob('*.pyc'):
            fixed = fix_pyc_header(pyc.read_bytes(), python_version)
            pyc.write_bytes(fixed)
            result['extracted'].append(str(pyc.relative_to(out_dir)))
        return result

    # Manual CArchive extraction
    result['method'] = 'manual_carchive'
    data = filepath.read_bytes()
    archive_offset = detection.get('archive_offset', 0)

    if not archive_offset:
        print("[!] Cannot determine archive offset — trying from file start")
        archive_offset = 0

    # Find TOC by scanning for entry patterns
    toc_entries = []
    # Try to find TOC via cookie
    tail = data[-4096:]
    mei_pos = tail.rfind(MEI_MAGIC)
    if mei_pos >= 0:
        abs_mei = len(data) - 4096 + mei_pos
        for cookie_size in [64, 88, 24]:
            cookie_start = abs_mei - cookie_size + 8
            if cookie_start < 0:
                continue
            try:
                cookie = data[cookie_start:abs_mei + 8]
                pkg_len = struct.unpack_from('<I', cookie, 8)[0]
                toc_off = struct.unpack_from('<I', cookie, 12)[0]
                toc_len = struct.unpack_from('<I', cookie, 16)[0]
                actual_archive = abs_mei + 8 - pkg_len
                toc_entries = parse_toc(data, actual_archive + toc_off, toc_len)
                if toc_entries:
                    archive_offset = actual_archive
                    break
            except Exception:
                continue

    if not toc_entries:
        print("[!] Could not parse TOC — extracting raw overlay")
        # Fallback: extract everything after PE end
        pe_end = _find_pe_overlay(data)
        if pe_end:
            overlay_path = out_dir / 'overlay.bin'
            overlay_path.write_bytes(data[pe_end:])
            result['extracted'].append('overlay.bin')
        return result

    print(f"[*] Found {len(toc_entries)} TOC entries")
    for entry in toc_entries:
        try:
            entry_data = extract_entry(data, entry, archive_offset)
            if not entry_data:
                continue

            name = entry['name'].replace('\\', '/').lstrip('/')
            if not name:
                name = f"unnamed_{entry['typecode']}"

            out_path = out_dir / name
            out_path.parent.mkdir(parents=True, exist_ok=True)

            # Fix .pyc headers for Python entries
            if entry['type'] in ('SCRIPT', 'PYMODULE', 'PYPACKAGE'):
                entry_data = fix_pyc_header(entry_data, python_version)
                if not name.endswith('.pyc'):
                    out_path = out_path.with_suffix('.pyc')

            out_path.write_bytes(entry_data)
            result['extracted'].append(str(out_path.relative_to(out_dir)))
        except Exception as e:
            result['failed'].append(f"{entry['name']}: {e}")

    return result


def _find_pe_overlay(data: bytes) -> int | None:
    """Find end of PE sections (start of overlay)."""
    if data[:2] != b'MZ':
        return None
    try:
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        num_sec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
        opt_sz = struct.unpack_from('<H', data, e_lfanew + 20)[0]
        sec_base = e_lfanew + 24 + opt_sz
        max_end = 0
        for i in range(num_sec):
            o = sec_base + i * 40
            raw_off = struct.unpack_from('<I', data, o + 20)[0]
            raw_sz = struct.unpack_from('<I', data, o + 16)[0]
            max_end = max(max_end, raw_off + raw_sz)
        return max_end
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract .pyc from PyInstaller bundles")
    ap.add_argument('path', help='PyInstaller executable or onedir folder')
    ap.add_argument('--out', default='pyinstaller-unpacked', help='Output directory')
    ap.add_argument('--detect-only', action='store_true', help='Only detect, do not extract')
    ap.add_argument('--no-fix-headers', action='store_true', help='Skip .pyc header fix')
    ap.add_argument('--json', action='store_true', help='Output results as JSON')
    args = ap.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"[!] Not found: {target}", file=sys.stderr)
        return 1

    print(f"[*] Analyzing: {target.name} ({target.stat().st_size:,} bytes)")
    detection = detect_pyinstaller(target)

    if not detection['is_pyinstaller']:
        print("[!] Not a PyInstaller bundle")
        return 1

    print(f"[+] PyInstaller detected: {detection['mode']}")
    print(f"[+] Python version: {detection.get('python_version', 'unknown')}")

    if args.detect_only:
        if args.json:
            print(json.dumps(detection, indent=2, default=str))
        return 0

    out_dir = Path(args.out)
    print(f"[*] Extracting to: {out_dir}")
    result = extract_archive(target, out_dir, detection)

    # Write manifest
    manifest = {
        'detection': detection,
        'extraction': result,
    }
    (out_dir / 'manifest.json').write_text(
        json.dumps(manifest, indent=2, default=str), encoding='utf-8')

    print(f"\n[+] Extraction complete: {len(result['extracted'])} files")
    print(f"[+] Method: {result['method']}")
    if result['failed']:
        print(f"[!] Failed: {len(result['failed'])} entries")
    print(f"[+] Manifest: {out_dir / 'manifest.json'}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
