#!/usr/bin/env python3
"""
decompile_pyc.py — Batch decompile .pyc files with version-aware fallback chain.

Fallback order:
  Python 3.9+:  pycdc → decompile3 → dis (bytecode)
  Python 3.6-8: uncompyle6 → pycdc → dis

Usage:
    python decompile_pyc.py --pyc-dir unpacked/ --out decompiled/
    python decompile_pyc.py --single main.pyc --out decompiled/
    python decompile_pyc.py --pyc-dir unpacked/ --out decompiled/ --python-version 3.10
"""

import argparse
import dis
import importlib.util
import json
import marshal
import struct
import subprocess
import sys
from pathlib import Path


PYC_MAGIC_VERSIONS = {
    0x0D33: (3, 6),
    0x0D42: (3, 7),
    0x0D55: (3, 8),
    0x0D61: (3, 9),
    0x0D6F: (3, 10),
    0x0DA7: (3, 11),
    0x0DCB: (3, 12),
    0x0DF7: (3, 13),
}


def detect_python_version(pyc_path: Path) -> tuple | None:
    """Read .pyc magic number to determine Python version."""
    data = pyc_path.read_bytes()
    if len(data) < 4:
        return None
    magic = struct.unpack_from('<H', data, 0)[0]
    return PYC_MAGIC_VERSIONS.get(magic)


def _run_tool(cmd: list[str], timeout: int = 60) -> tuple[bool, str]:
    """Run external decompiler tool. Returns (success, output)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding='utf-8', errors='replace', timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            return True, result.stdout
        return False, result.stderr or result.stdout
    except FileNotFoundError:
        return False, 'tool not found'
    except subprocess.TimeoutExpired:
        return False, 'timeout'
    except Exception as e:
        return False, str(e)


def decompile_with_pycdc(pyc_path: Path) -> tuple[bool, str]:
    """Decompyle++ — best for Python 3.9+."""
    ok, out = _run_tool(['pycdc', str(pyc_path)])
    if not ok:
        ok, out = _run_tool([sys.executable, '-m', 'pycdc', str(pyc_path)])
    return ok, out


def decompile_with_uncompyle6(pyc_path: Path) -> tuple[bool, str]:
    """uncompyle6 — best for Python 3.6–3.8."""
    return _run_tool([sys.executable, '-m', 'uncompyle6', str(pyc_path)])


def decompile_with_decompile3(pyc_path: Path) -> tuple[bool, str]:
    """decompile3 — alternative for 3.7+."""
    return _run_tool([sys.executable, '-m', 'decompile3', str(pyc_path)])


def decompile_with_dis(pyc_path: Path) -> tuple[bool, str]:
    """Last resort: stdlib dis module bytecode disassembly."""
    try:
        data = pyc_path.read_bytes()
        # Skip header (16 bytes for 3.7+, 12 for older, 8 for very old)
        for header_size in [16, 12, 8]:
            try:
                code = marshal.loads(data[header_size:])
                if hasattr(code, 'co_code'):
                    break
            except Exception:
                continue
        else:
            return False, 'cannot unmarshal code object'

        import io
        buf = io.StringIO()
        buf.write(f'# Bytecode disassembly of {pyc_path.name}\n')
        buf.write(f'# Code object: {code.co_name}\n')
        buf.write(f'# Constants: {code.co_consts}\n')
        buf.write(f'# Names: {code.co_names}\n')
        buf.write(f'# Varnames: {code.co_varnames}\n\n')
        dis.dis(code, file=buf)
        return True, buf.getvalue()
    except Exception as e:
        return False, str(e)


def get_fallback_chain(python_version: tuple | None) -> list:
    """Get ordered decompiler chain based on Python version."""
    if python_version and python_version[1] <= 8:
        return [
            ('uncompyle6', decompile_with_uncompyle6),
            ('pycdc', decompile_with_pycdc),
            ('dis', decompile_with_dis),
        ]
    return [
        ('pycdc', decompile_with_pycdc),
        ('decompile3', decompile_with_decompile3),
        ('uncompyle6', decompile_with_uncompyle6),
        ('dis', decompile_with_dis),
    ]


def decompile_one(pyc_path: Path, out_path: Path,
                  python_version: tuple | None = None) -> dict:
    """Decompile a single .pyc file with fallback chain."""
    version = python_version or detect_python_version(pyc_path)
    chain = get_fallback_chain(version)

    for tool_name, tool_fn in chain:
        ok, output = tool_fn(pyc_path)
        if ok and output.strip():
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(output, encoding='utf-8')
            return {
                'status': 'success',
                'tool': tool_name,
                'source': str(pyc_path),
                'output': str(out_path),
                'lines': output.count('\n'),
            }

    return {
        'status': 'failed',
        'source': str(pyc_path),
        'errors': f'All decompilers failed for {pyc_path.name}',
    }


def batch_decompile(pyc_dir: Path, out_dir: Path,
                    python_version: tuple | None = None) -> dict:
    """Batch decompile all .pyc files in directory."""
    out_dir.mkdir(parents=True, exist_ok=True)
    pyc_files = sorted(pyc_dir.rglob('*.pyc'))

    results = {'success': 0, 'failed': 0, 'total': len(pyc_files), 'files': []}
    print(f"[*] Found {len(pyc_files)} .pyc files")

    for i, pyc in enumerate(pyc_files, 1):
        rel = pyc.relative_to(pyc_dir)
        out_path = out_dir / rel.with_suffix('.py')
        print(f"[*] [{i}/{len(pyc_files)}] {rel}")

        result = decompile_one(pyc, out_path, python_version)
        results['files'].append(result)

        if result['status'] == 'success':
            results['success'] += 1
            print(f"    [+] OK ({result['tool']}, {result['lines']} lines)")
        else:
            results['failed'] += 1
            print(f"    [!] Failed")

    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="Batch decompile .pyc with fallback chain")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--pyc-dir', help='Directory containing .pyc files')
    group.add_argument('--single', help='Single .pyc file to decompile')
    ap.add_argument('--out', default='decompiled', help='Output directory')
    ap.add_argument('--python-version', help='Python version hint (e.g., 3.10)')
    ap.add_argument('--json', action='store_true', help='Output results as JSON')
    args = ap.parse_args()

    py_ver = None
    if args.python_version:
        parts = args.python_version.split('.')
        py_ver = (int(parts[0]), int(parts[1]))

    out_dir = Path(args.out)

    if args.single:
        pyc = Path(args.single)
        if not pyc.exists():
            print(f"[!] Not found: {pyc}", file=sys.stderr)
            return 1
        out_path = out_dir / pyc.with_suffix('.py').name
        result = decompile_one(pyc, out_path, py_ver)
        if result['status'] == 'success':
            print(f"[+] Decompiled: {result['output']} ({result['tool']})")
            return 0
        print(f"[!] Failed: {result.get('errors', 'unknown')}")
        return 1

    pyc_dir = Path(args.pyc_dir)
    if not pyc_dir.exists():
        print(f"[!] Not found: {pyc_dir}", file=sys.stderr)
        return 1

    results = batch_decompile(pyc_dir, out_dir, py_ver)

    # Write report
    (out_dir / 'decompile_report.json').write_text(
        json.dumps(results, indent=2), encoding='utf-8')

    print(f"\n[+] Decompilation complete:")
    print(f"    Success: {results['success']}/{results['total']}")
    print(f"    Failed:  {results['failed']}/{results['total']}")
    print(f"    Report:  {out_dir / 'decompile_report.json'}")

    return 0 if results['failed'] == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
