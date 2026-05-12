#!/usr/bin/env python3
"""
decompile_dotnet.py — Automated .NET assembly decompilation.

Uses ilspycmd (ILSpy CLI) when available, falls back to metadata extraction.
Detects .NET version and obfuscators (ConfuserEx, .NET Reactor, Babel, etc.).

Usage:
    python decompile_dotnet.py target.exe --out decompiled/
    python decompile_dotnet.py target.dll --detect-only
    python decompile_dotnet.py target.exe --out decompiled/ --extract-resources
"""

import argparse
import json
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path


OBFUSCATOR_SIGNATURES = {
    'ConfuserEx': [
        rb'ConfuserEx\s*v[\d.]+', rb'Confuser\.Core',
        rb'\xEF\xBB\xBF', rb'<Module>\s*cctor.*Confuser',
    ],
    '.NET Reactor': [
        rb'\.NET\s*Reactor', rb'Eziriz', rb'_ProtectedModule',
        rb'ReactorHelper',
    ],
    'Babel': [
        rb'Babel\.Net', rb'babel', rb'BabelObfuscator',
    ],
    'SmartAssembly': [
        rb'SmartAssembly', rb'{z2}', rb'PoweredBy.*SmartAssembly',
    ],
    'Dotfuscator': [
        rb'Dotfuscator', rb'PreEmptive',
    ],
    'Eazfuscator': [
        rb'Eazfuscator', rb'\x00\x02\x06\x08',
    ],
    'Crypto Obfuscator': [
        rb'CryptoObfuscator', rb'LogicalTech',
    ],
}


def detect_dotnet(filepath: Path) -> dict:
    """Detect if file is a .NET assembly and identify version/obfuscator."""
    data = filepath.read_bytes()
    result = {
        'is_dotnet': False,
        'framework': None,
        'version': None,
        'obfuscator': None,
        'entry_point': None,
        'file_size': len(data),
    }

    # Check PE header
    if data[:2] != b'MZ':
        return result

    try:
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
            return result
    except Exception:
        return result

    # Check for mscoree.dll import (indicator of .NET)
    if b'mscoree.dll' not in data and b'_CorExeMain' not in data and b'_CorDllMain' not in data:
        # Also check for BSJB metadata
        if b'BSJB' not in data:
            return result

    result['is_dotnet'] = True

    # Find CLI header via PE data directory 14 (COM descriptor)
    try:
        opt_off = e_lfanew + 24
        magic = struct.unpack_from('<H', data, opt_off)[0]
        if magic == 0x20b:  # PE32+
            dd_off = opt_off + 112 + 14 * 8
        else:  # PE32
            dd_off = opt_off + 96 + 14 * 8
        cli_rva = struct.unpack_from('<I', data, dd_off)[0]
        if cli_rva > 0:
            result['framework'] = 'CLR'
    except Exception:
        pass

    # Detect .NET version from metadata
    bsjb_pos = data.find(b'BSJB')
    if bsjb_pos > 0:
        # Version string follows BSJB + 8 bytes
        try:
            ver_len = struct.unpack_from('<I', data, bsjb_pos + 12)[0]
            ver_str = data[bsjb_pos + 16:bsjb_pos + 16 + ver_len]
            ver_str = ver_str.rstrip(b'\x00').decode('utf-8', errors='ignore')
            result['version'] = ver_str
            if 'v4.' in ver_str:
                result['framework'] = '.NET Framework 4.x'
            elif 'v2.' in ver_str:
                result['framework'] = '.NET Framework 2.x'
            elif ver_str.startswith('v'):
                result['framework'] = f'.NET {ver_str}'
        except Exception:
            pass

    # Detect obfuscator
    for obf_name, signatures in OBFUSCATOR_SIGNATURES.items():
        for sig in signatures:
            if re.search(sig, data):
                result['obfuscator'] = obf_name
                break
        if result['obfuscator']:
            break

    # Check for unprintable type names (generic obfuscation)
    if not result['obfuscator']:
        unprintable_count = len(re.findall(rb'[\x01-\x1f]{3,}', data[:100000]))
        if unprintable_count > 50:
            result['obfuscator'] = 'Unknown (heavily renamed)'

    return result


def deobfuscate_with_de4dot(filepath: Path, out_dir: Path, obfuscator: str | None = None) -> Path | None:
    """Run de4dot to deobfuscate assembly before decompilation."""
    de4dot = shutil.which('de4dot') or shutil.which('de4dot-x64')
    if not de4dot:
        for candidate in [
            Path('C:/tools/de4dot/de4dot.exe'),
            Path.home() / 'tools' / 'de4dot' / 'de4dot.exe',
            Path('.') / 'de4dot' / 'de4dot.exe',
        ]:
            if candidate.exists():
                de4dot = str(candidate)
                break
    if not de4dot:
        print("[!] de4dot not found — skipping deobfuscation")
        print("[i] Download: https://github.com/de4dot/de4dot/releases")
        return None

    cleaned = out_dir / f"{filepath.stem}-cleaned{filepath.suffix}"
    cmd = [de4dot, str(filepath), '-o', str(cleaned)]

    if obfuscator:
        obf_map = {
            'ConfuserEx': 'cr',
            '.NET Reactor': 'dr',
            'Babel': 'ba',
            'Dotfuscator': 'df',
            'Eazfuscator': 'ef',
            'Crypto Obfuscator': 'co',
            'SmartAssembly': 'sa',
        }
        code = obf_map.get(obfuscator)
        if code:
            cmd.extend(['-p', code])

    print(f"[*] Deobfuscating with de4dot...")
    if obfuscator:
        print(f"    Obfuscator hint: {obfuscator}")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding='utf-8',
            errors='replace', timeout=300,
        )
        if cleaned.exists() and cleaned.stat().st_size > 0:
            print(f"[+] Deobfuscated: {cleaned.name} ({cleaned.stat().st_size:,} bytes)")
            return cleaned
        else:
            print(f"[!] de4dot output empty or failed")
            if result.stderr:
                print(f"    stderr: {result.stderr[:300]}")
            return None
    except subprocess.TimeoutExpired:
        print("[!] de4dot timed out (300s)")
        return None
    except Exception as e:
        print(f"[!] de4dot error: {e}")
        return None


def decompile_with_ilspy(filepath: Path, out_dir: Path) -> bool:
    """Decompile using ilspycmd (ILSpy CLI)."""
    ilspy = shutil.which('ilspycmd')
    if not ilspy:
        # Try dotnet tool
        try:
            result = subprocess.run(
                ['dotnet', 'tool', 'run', 'ilspycmd', str(filepath),
                 '-p', '-o', str(out_dir)],
                capture_output=True, text=True, timeout=300,
            )
            return result.returncode == 0
        except Exception:
            pass
        return False

    try:
        result = subprocess.run(
            [ilspy, str(filepath), '-p', '-o', str(out_dir)],
            capture_output=True, text=True, encoding='utf-8',
            errors='replace', timeout=300,
        )
        return result.returncode == 0
    except Exception:
        return False


def extract_metadata_strings(filepath: Path) -> list[str]:
    """Extract user strings from .NET metadata #US heap."""
    data = filepath.read_bytes()
    strings = []

    # Find #US (User Strings) heap
    us_marker = b'#US\x00'
    pos = data.find(us_marker)
    if pos < 0:
        # Try #Strings heap instead
        s_marker = b'#Strings\x00'
        pos = data.find(s_marker)
        if pos < 0:
            return strings

    # Extract readable strings from metadata area
    region = data[pos:pos + 0x100000]
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}', region):
        try:
            s = m.group().decode('utf-16-le').strip()
            if s and len(s) >= 4:
                strings.append(s)
        except Exception:
            pass

    return strings


def extract_resources(filepath: Path, out_dir: Path) -> list[str]:
    """Extract embedded .NET resources (including Costura.Fody merged DLLs)."""
    data = filepath.read_bytes()
    resources = []
    res_dir = out_dir / 'resources'
    res_dir.mkdir(parents=True, exist_ok=True)

    # Look for Costura.Fody pattern: compressed DLLs as resources
    costura_prefix = b'costura.'
    pos = 0
    while True:
        idx = data.find(costura_prefix, pos)
        if idx < 0:
            break
        # Extract name
        end = data.find(b'\x00', idx)
        if end > idx:
            name = data[idx:end].decode('ascii', errors='ignore')
            resources.append(name)
        pos = idx + 1

    # Generic resource extraction via regex for known patterns
    for m in re.finditer(rb'[\w.]+\.resources\x00', data):
        name = m.group().rstrip(b'\x00').decode('ascii', errors='ignore')
        if name not in resources:
            resources.append(name)

    return resources


def decompile_manual(filepath: Path, out_dir: Path) -> bool:
    """Fallback: extract what we can without external tools."""
    out_dir.mkdir(parents=True, exist_ok=True)
    detection = detect_dotnet(filepath)

    # Extract metadata strings
    strings = extract_metadata_strings(filepath)
    if strings:
        strings_file = out_dir / 'metadata_strings.txt'
        strings_file.write_text('\n'.join(strings), encoding='utf-8')
        print(f"    [+] Extracted {len(strings)} metadata strings")

    # Extract resources
    resources = extract_resources(filepath, out_dir)
    if resources:
        res_file = out_dir / 'resources_list.txt'
        res_file.write_text('\n'.join(resources), encoding='utf-8')
        print(f"    [+] Found {len(resources)} embedded resources")

    # Write detection report
    report = {
        'detection': detection,
        'strings_count': len(strings),
        'resources': resources,
        'note': 'Manual extraction only — install ilspycmd for full C# decompilation',
    }
    (out_dir / 'manual_extraction.json').write_text(
        json.dumps(report, indent=2, default=str), encoding='utf-8')

    return len(strings) > 0 or len(resources) > 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Decompile .NET assemblies")
    ap.add_argument('path', help='.NET assembly (.exe/.dll)')
    ap.add_argument('--out', default='dotnet-decompiled', help='Output directory')
    ap.add_argument('--detect-only', action='store_true', help='Only detect, skip decompilation')
    ap.add_argument('--extract-resources', action='store_true', help='Also extract embedded resources')
    ap.add_argument('--no-deobfuscate', action='store_true', help='Skip de4dot deobfuscation')
    ap.add_argument('--json', action='store_true', help='Output as JSON')
    args = ap.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"[!] Not found: {target}", file=sys.stderr)
        return 1

    print(f"[*] Analyzing: {target.name} ({target.stat().st_size:,} bytes)")
    detection = detect_dotnet(target)

    if not detection['is_dotnet']:
        print("[!] Not a .NET assembly")
        return 1

    print(f"[+] .NET detected: {detection['framework'] or 'unknown framework'}")
    print(f"[+] Version: {detection['version'] or 'unknown'}")
    if detection['obfuscator']:
        print(f"[!] Obfuscator: {detection['obfuscator']}")

    if args.detect_only:
        if args.json:
            print(json.dumps(detection, indent=2, default=str))
        return 0

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Auto-deobfuscate if obfuscator detected
    decompile_target = target
    if detection['obfuscator'] and not args.no_deobfuscate:
        print(f"[*] Obfuscator detected — attempting deobfuscation first...")
        cleaned = deobfuscate_with_de4dot(target, out_dir, detection['obfuscator'])
        if cleaned:
            decompile_target = cleaned
            print(f"[+] Will decompile cleaned assembly: {cleaned.name}")
        else:
            print(f"[*] Proceeding with original (obfuscated) assembly")

    # Try ilspycmd first
    print(f"[*] Decompiling to: {out_dir}")
    if decompile_with_ilspy(decompile_target, out_dir):
        print("[+] Decompilation complete (ilspycmd)")
        cs_files = list(out_dir.rglob('*.cs'))
        print(f"[+] Generated {len(cs_files)} .cs files")
    else:
        print("[!] ilspycmd not available — using manual extraction")
        print("[i] Install: dotnet tool install -g ilspycmd")
        decompile_manual(decompile_target, out_dir)

    # Extract resources if requested
    if args.extract_resources:
        resources = extract_resources(target, out_dir)
        print(f"[+] Resources found: {len(resources)}")

    # Write manifest
    manifest = {
        'detection': detection,
        'output_dir': str(out_dir),
    }
    (out_dir / 'manifest.json').write_text(
        json.dumps(manifest, indent=2, default=str), encoding='utf-8')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
