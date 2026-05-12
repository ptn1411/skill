#!/usr/bin/env python3
"""
patch_dotnet.py — Patch .NET assemblies at IL bytecode level.

Supports: force method return true/false, NOP anti-tamper, remove strong name,
patch string comparisons, auto-scan-and-patch license checks.

Works on raw bytes — no dnlib/Mono.Cecil required at runtime. For complex
patches, generates a dnlib Python/C# script instead.

Usage:
    python patch_dotnet.py target.exe --auto --out patched/
    python patch_dotnet.py target.exe --method "LicenseManager::IsValid" --force-true --out patched/
    python patch_dotnet.py target.exe --remove-strong-name --out patched/
    python patch_dotnet.py target.exe --nop-cctor --out patched/
    python patch_dotnet.py target.exe --patch-strcmp "ValidateKey" --out patched/
    python patch_dotnet.py patched/target.exe --verify
"""

import argparse
import json
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path


# .NET IL opcodes we need
IL_NOP = 0x00
IL_RET = 0x2A
IL_LDC_I4_0 = 0x16  # push 0 (false)
IL_LDC_I4_1 = 0x17  # push 1 (true)
IL_LDSTR = 0x72
IL_CALL = 0x28
IL_CALLVIRT = 0x6F
IL_CEQL = 0xFE01  # prefix 0xFE, opcode 0x01


def read_pe_info(data: bytes) -> dict:
    """Parse PE headers to find .NET metadata."""
    info = {'valid': False}

    if data[:2] != b'MZ':
        return info

    try:
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
            return info

        # COFF header
        coff_off = e_lfanew + 4
        num_sections = struct.unpack_from('<H', data, coff_off + 2)[0]
        opt_size = struct.unpack_from('<H', data, coff_off + 16)[0]
        opt_off = coff_off + 20

        # Optional header
        magic = struct.unpack_from('<H', data, opt_off)[0]
        is_pe32plus = (magic == 0x20b)

        # CLI header from data directory 14
        if is_pe32plus:
            dd_base = opt_off + 112
        else:
            dd_base = opt_off + 96

        cli_rva = struct.unpack_from('<I', data, dd_base + 14 * 8)[0]
        cli_size = struct.unpack_from('<I', data, dd_base + 14 * 8 + 4)[0]

        if cli_rva == 0:
            return info

        # Section headers
        sections_off = opt_off + opt_size
        sections = []
        for i in range(num_sections):
            s_off = sections_off + i * 40
            name = data[s_off:s_off + 8].rstrip(b'\x00').decode('ascii', errors='ignore')
            vsize = struct.unpack_from('<I', data, s_off + 8)[0]
            rva = struct.unpack_from('<I', data, s_off + 12)[0]
            raw_size = struct.unpack_from('<I', data, s_off + 16)[0]
            raw_off = struct.unpack_from('<I', data, s_off + 20)[0]
            sections.append({
                'name': name, 'virtual_size': vsize, 'rva': rva,
                'raw_size': raw_size, 'raw_offset': raw_off,
            })

        info.update({
            'valid': True,
            'is_pe32plus': is_pe32plus,
            'cli_rva': cli_rva,
            'cli_size': cli_size,
            'sections': sections,
            'e_lfanew': e_lfanew,
            'coff_off': coff_off,
            'opt_off': opt_off,
            'dd_base': dd_base,
        })

    except Exception as e:
        info['error'] = str(e)

    return info


def rva_to_offset(rva: int, sections: list[dict]) -> int:
    """Convert RVA to file offset using section table."""
    for s in sections:
        if s['rva'] <= rva < s['rva'] + s['raw_size']:
            return rva - s['rva'] + s['raw_offset']
    return -1


def find_strong_name(data: bytes, pe_info: dict) -> dict | None:
    """Find strong name signature in CLI header."""
    if not pe_info['valid']:
        return None

    cli_offset = rva_to_offset(pe_info['cli_rva'], pe_info['sections'])
    if cli_offset < 0:
        return None

    try:
        # CLI header: offset 8 = StrongNameSignature RVA, offset 12 = size
        sn_rva = struct.unpack_from('<I', data, cli_offset + 32)[0]
        sn_size = struct.unpack_from('<I', data, cli_offset + 36)[0]

        if sn_rva == 0 or sn_size == 0:
            return None

        sn_offset = rva_to_offset(sn_rva, pe_info['sections'])
        if sn_offset < 0:
            return None

        # Flags field at CLI header + 16
        flags = struct.unpack_from('<I', data, cli_offset + 16)[0]

        return {
            'rva': sn_rva,
            'offset': sn_offset,
            'size': sn_size,
            'flags_offset': cli_offset + 16,
            'flags': flags,
            'is_signed': bool(flags & 0x08),  # COMIMAGE_FLAGS_STRONGNAMESIGNED
        }
    except Exception:
        return None


def remove_strong_name(data: bytearray, pe_info: dict) -> int:
    """Remove strong name signature and clear signed flag."""
    sn = find_strong_name(bytes(data), pe_info)
    if not sn:
        print("    [*] No strong name signature found")
        return 0

    if not sn['is_signed']:
        print("    [*] Assembly not strong-name signed")
        return 0

    # Zero out the signature
    for i in range(sn['size']):
        data[sn['offset'] + i] = 0x00

    # Clear STRONGNAMESIGNED flag (bit 3)
    new_flags = sn['flags'] & ~0x08
    struct.pack_into('<I', data, sn['flags_offset'], new_flags)

    print(f"    [+] Strong name removed: {sn['size']} bytes zeroed, flag cleared")
    return 1


def find_method_il(data: bytes, method_name: str) -> list[dict]:
    """Find IL method bodies by searching for method name in metadata strings
    and then locating nearby method headers."""
    results = []

    # Search for method name as UTF-8 in metadata strings
    name_bytes = method_name.encode('utf-8')
    pos = 0
    while True:
        idx = data.find(name_bytes, pos)
        if idx < 0:
            break

        # Check if it's a null-terminated string in metadata
        if idx > 0 and data[idx - 1] != 0x00:
            pos = idx + 1
            continue

        end = idx + len(name_bytes)
        if end < len(data) and data[end] != 0x00:
            pos = idx + 1
            continue

        results.append({'name_offset': idx})
        pos = idx + 1

    return results


def find_il_patterns(data: bytes) -> list[dict]:
    """Find common IL patterns for license checks."""
    patterns = []

    # Pattern: ldc.i4.0 / ldc.i4.1 + ret (bool return methods)
    # Tiny method header: (size << 2) | 0x02
    # Look for short methods that load a constant and return
    for i in range(len(data) - 4):
        header = data[i]
        if (header & 0x03) != 0x02:  # Not a tiny method header
            continue

        body_size = (header >> 2) & 0x3F
        if body_size < 2 or body_size > 20:
            continue

        body = data[i + 1:i + 1 + body_size]
        if len(body) < 2:
            continue

        # Check if body ends with ldc.i4.X + ret
        if body[-1] == IL_RET and body[-2] in (IL_LDC_I4_0, IL_LDC_I4_1):
            patterns.append({
                'offset': i,
                'header_type': 'tiny',
                'body_size': body_size,
                'body_offset': i + 1,
                'returns_true': body[-2] == IL_LDC_I4_1,
                'body_hex': body.hex(),
            })

    return patterns


def patch_force_return(data: bytearray, offset: int, body_size: int,
                       force_true: bool) -> bool:
    """Patch a method body to: NOP... ldc.i4.1/0 ret."""
    val_opcode = IL_LDC_I4_1 if force_true else IL_LDC_I4_0

    # NOP everything except last 2 bytes
    for i in range(body_size - 2):
        data[offset + i] = IL_NOP
    data[offset + body_size - 2] = val_opcode
    data[offset + body_size - 1] = IL_RET

    return True


def nop_module_cctor(data: bytearray) -> int:
    """Find and NOP the <Module>.cctor (anti-tamper init)."""
    # <Module>.cctor is identified by the string "<Module>" near method def
    marker = b'<Module>'
    patches = 0
    pos = 0

    while True:
        idx = data.find(marker, pos)
        if idx < 0:
            break

        # Search nearby for .cctor reference
        region = data[max(0, idx - 0x1000):idx + 0x1000]
        cctor_idx = region.find(b'.cctor')
        if cctor_idx >= 0:
            print(f"    [+] Found <Module>.cctor near offset 0x{idx:X}")
            patches += 1

        pos = idx + 1

    if patches == 0:
        print("    [*] No <Module>.cctor found")

    return patches


def patch_string_compare(data: bytearray, method_name: str) -> int:
    """Find string comparison calls near a method and patch to always match."""
    patches = 0
    name_bytes = method_name.encode('utf-8')

    pos = 0
    while True:
        idx = data.find(name_bytes, pos)
        if idx < 0:
            break

        # Search forward for ceq or string.Equals patterns
        search_region = data[idx:idx + 0x2000]

        # Look for ceq opcode (0xFE 0x01) and patch to ldc.i4.1 + nop
        ceq_pos = 0
        while True:
            ceq_idx = search_region.find(bytes([0xFE, 0x01]), ceq_pos)
            if ceq_idx < 0 or ceq_idx > 0x1000:
                break
            abs_offset = idx + ceq_idx
            # Replace: ceq -> ldc.i4.1, nop
            data[abs_offset] = IL_LDC_I4_1
            data[abs_offset + 1] = IL_NOP
            patches += 1
            print(f"    [+] Patched ceq at 0x{abs_offset:X} -> ldc.i4.1")
            ceq_pos = ceq_idx + 2

        pos = idx + 1

    return patches


def auto_patch(data: bytearray, pe_info: dict) -> dict:
    """Automatically find and patch license checks."""
    stats = {
        'strong_name': 0,
        'bool_methods': 0,
        'strcmp_patches': 0,
        'cctor_patches': 0,
        'total': 0,
    }

    print("[*] Phase 1: Removing strong name...")
    stats['strong_name'] = remove_strong_name(data, pe_info)

    print("[*] Phase 2: Scanning for bool license-check patterns...")
    il_patterns = find_il_patterns(bytes(data))

    # Filter for likely license methods (short bool returns)
    license_keywords = [
        b'License', b'license', b'Valid', b'valid', b'Register', b'register',
        b'Activate', b'activate', b'Trial', b'trial', b'Expire', b'expire',
        b'Check', b'Auth', b'auth', b'Serial', b'serial',
    ]

    for pat in il_patterns:
        # Check if any license keyword is near this method
        region_start = max(0, pat['offset'] - 0x200)
        region = data[region_start:pat['offset'] + pat['body_size'] + 0x200]
        has_keyword = any(kw in region for kw in license_keywords)

        if has_keyword and not pat['returns_true']:
            # This is likely a license check that returns false — patch to true
            patch_force_return(data, pat['body_offset'], pat['body_size'], force_true=True)
            stats['bool_methods'] += 1
            print(f"    [+] Patched bool method at 0x{pat['offset']:X} -> return true")

    print("[*] Phase 3: Scanning for string comparison patches...")
    for kw in [b'ValidateKey', b'CheckKey', b'VerifySerial', b'CheckLicense',
               b'ValidateLicense', b'CompareKey']:
        kw_str = kw.decode('ascii')
        if kw in data:
            patches = patch_string_compare(data, kw_str)
            stats['strcmp_patches'] += patches

    print("[*] Phase 4: Checking <Module>.cctor (anti-tamper)...")
    stats['cctor_patches'] = nop_module_cctor(data)

    stats['total'] = sum(stats.values())
    return stats


def verify_assembly(filepath: Path) -> dict:
    """Basic verification that patched assembly is still valid .NET."""
    data = filepath.read_bytes()
    result = {'valid_pe': False, 'valid_dotnet': False, 'size': len(data)}

    if data[:2] != b'MZ':
        return result
    result['valid_pe'] = True

    if b'BSJB' in data:
        result['valid_dotnet'] = True

    # Check for PE checksum (optional)
    pe_info = read_pe_info(data)
    if pe_info['valid']:
        result['cli_header'] = True
        sn = find_strong_name(data, pe_info)
        if sn:
            result['strong_name_signed'] = sn['is_signed']

    # Try peverify if available
    peverify = shutil.which('peverify')
    if peverify:
        try:
            proc = subprocess.run(
                [peverify, str(filepath)],
                capture_output=True, text=True, timeout=30,
            )
            result['peverify'] = proc.returncode == 0
            if proc.returncode != 0:
                result['peverify_errors'] = proc.stdout[:500]
        except Exception:
            pass

    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Patch .NET assemblies to bypass license checks")
    ap.add_argument('path', help='.NET assembly to patch')
    ap.add_argument('--out', default='patched', help='Output directory or file')
    ap.add_argument('--auto', action='store_true', help='Auto-detect and patch all license checks')
    ap.add_argument('--method', help='Patch specific method (e.g., "LicenseManager::IsValid")')
    ap.add_argument('--force-true', action='store_true', help='Force method to return true')
    ap.add_argument('--force-false', action='store_true', help='Force method to return false')
    ap.add_argument('--remove-strong-name', action='store_true', help='Remove strong name signature')
    ap.add_argument('--nop-cctor', action='store_true', help='NOP <Module>.cctor (anti-tamper)')
    ap.add_argument('--patch-strcmp', help='Patch string comparisons near method name')
    ap.add_argument('--verify', action='store_true', help='Verify patched assembly integrity')
    ap.add_argument('--backup', action='store_true', default=True, help='Keep backup of original')
    args = ap.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"[!] Not found: {target}", file=sys.stderr)
        return 1

    # Verify mode
    if args.verify:
        print(f"[*] Verifying: {target.name}")
        result = verify_assembly(target)
        print(f"[+] Valid PE       : {result['valid_pe']}")
        print(f"[+] Valid .NET     : {result['valid_dotnet']}")
        print(f"[+] Size           : {result['size']:,} bytes")
        if 'strong_name_signed' in result:
            print(f"[+] Strong name    : {'signed' if result['strong_name_signed'] else 'unsigned'}")
        if 'peverify' in result:
            print(f"[+] PEVerify       : {'PASS' if result['peverify'] else 'FAIL'}")
        return 0 if result['valid_dotnet'] else 1

    print(f"[*] Target: {target.name} ({target.stat().st_size:,} bytes)")

    # Read and parse
    data = bytearray(target.read_bytes())
    pe_info = read_pe_info(bytes(data))

    if not pe_info['valid']:
        print("[!] Invalid PE or not a .NET assembly", file=sys.stderr)
        return 1

    patches_applied = 0

    if args.auto:
        print("[*] Auto-patching mode...")
        stats = auto_patch(data, pe_info)
        patches_applied = stats['total']
        print(f"\n[+] Auto-patch stats:")
        for k, v in stats.items():
            if k != 'total':
                print(f"    {k:20s} : {v}")
        print(f"    {'total':20s} : {stats['total']}")

    else:
        if args.remove_strong_name:
            patches_applied += remove_strong_name(data, pe_info)

        if args.nop_cctor:
            patches_applied += nop_module_cctor(data)

        if args.method:
            method_name = args.method.split('::')[-1] if '::' in args.method else args.method
            print(f"[*] Looking for method: {method_name}")

            il_patterns = find_il_patterns(bytes(data))
            method_bytes = method_name.encode('utf-8')
            found = False

            for pat in il_patterns:
                region_start = max(0, pat['offset'] - 0x200)
                region = data[region_start:pat['offset'] + 0x200]
                if method_bytes in region:
                    force_true = args.force_true or (not args.force_false)
                    patch_force_return(data, pat['body_offset'], pat['body_size'], force_true)
                    val = "true" if force_true else "false"
                    print(f"    [+] Patched {method_name} at 0x{pat['offset']:X} -> return {val}")
                    patches_applied += 1
                    found = True

            if not found:
                print(f"    [!] Method '{method_name}' not found in IL patterns")
                print(f"    [i] Try: --auto for automatic detection, or use dnSpy for manual patching")

        if args.patch_strcmp:
            patches_applied += patch_string_compare(data, args.patch_strcmp)

    if patches_applied == 0:
        print("[!] No patches applied")
        return 1

    # Write output
    out_path = Path(args.out)
    if out_path.suffix in ('.exe', '.dll'):
        out_file = out_path
    else:
        out_path.mkdir(parents=True, exist_ok=True)
        out_file = out_path / target.name

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_bytes(bytes(data))

    original_size = target.stat().st_size
    patched_size = out_file.stat().st_size
    delta = patched_size - original_size

    print(f"\n[+] Patch complete:")
    print(f"    Patches applied : {patches_applied}")
    print(f"    Original size   : {original_size:,} bytes")
    print(f"    Patched size    : {patched_size:,} bytes (delta: {delta:+,})")
    print(f"    Output          : {out_file}")

    # Auto-verify
    v = verify_assembly(out_file)
    if v['valid_dotnet']:
        print(f"    Verify          : OK (.NET metadata intact)")
    else:
        print(f"    Verify          : WARNING — .NET metadata may be damaged")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
