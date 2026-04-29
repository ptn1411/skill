#!/usr/bin/env python3
"""
apply_patch.py — Automated Binary Patcher.
Applies patches (hex replacements) to a file at specified offsets.
Useful for permanent assembly patching after identifying targets in x64dbg.
"""
import argparse
import sys
from pathlib import Path

def apply_patches(target_path, patches, output_path=None):
    p = Path(target_path)
    if not p.exists():
        print(f"[!] Error: {target_path} not found.")
        return

    data = bytearray(p.read_bytes())
    print(f"[*] Original File: {p.name} ({len(data):,} bytes)")
    
    for offset_hex, original_hex, patch_hex in patches:
        try:
            # Handle both file offsets and virtual addresses if needed (though file offset is safer here)
            offset = int(offset_hex, 16)
            original = bytes.fromhex(original_hex.replace(' ', ''))
            patch = bytes.fromhex(patch_hex.replace(' ', ''))
            
            if len(original) != len(patch):
                print(f"[!] Warning: Original size ({len(original)}) != Patch size ({len(patch)}). Using patch size.")

            # Verify original content
            current = data[offset : offset + len(original)]
            if current != original:
                print(f"[!] Verification failed at 0x{offset:X}!")
                print(f"    Expected: {original.hex(' ')}")
                print(f"    Found   : {current.hex(' ')}")
                continue
                
            # Apply patch
            data[offset : offset + len(patch)] = patch
            print(f"  [+] Patched 0x{offset:X}: {original.hex(' ')} -> {patch.hex(' ')}")
            
        except Exception as e:
            print(f"  [X] Failed at {offset_hex}: {e}")

    out = Path(output_path if output_path else target_path)
    out.write_bytes(data)
    print(f"\n[+] Patching complete! Saved to: {out}")

def main():
    ap = argparse.ArgumentParser(description="Binary Patcher")
    ap.add_argument('file', help='Binary file to patch')
    ap.add_argument('--patch', action='append', nargs=3, metavar=('OFFSET', 'ORIGINAL_HEX', 'PATCH_HEX'),
                    help='Specify a patch (e.g., 0x1234 7405 9090)')
    ap.add_argument('--out', help='Output file path')
    args = ap.parse_args()

    if not args.patch:
        print("Usage example:")
        print("  python apply_patch.py laragon.exe --patch 0x61C14 7405 9090")
        return

    apply_patches(args.file, args.patch, args.out)

if __name__ == "__main__":
    main()
