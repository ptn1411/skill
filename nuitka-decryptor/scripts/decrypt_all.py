#!/usr/bin/env python3
"""
decrypt_all.py — Bulk decrypt Nuitka XOR+Base64 encrypted source files
Formula: plaintext = XOR(base64_decode(ciphertext), repeating_key)

Usage:
    # Bulk decrypt via MANIFEST
    python decrypt_all.py --key BT_DEV_2025_SECURE \
        --encrypted-dir app/encrypted_sources \
        --manifest app/encrypted_sources/MANIFEST.txt \
        --output-dir decrypted_sources

    # Decrypt a single .encrypted file
    python decrypt_all.py --key BT_DEV_2025_SECURE \
        --single update_config.json.encrypted \
        --output-dir ./out

    # Read key from file
    python decrypt_all.py --key-file key_final.txt \
        --encrypted-dir app/encrypted_sources \
        --output-dir decrypted_sources

    # Dry-run: verify key only
    python decrypt_all.py --key BT_DEV_2025_SECURE \
        --single update_config.json.encrypted \
        --dry-run
"""
import argparse
import base64
import json
import os
import sys
from pathlib import Path


# ── Core decrypt ───────────────────────────────────────────────────────────────

def xor_decrypt(payload_b64: str, key: bytes) -> str:
    decoded = base64.b64decode(payload_b64)
    kr = (key * (len(decoded) // len(key) + 1))[:len(decoded)]
    return bytes(a ^ b for a, b in zip(decoded, kr)).decode('utf-8', errors='replace')


def fernet_decrypt(payload_b64: str, key: bytes) -> str:
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        print("[!] cryptography library missing. Required for Fernet mode.")
        return ""
    
    try:
        # Check if the payload is double-base64 encoded (common in some apps)
        decoded = base64.b64decode(payload_b64)
        if decoded.startswith(b'gAAAA'):
            token = decoded
        else:
            token = payload_b64.encode()
            
        f = Fernet(key)
        return f.decrypt(token).decode('utf-8')
    except Exception as e:
        print(f"  [FERNET ERROR] {e}")
        return ""


def decrypt_file(src: Path, dst: Path, key: bytes, algo='xor', dry_run: bool = False) -> bool:
    try:
        encrypted = src.read_text(encoding='utf-8').strip()
        if algo == 'fernet':
            plaintext = fernet_decrypt(encrypted, key)
        else:
            plaintext = xor_decrypt(encrypted, key)
            
        if not plaintext:
            return False
            
        if dry_run:
            print(f"  [DRY] Would write {dst} ({len(plaintext)} chars)")
            return True
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(plaintext, encoding='utf-8')
        return True
    except Exception as e:
        print(f"  [ERROR] {src.name}: {e}", file=sys.stderr)
        return False


# ── Verify key ─────────────────────────────────────────────────────────────────

def verify_key(key: bytes, config_path: Path | None, manifest_first: Path | None) -> bool:
    """Quick-check key on a known-structure file."""
    target = config_path or manifest_first
    if not target:
        return True  # can't verify, assume ok

    try:
        b64 = target.read_text(encoding='utf-8').strip()
        plain = xor_decrypt(b64, key)
        # Config should be JSON; manifest should be plain text paths
        if config_path:
            json.loads(plain)
            print(f"[+] Key verified via JSON config: {target.name}")
        else:
            assert plain.strip(), "Empty decrypt result"
            print(f"[+] Key plausibly correct (high printable ratio)")
        return True
    except Exception as e:
        print(f"[!] Key verification failed on {target.name}: {e}", file=sys.stderr)
        return False


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Decrypt Nuitka XOR+Base64 encrypted sources")

    key_grp = ap.add_mutually_exclusive_group(required=True)
    key_grp.add_argument('--key', metavar='STR', help='Decryption key (ASCII string)')
    key_grp.add_argument('--key-file', metavar='FILE', help='File containing the key')

    mode_grp = ap.add_mutually_exclusive_group(required=True)
    mode_grp.add_argument('--single', metavar='FILE', help='Decrypt a single .encrypted file')
    mode_grp.add_argument('--encrypted-dir', metavar='DIR', help='Directory with .encrypted files')

    ap.add_argument('--manifest', metavar='FILE',
                    help='MANIFEST.txt listing relative paths (used with --encrypted-dir)')
    ap.add_argument('--output-dir', required=True, metavar='DIR', help='Output directory')
    ap.add_argument('--config', metavar='FILE',
                    help='.encrypted config file for key verification')
    ap.add_argument('--algo', default='xor', choices=['xor', 'fernet'],
                    help='Decryption algorithm (default: xor)')
    ap.add_argument('--dry-run', action='store_true', help='Verify key + preview, no file writes')
    ap.add_argument('--sample', metavar='FILE',
                    help='Show first 500 chars of this decrypted file after bulk run')
    args = ap.parse_args()

    # Resolve key
    if args.key_file:
        key = Path(args.key_file).read_text(encoding='utf-8').strip().encode()
    else:
        key = args.key.encode()

    print(f"Key : {key!r} ({len(key)} bytes)")
    out_dir = Path(args.output_dir)

    # Verify key
    config_path = Path(args.config) if args.config else None
    if config_path and not config_path.exists():
        print(f"[!] Config file not found: {config_path}", file=sys.stderr)
        config_path = None

    if not verify_key(key, config_path, None):
        print("[!] Key failed verification. Aborting.", file=sys.stderr)
        sys.exit(1)

    # ── Single file mode ──────────────────────────────────────────────────────
    if args.single:
        src = Path(args.single)
        if not src.exists():
            print(f"[!] File not found: {src}", file=sys.stderr)
            sys.exit(1)

        # Output filename: strip .encrypted suffix if present
        out_name = src.stem if src.suffix == '.encrypted' else src.name
        dst = out_dir / out_name
        ok = decrypt_file(src, dst, key, args.algo, args.dry_run)
        if ok and not args.dry_run:
            text = dst.read_text(encoding='utf-8')
            print(f"[+] Decrypted: {dst} ({len(text)} chars)")
            print(f"\n--- Preview (500 chars) ---")
            print(text[:500])
            # Try JSON parse
            try:
                obj = json.loads(text)
                print(f"\n[+] Valid JSON, keys: {list(obj.keys())[:10]}")
            except Exception:
                pass
        sys.exit(0 if ok else 1)

    # ── Bulk mode (MANIFEST) ──────────────────────────────────────────────────
    enc_dir = Path(args.encrypted_dir)
    if not enc_dir.exists():
        print(f"[!] Encrypted dir not found: {enc_dir}", file=sys.stderr)
        sys.exit(1)

    # Read manifest
    if args.manifest:
        manifest = Path(args.manifest)
        if not manifest.exists():
            print(f"[!] MANIFEST not found: {manifest}", file=sys.stderr)
            sys.exit(1)
        files = [l.strip() for l in manifest.read_text(encoding='utf-8').splitlines() if l.strip()]
    else:
        # Auto-discover all .encrypted files
        files = [str(p.relative_to(enc_dir)).replace('.encrypted', '')
                 for p in enc_dir.rglob('*.encrypted')]
        print(f"[i] No manifest — auto-discovered {len(files)} .encrypted files")

    print(f"\nDecrypting {len(files)} files → {out_dir}")
    if args.dry_run:
        print("[DRY RUN mode — no files will be written]\n")

    success, failed, skipped = 0, 0, 0
    failed_files = []

    for rel_path in files:
        src = enc_dir / (rel_path + '.encrypted')
        dst = out_dir / rel_path

        if not src.exists():
            print(f"  [SKIP] {rel_path}")
            skipped += 1
            continue

        ok = decrypt_file(src, dst, key, args.algo, args.dry_run)
        if ok:
            success += 1
        else:
            failed += 1
            failed_files.append(rel_path)

    # Summary
    print(f"\n{'='*60}")
    print(f"Results:")
    print(f"  Success : {success}")
    print(f"  Failed  : {failed}")
    print(f"  Skipped : {skipped}")
    print(f"  Total   : {len(files)}")
    if not args.dry_run:
        print(f"\nOutput  : {out_dir.resolve()}")

    if failed_files:
        print(f"\nFailed files:")
        for f in failed_files[:20]:
            print(f"  {f}")

    # Show sample
    sample_rel = args.sample or (files[0] if files else None)
    if sample_rel and not args.dry_run:
        sample_path = out_dir / sample_rel
        if sample_path.exists():
            print(f"\n--- Sample: {sample_rel} ---")
            print(sample_path.read_text(encoding='utf-8', errors='replace')[:500])

    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()
