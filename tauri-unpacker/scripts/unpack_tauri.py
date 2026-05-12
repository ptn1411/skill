#!/usr/bin/env python3
"""
unpack_tauri.py — Extract embedded web assets from a Tauri desktop app.

Tauri embeds HTML/JS/CSS at compile time (often brotli-compressed).
This script extracts those assets by scanning the binary for web content
signatures, compressed data blobs, and Tauri config.

Usage:
    python unpack_tauri.py app.exe --out output/tauri-unpacked
    python unpack_tauri.py app.exe --out output/tauri-unpacked --no-decompress
    python unpack_tauri.py /path/to/MyApp.app --out output/tauri-unpacked  # macOS bundle
"""

import argparse
import io
import json
import os
import re
import struct
import sys
from pathlib import Path

try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False

MAX_READ = 512 * 1024 * 1024  # 512 MB


# --- Asset signatures ---------------------------------------------------------

HTML_SIGNATURES = [
    b'<!DOCTYPE html>',
    b'<!doctype html>',
    b'<html',
    b'<!DOCTYPE HTML>',
]

JS_SIGNATURES = [
    b'(function(',
    b'function(',
    b'"use strict"',
    b"'use strict'",
    b'const ',
    b'import ',
    b'export ',
    b'window.',
    b'document.',
    b'__TAURI__',
]

CSS_SIGNATURES = [
    b'body{',
    b'body {',
    b'.container{',
    b'.container {',
    b':root{',
    b':root {',
    b'@media',
    b'@import',
    b'@charset',
    b'@font-face',
]

JSON_SIGNATURES = [
    b'{"build"',
    b'{"tauri"',
    b'{"package"',
    b'{"productName"',
    b'{"version"',
    b'{"name"',
]

TAURI_CONFIG_KEYS = [
    'tauri', 'build', 'distDir', 'devPath', 'productName',
    'identifier', 'allowlist', 'security', 'csp',
]


# --- Tauri detection ----------------------------------------------------------

def detect_tauri(data: bytes) -> dict:
    """Detect if binary is a Tauri app and determine version."""
    strings_region = data  # search full binary

    indicators = {
        'tauri': b'tauri',
        '__TAURI__': b'__TAURI__',
        'tauri_runtime': b'tauri_runtime',
        'tauri::app': b'tauri::app',
        'wry': b'wry::webview',  # Tauri's webview library
        'tao': b'tao::window',   # Tauri's window library
    }

    found = {}
    for name, sig in indicators.items():
        if sig in strings_region:
            found[name] = True

    # Version detection
    version = 'unknown'
    if b'tauri::app::App' in data or b'tauri_runtime_wry' in data:
        version = 'v1'
    if b'tauri::app::AppHandle' in data and b'tauri_plugin' in data:
        version = 'v2'

    v_match = re.search(rb'tauri[- ](\d+\.\d+\.\d+)', data)
    version_str = v_match.group(1).decode() if v_match else None

    return {
        'is_tauri': len(found) >= 2,
        'version': version,
        'version_string': version_str,
        'indicators': list(found.keys()),
    }


# --- macOS bundle handling ----------------------------------------------------

def find_macos_binary(app_path: Path) -> Path | None:
    """Find the main binary in a macOS .app bundle."""
    contents = app_path / 'Contents'
    macos_dir = contents / 'MacOS'
    if macos_dir.exists():
        bins = list(macos_dir.iterdir())
        if bins:
            return bins[0]

    # Tauri v2 may have different structure
    for f in app_path.rglob('*'):
        if f.is_file() and not f.suffix and os.access(f, os.X_OK):
            return f
    return None


def check_macos_resources(app_path: Path, out_dir: Path) -> list[str]:
    """Check for web assets in macOS bundle Resources directory."""
    resources = app_path / 'Contents' / 'Resources'
    extracted = []

    if not resources.exists():
        return extracted

    for f in resources.rglob('*'):
        if f.is_file() and f.suffix in ('.html', '.js', '.css', '.json', '.svg', '.png', '.jpg', '.woff', '.woff2'):
            rel = f.relative_to(resources)
            dest = out_dir / 'assets' / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(f.read_bytes())
            extracted.append(str(rel))

    return extracted


# --- Asset extraction ---------------------------------------------------------

def find_html_blocks(data: bytes) -> list[dict]:
    """Find HTML content blocks in binary data."""
    blocks = []
    for sig in HTML_SIGNATURES:
        offset = 0
        while True:
            idx = data.find(sig, offset)
            if idx == -1:
                break
            # Find the end of HTML (look for </html> or next null region)
            end_marker = data.find(b'</html>', idx)
            if end_marker != -1:
                end_marker += len(b'</html>')
                content = data[idx:end_marker]
                # Validate: should contain some HTML structure
                if b'<head' in content or b'<body' in content or b'<div' in content:
                    blocks.append({
                        'offset': idx,
                        'size': len(content),
                        'type': 'html',
                        'data': content,
                    })
            offset = idx + len(sig)
    return blocks


def find_js_blocks(data: bytes, min_size: int = 500) -> list[dict]:
    """Find JavaScript content blocks in binary data."""
    blocks = []

    # Look for large JS-like content regions
    js_pattern = re.compile(
        rb'(?:(?:function\s*\w*\s*\([^)]*\)\s*\{)|'
        rb'(?:const\s+\w+\s*=)|'
        rb'(?:var\s+\w+\s*=)|'
        rb'(?:let\s+\w+\s*=)|'
        rb'(?:export\s+(?:default\s+)?(?:function|class|const))|'
        rb'(?:import\s+\{[^}]+\}\s+from))'
    )

    for m in js_pattern.finditer(data):
        start = m.start()
        # Scan backward to find the actual start of the JS block
        block_start = start
        while block_start > 0 and data[block_start - 1:block_start] in (b' ', b'\n', b'\r', b'\t', b'/'):
            block_start -= 1

        # Scan forward to estimate block size
        # JS blocks usually end with consecutive null bytes or non-printable
        pos = start + 100
        null_run = 0
        while pos < len(data) and pos < start + 5 * 1024 * 1024:  # max 5MB per block
            if data[pos] == 0:
                null_run += 1
                if null_run > 4:
                    break
            else:
                null_run = 0
            pos += 1

        content = data[block_start:pos - null_run]

        # Filter: must be mostly printable and large enough
        printable = sum(1 for b in content[:2000] if 0x20 <= b <= 0x7e or b in (0x0a, 0x0d, 0x09))
        ratio = printable / min(len(content), 2000) if content else 0

        if len(content) >= min_size and ratio > 0.85:
            blocks.append({
                'offset': block_start,
                'size': len(content),
                'type': 'js',
                'data': content,
            })

    # Deduplicate overlapping blocks
    blocks.sort(key=lambda b: b['offset'])
    deduped = []
    for block in blocks:
        if deduped and block['offset'] < deduped[-1]['offset'] + deduped[-1]['size']:
            # Merge or skip
            if block['size'] > deduped[-1]['size']:
                deduped[-1] = block
        else:
            deduped.append(block)

    return deduped


def find_css_blocks(data: bytes, min_size: int = 200) -> list[dict]:
    """Find CSS content blocks in binary data."""
    blocks = []
    css_pattern = re.compile(rb'(?:[\w.#:*\[\]-]+\s*\{[^}]+\}\s*){3,}')

    for m in css_pattern.finditer(data):
        start = m.start()
        # Expand to find full CSS block
        pos = m.end()
        brace_depth = 0
        while pos < len(data) and pos < start + 2 * 1024 * 1024:
            if data[pos] == 0x7b:  # {
                brace_depth += 1
            elif data[pos] == 0x7d:  # }
                brace_depth -= 1
            elif data[pos] == 0 and brace_depth <= 0:
                break
            pos += 1

        content = data[start:pos]
        if len(content) >= min_size:
            blocks.append({
                'offset': start,
                'size': len(content),
                'type': 'css',
                'data': content,
            })

    # Deduplicate
    blocks.sort(key=lambda b: b['offset'])
    deduped = []
    for block in blocks:
        if deduped and block['offset'] < deduped[-1]['offset'] + deduped[-1]['size']:
            if block['size'] > deduped[-1]['size']:
                deduped[-1] = block
        else:
            deduped.append(block)

    return deduped


# --- Tauri config extraction --------------------------------------------------

def find_tauri_config(data: bytes) -> dict | None:
    """Extract embedded tauri.conf.json from binary."""
    # Search for JSON objects containing Tauri config keys
    for key in [b'"tauri"', b'"build"', b'"productName"']:
        idx = 0
        while True:
            pos = data.find(key, idx)
            if pos == -1:
                break

            # Walk backward to find opening brace
            start = pos
            while start > 0 and data[start:start+1] != b'{':
                start -= 1
                if pos - start > 500:
                    break

            if data[start:start+1] != b'{':
                idx = pos + 1
                continue

            # Walk forward to find matching closing brace
            depth = 0
            end = start
            while end < len(data) and end < start + 50000:
                if data[end] == 0x7b:
                    depth += 1
                elif data[end] == 0x7d:
                    depth -= 1
                    if depth == 0:
                        end += 1
                        break
                end += 1

            candidate = data[start:end]
            try:
                obj = json.loads(candidate)
                # Verify it's a Tauri config
                is_config = any(k in obj for k in ('tauri', 'build', 'productName', 'package'))
                if is_config:
                    return obj
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

            idx = pos + 1

    return None


# --- Brotli decompression scanning --------------------------------------------

def try_brotli_regions(data: bytes, out_dir: Path) -> list[str]:
    """Scan for brotli-compressed regions and attempt decompression."""
    if not HAS_BROTLI:
        print("[!] brotli not installed — pip install brotli")
        return []

    extracted = []
    # Brotli doesn't have a fixed magic; try various offsets with potential data
    # Focus on regions after path-like strings (Tauri asset keys)

    asset_name_re = re.compile(rb'([\w/.-]+\.(?:html|js|css|json|svg|woff2?))\x00')
    for m in asset_name_re.finditer(data):
        name = m.group(1).decode('ascii', errors='replace')
        search_start = m.end()
        search_end = min(search_start + 1024 * 1024, len(data))

        # Try decompression at various offsets after the filename
        for offset in range(search_start, min(search_start + 256, search_end), 1):
            chunk = data[offset:offset + 512 * 1024]
            if not chunk:
                continue
            try:
                decompressed = brotli.decompress(chunk)
                if len(decompressed) > 50:
                    # Verify it looks like web content
                    printable = sum(1 for b in decompressed[:500] if 0x20 <= b <= 0x7e or b in (0x0a, 0x0d, 0x09))
                    if printable / min(len(decompressed), 500) > 0.7:
                        dest = out_dir / 'assets' / name
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(decompressed)
                        extracted.append(name)
                        print(f"[+] Decompressed: {name} ({len(decompressed)} bytes)")
                        break
            except Exception:
                continue

    return extracted


# --- Filename map extraction --------------------------------------------------

def extract_asset_names(data: bytes) -> list[str]:
    """Find embedded asset filenames (Tauri stores them as string keys)."""
    patterns = [
        rb'(index\.html)',
        rb'([\w/.-]+\.(?:html|htm))',
        rb'([\w/.-]+\.(?:js|mjs|cjs))',
        rb'([\w/.-]+\.(?:css))',
        rb'([\w/.-]+\.(?:json))',
        rb'([\w/.-]+\.(?:svg|png|jpg|jpeg|gif|ico|webp))',
        rb'([\w/.-]+\.(?:woff2?|ttf|eot))',
    ]

    names = set()
    for pat in patterns:
        for m in re.finditer(pat, data):
            name = m.group(1).decode('ascii', errors='replace')
            if not name.startswith('.') and '/' not in name[:1]:
                names.add(name)

    return sorted(names)


# --- Raw content extraction ---------------------------------------------------

def extract_raw_assets(data: bytes, out_dir: Path) -> list[str]:
    """Extract web assets found as raw (uncompressed) content in binary."""
    assets_dir = out_dir / 'assets'
    assets_dir.mkdir(parents=True, exist_ok=True)
    extracted = []

    # HTML blocks
    html_blocks = find_html_blocks(data)
    for i, block in enumerate(html_blocks):
        name = f'index.html' if i == 0 else f'page_{i}.html'
        dest = assets_dir / name
        try:
            content = block['data'].decode('utf-8', errors='replace')
            dest.write_text(content, encoding='utf-8')
            extracted.append(name)
            print(f"[+] HTML: {name} ({block['size']} bytes, offset 0x{block['offset']:x})")
        except Exception:
            pass

    # JS blocks (only large ones — small fragments are noise)
    js_blocks = find_js_blocks(data, min_size=1000)
    for i, block in enumerate(js_blocks[:20]):  # cap at 20
        name = f'script_{i}.js' if i > 0 else 'main.js'
        dest = assets_dir / name
        try:
            content = block['data'].rstrip(b'\x00').decode('utf-8', errors='replace')
            dest.write_text(content, encoding='utf-8')
            extracted.append(name)
            print(f"[+] JS: {name} ({block['size']} bytes, offset 0x{block['offset']:x})")
        except Exception:
            pass

    # CSS blocks
    css_blocks = find_css_blocks(data, min_size=200)
    for i, block in enumerate(css_blocks[:10]):
        name = f'style_{i}.css' if i > 0 else 'style.css'
        dest = assets_dir / name
        try:
            content = block['data'].rstrip(b'\x00').decode('utf-8', errors='replace')
            dest.write_text(content, encoding='utf-8')
            extracted.append(name)
            print(f"[+] CSS: {name} ({block['size']} bytes, offset 0x{block['offset']:x})")
        except Exception:
            pass

    return extracted


# --- Main unpack --------------------------------------------------------------

def unpack_tauri(target: Path, out_dir: Path, try_decompress: bool = True) -> dict:
    """Unpack a Tauri app, extracting embedded web assets."""
    result = {
        'target': str(target),
        'tauri': {},
        'config': None,
        'asset_names': [],
        'extracted': [],
        'method': [],
    }

    # Handle macOS .app bundle
    binary_path = target
    if target.is_dir() and target.suffix == '.app':
        print(f"[*] macOS bundle detected: {target.name}")
        binary_path = find_macos_binary(target)
        if not binary_path:
            print("[!] Could not find main binary in .app bundle")
            return result
        print(f"[*] Main binary: {binary_path}")

        # Check Resources directory first
        res_files = check_macos_resources(target, out_dir)
        if res_files:
            result['extracted'].extend(res_files)
            result['method'].append('macos-resources')
            print(f"[+] Found {len(res_files)} files in Resources/")

    # Read binary
    size = binary_path.stat().st_size
    print(f"[*] Reading {binary_path.name} ({size / 1024 / 1024:.1f} MB)")
    data = binary_path.read_bytes()[:MAX_READ]

    # Detect Tauri
    tauri_info = detect_tauri(data)
    result['tauri'] = tauri_info
    if not tauri_info['is_tauri']:
        print("[!] Binary does not appear to be a Tauri app")
        print("[*] Attempting asset extraction anyway...")

    print(f"[*] Tauri version: {tauri_info.get('version', 'unknown')}")
    if tauri_info.get('version_string'):
        print(f"[*] Tauri version string: {tauri_info['version_string']}")

    # Extract Tauri config
    print("[*] Searching for tauri.conf.json...")
    config = find_tauri_config(data)
    if config:
        result['config'] = config
        config_path = out_dir / 'tauri_config.json'
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding='utf-8')
        print(f"[+] Config extracted: {config_path}")

        product = config.get('package', {}).get('productName') or config.get('productName', '')
        if product:
            print(f"[+] Product: {product}")
    else:
        print("[-] No tauri.conf.json found in binary")

    # Discover asset names
    print("[*] Scanning for asset filenames...")
    asset_names = extract_asset_names(data)
    result['asset_names'] = asset_names
    if asset_names:
        print(f"[+] Found {len(asset_names)} asset references: {', '.join(asset_names[:10])}")

    # Try brotli decompression
    if try_decompress and HAS_BROTLI:
        print("[*] Scanning for brotli-compressed assets...")
        brotli_files = try_brotli_regions(data, out_dir)
        if brotli_files:
            result['extracted'].extend(brotli_files)
            result['method'].append('brotli')

    # Extract raw (uncompressed) assets
    print("[*] Scanning for raw web content...")
    raw_files = extract_raw_assets(data, out_dir)
    if raw_files:
        result['extracted'].extend(raw_files)
        result['method'].append('raw')

    # Summary
    total = len(set(result['extracted']))
    if total > 0:
        print(f"\n[+] Extracted {total} assets to {out_dir / 'assets'}")
        print(f"[*] Methods used: {', '.join(result['method'])}")
    else:
        print("\n[-] No assets extracted — assets may be heavily compressed or encrypted")
        print("[*] Try: run rust-binary-analyzer for symbol/module info")
        print("[*] Try: run memory-dumper on running app to capture decrypted assets")

    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Unpack Tauri app — extract embedded web assets")
    ap.add_argument('target', help='Tauri app binary or macOS .app bundle')
    ap.add_argument('--out', required=True, help='Output directory')
    ap.add_argument('--no-decompress', action='store_true', help='Skip brotli decompression')
    ap.add_argument('--json', help='Write result summary to JSON file')
    args = ap.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"[!] Not found: {target}", file=sys.stderr)
        return 1

    out_dir = Path(args.out)
    result = unpack_tauri(target, out_dir, try_decompress=not args.no_decompress)

    if args.json:
        json_path = Path(args.json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
        print(f"[+] Result JSON: {json_path}")

    return 0 if result['extracted'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
