#!/usr/bin/env python3
"""
analyze_rust.py — Analyse a Rust native binary without disassembly.

Extracts symbols, panic paths, framework hints, and license-related functions
from the raw binary to build a high-level map of the application.

Usage:
    python analyze_rust.py target.exe --out output/rust-analysis
    python analyze_rust.py target.exe --json output/rust_info.json
    python analyze_rust.py target.exe --symbols-only
"""

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


MIN_STR_LEN = 4
MAX_READ = 256 * 1024 * 1024  # 256 MB cap


# --- String extraction -------------------------------------------------------

def extract_strings(data: bytes, min_len: int = MIN_STR_LEN) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
    return [m.group().decode('ascii', errors='replace') for m in pattern.finditer(data)]


def extract_utf8_strings(data: bytes, min_len: int = MIN_STR_LEN) -> list[str]:
    """Extract valid UTF-8 strings (for Rust string literals)."""
    results = []
    pattern = re.compile(rb'[\x20-\x7e\xc0-\xfd][\x20-\x7e\x80-\xbf]{%d,}' % (min_len - 1))
    for m in pattern.finditer(data):
        try:
            s = m.group().decode('utf-8')
            if len(s) >= min_len:
                results.append(s)
        except UnicodeDecodeError:
            pass
    return results


# --- Rust detection -----------------------------------------------------------

RUST_INDICATORS = [
    'core::panicking::panic',
    'std::rt::lang_start',
    'core::fmt::',
    'core::result::Result',
    'core::option::Option',
    'alloc::string::String',
    'alloc::vec::Vec',
    'std::io::',
    'core::slice::',
    'core::ptr::',
    'rustc_demangle',
    '.rs:',
    'panicked at',
    'rust_begin_unwind',
    'rust_panic',
]

def detect_rust(strings: list[str]) -> dict:
    """Detect if binary is Rust-compiled and gather evidence."""
    evidence = []
    for s in strings:
        for indicator in RUST_INDICATORS:
            if indicator in s:
                evidence.append({'indicator': indicator, 'context': s[:120]})
                break

    rustc_version = None
    for s in strings:
        m = re.search(r'rustc\s+(\d+\.\d+\.\d+)', s)
        if m:
            rustc_version = m.group(1)
            break

    return {
        'is_rust': len(evidence) >= 3,
        'confidence': min(len(evidence) / 5.0, 1.0),
        'evidence_count': len(evidence),
        'rustc_version': rustc_version,
        'evidence': evidence[:20],
    }


# --- Symbol demangling --------------------------------------------------------

def demangle_legacy(mangled: str) -> str | None:
    """Demangle Rust legacy mangling (_ZN...)."""
    if not mangled.startswith('_ZN'):
        return None
    rest = mangled[3:]
    parts = []
    i = 0
    while i < len(rest):
        if rest[i] == 'E':
            break
        if not rest[i].isdigit():
            return None
        j = i
        while j < len(rest) and rest[j].isdigit():
            j += 1
        length = int(rest[i:j])
        name = rest[j:j + length]
        if len(name) < length:
            return None
        # strip hash suffix (h followed by 16 hex chars)
        if re.match(r'^h[0-9a-f]{16}$', name):
            i = j + length
            continue
        parts.append(name)
        i = j + length
    return '::'.join(parts) if parts else None


def demangle_v0(mangled: str) -> str | None:
    """Basic Rust v0 demangling (_R...)."""
    if not mangled.startswith('_R'):
        return None
    # v0 mangling is complex; try external tool first, basic fallback
    return None  # defer to rustfilt


def demangle_symbol(mangled: str) -> str:
    """Demangle a single Rust symbol."""
    result = demangle_legacy(mangled)
    if result:
        return result
    result = demangle_v0(mangled)
    if result:
        return result
    return mangled


def demangle_with_rustfilt(symbols: list[str]) -> dict[str, str]:
    """Use rustfilt for demangling if available."""
    rustfilt = shutil.which('rustfilt') or shutil.which('rust-demangler')
    if not rustfilt:
        return {}

    try:
        proc = subprocess.run(
            [rustfilt],
            input='\n'.join(symbols),
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode == 0:
            demangled = proc.stdout.strip().split('\n')
            return {s: d for s, d in zip(symbols, demangled) if s != d}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return {}


def extract_symbols(strings: list[str]) -> list[dict]:
    """Find and demangle Rust symbols from string table."""
    rust_sym_re = re.compile(r'(_ZN\d+\w+E|_R[A-Z]\w+)')
    mangled = []
    for s in strings:
        for m in rust_sym_re.finditer(s):
            mangled.append(m.group())

    # Try external demangler first
    ext_demangled = demangle_with_rustfilt(mangled)

    results = []
    seen = set()
    for sym in mangled:
        if sym in seen:
            continue
        seen.add(sym)
        if sym in ext_demangled:
            demangled = ext_demangled[sym]
        else:
            demangled = demangle_symbol(sym)

        results.append({
            'mangled': sym,
            'demangled': demangled,
            'is_demangled': demangled != sym,
        })

    return results


# --- Panic path extraction ----------------------------------------------------

def extract_panic_paths(strings: list[str]) -> list[dict]:
    """Extract panic strings that reveal source file paths."""
    panic_re = re.compile(
        r'(?:panicked at [\'"].*?[\'"],\s*)?'
        r'((?:[\w./-]+/)?[\w.-]+\.rs)'
        r':(\d+)(?::(\d+))?'
    )
    alt_re = re.compile(r'((?:src|lib|crates?|modules?)/[\w./-]+\.rs)')

    paths = []
    seen = set()

    for s in strings:
        for m in panic_re.finditer(s):
            path = m.group(1)
            line = int(m.group(2))
            col = int(m.group(3)) if m.group(3) else None
            key = (path, line)
            if key not in seen:
                seen.add(key)
                is_panic = 'panicked' in s or 'panic' in s.lower()
                paths.append({
                    'file': path,
                    'line': line,
                    'col': col,
                    'is_panic': is_panic,
                    'context': s[:200],
                })

        for m in alt_re.finditer(s):
            path = m.group(1)
            key = (path, 0)
            if key not in seen:
                seen.add(key)
                paths.append({
                    'file': path,
                    'line': 0,
                    'col': None,
                    'is_panic': False,
                    'context': s[:200],
                })

    return paths


def build_module_tree(panic_paths: list[dict]) -> dict:
    """Build a module hierarchy from panic source paths."""
    tree: dict = {}
    for entry in panic_paths:
        parts = entry['file'].replace('\\', '/').split('/')
        node = tree
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        filename = parts[-1]
        if filename not in node:
            node[filename] = {'_lines': []}
        if isinstance(node[filename], dict) and entry['line'] > 0:
            node[filename].setdefault('_lines', []).append(entry['line'])
    return tree


def format_tree(tree: dict, prefix: str = '') -> list[str]:
    """Format module tree as indented text."""
    lines = []
    items = sorted(tree.items())
    for i, (name, subtree) in enumerate(items):
        is_last = (i == len(items) - 1)
        connector = '+-- ' if is_last else '|-- '
        if name == '_lines':
            continue
        if isinstance(subtree, dict) and set(subtree.keys()) == {'_lines'}:
            line_info = f" (lines: {', '.join(map(str, sorted(subtree['_lines'])[:10]))})" if subtree['_lines'] else ''
            lines.append(f"{prefix}{connector}{name}{line_info}")
        elif isinstance(subtree, dict):
            lines.append(f"{prefix}{connector}{name}/")
            extension = '    ' if is_last else '|   '
            lines.extend(format_tree(subtree, prefix + extension))
        else:
            lines.append(f"{prefix}{connector}{name}")
    return lines


# --- Framework detection ------------------------------------------------------

FRAMEWORK_SIGNATURES = {
    'tauri': {
        'strings': ['tauri', '__TAURI__', 'tauri::app', 'tauri::command', 'tauri_runtime',
                     'tauri::plugin', 'tauri.conf.json', 'devPath', 'distDir'],
        'type': 'desktop-webview',
    },
    'actix-web': {
        'strings': ['actix_web', 'actix::actor', 'HttpServer', 'actix_rt'],
        'type': 'web-server',
    },
    'axum': {
        'strings': ['axum::Router', 'axum::extract', 'axum::routing', 'axum::handler'],
        'type': 'web-server',
    },
    'rocket': {
        'strings': ['rocket::Rocket', 'rocket::route', '#[get(', '#[post('],
        'type': 'web-server',
    },
    'warp': {
        'strings': ['warp::Filter', 'warp::serve', 'warp::path'],
        'type': 'web-server',
    },
    'tokio': {
        'strings': ['tokio::runtime', 'tokio::spawn', 'tokio::sync', 'tokio::net'],
        'type': 'async-runtime',
    },
    'reqwest': {
        'strings': ['reqwest::Client', 'reqwest::blocking', 'reqwest::Url'],
        'type': 'http-client',
    },
    'serde': {
        'strings': ['serde::Deserialize', 'serde::Serialize', 'serde_json'],
        'type': 'serialization',
    },
    'clap': {
        'strings': ['clap::App', 'clap::Arg', 'clap::Command', 'clap_derive'],
        'type': 'cli',
    },
    'diesel': {
        'strings': ['diesel::query_builder', 'diesel::connection', 'diesel::pg'],
        'type': 'orm',
    },
    'sqlx': {
        'strings': ['sqlx::query', 'sqlx::Pool', 'sqlx::sqlite', 'sqlx::postgres'],
        'type': 'database',
    },
}


def detect_frameworks(strings: list[str]) -> list[dict]:
    """Detect Rust frameworks/crates used in the binary."""
    string_set = '\n'.join(strings)
    detected = []

    for name, info in FRAMEWORK_SIGNATURES.items():
        matches = []
        for sig in info['strings']:
            if sig in string_set:
                matches.append(sig)
        if matches:
            detected.append({
                'name': name,
                'type': info['type'],
                'confidence': min(len(matches) / len(info['strings']), 1.0),
                'matched_signatures': matches,
            })

    detected.sort(key=lambda x: x['confidence'], reverse=True)
    return detected


# --- Crate detection ----------------------------------------------------------

def detect_crates(strings: list[str], symbols: list[dict]) -> list[str]:
    """Detect linked crates from symbols and strings."""
    crate_re = re.compile(r'(?:^|::)([\w_]+)(?:::[\w_]+)+')
    crate_names = set()

    for sym in symbols:
        name = sym['demangled']
        m = crate_re.match(name)
        if m:
            crate = m.group(1)
            if crate not in ('core', 'std', 'alloc', 'compiler_builtins'):
                crate_names.add(crate)

    # Also check Cargo.toml references in strings
    cargo_re = re.compile(r'registry/src/[^/]+/([a-z_][\w-]*)-\d+\.\d+')
    for s in strings:
        m = cargo_re.search(s)
        if m:
            crate_names.add(m.group(1))

    return sorted(crate_names)


# --- License function detection -----------------------------------------------

LICENSE_KEYWORDS = [
    'license', 'licence', 'serial', 'activate', 'activation',
    'register', 'registration', 'validate', 'verify', 'check_key',
    'trial', 'expire', 'expiry', 'expiration', 'subscription',
    'premium', 'pro_version', 'is_licensed', 'is_registered',
    'is_activated', 'check_license', 'validate_license', 'key_valid',
    'hwid', 'machine_id', 'hardware_id', 'fingerprint',
]

LICENSE_STRING_PATTERNS = [
    r'(?i)invalid\s*(license|key|serial|registration)',
    r'(?i)(license|key|serial)\s*expired',
    r'(?i)trial\s*(period|version|expired|ended)',
    r'(?i)(enter|input|provide)\s*(your\s*)?(license|key|serial)',
    r'(?i)activation\s*(code|key|server|failed|successful)',
    r'(?i)(registered|licensed)\s*to',
    r'(?i)days?\s*remaining',
    r'(?i)purchase\s*(a\s*)?(license|key|subscription)',
]


def find_license_functions(symbols: list[dict], strings: list[str]) -> dict:
    """Find symbols and strings related to licensing."""
    # Symbol matches
    func_matches = []
    for sym in symbols:
        name_lower = sym['demangled'].lower()
        for kw in LICENSE_KEYWORDS:
            if kw in name_lower:
                func_matches.append({
                    'symbol': sym['demangled'],
                    'mangled': sym['mangled'],
                    'keyword': kw,
                })
                break

    # String matches
    str_matches = []
    for s in strings:
        for pattern in LICENSE_STRING_PATTERNS:
            if re.search(pattern, s):
                str_matches.append({
                    'string': s[:200],
                    'pattern': pattern,
                })
                break

    return {
        'functions': func_matches,
        'strings': str_matches,
        'has_licensing': bool(func_matches or str_matches),
    }


# --- PE info ------------------------------------------------------------------

def read_pe_info(data: bytes) -> dict | None:
    """Read basic PE information."""
    if data[:2] != b'MZ':
        return None

    try:
        pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
        if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
            return None

        machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
        machines = {0x14c: 'x86', 0x8664: 'x86_64', 0xaa64: 'ARM64'}

        num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
        timestamp = struct.unpack_from('<I', data, pe_offset + 8)[0]

        # Check if PE32 or PE32+
        magic = struct.unpack_from('<H', data, pe_offset + 24)[0]
        is_64 = magic == 0x20b

        return {
            'format': 'PE',
            'arch': machines.get(machine, f'0x{machine:04x}'),
            'bits': 64 if is_64 else 32,
            'sections': num_sections,
            'timestamp': timestamp,
        }
    except (struct.error, IndexError):
        return None


def read_elf_info(data: bytes) -> dict | None:
    """Read basic ELF information."""
    if data[:4] != b'\x7fELF':
        return None

    try:
        ei_class = data[4]  # 1=32bit, 2=64bit
        ei_data = data[5]   # 1=LE, 2=BE
        e_type = struct.unpack_from('<H' if ei_data == 1 else '>H', data, 16)[0]
        e_machine = struct.unpack_from('<H' if ei_data == 1 else '>H', data, 18)[0]

        machines = {0x03: 'x86', 0x3e: 'x86_64', 0xb7: 'ARM64', 0x28: 'ARM'}
        types = {2: 'EXEC', 3: 'DYN (shared/PIE)'}

        return {
            'format': 'ELF',
            'arch': machines.get(e_machine, f'0x{e_machine:04x}'),
            'bits': 64 if ei_class == 2 else 32,
            'type': types.get(e_type, f'0x{e_type:04x}'),
            'endian': 'little' if ei_data == 1 else 'big',
        }
    except (struct.error, IndexError):
        return None


# --- Main analysis ------------------------------------------------------------

def analyze_binary(filepath: Path) -> dict:
    """Full Rust binary analysis."""
    size = filepath.stat().st_size
    read_size = min(size, MAX_READ)

    print(f"[*] Reading {filepath.name} ({size / 1024 / 1024:.1f} MB)")
    data = filepath.read_bytes()[:read_size]

    # Binary format
    pe_info = read_pe_info(data)
    elf_info = read_elf_info(data)
    binary_info = pe_info or elf_info or {'format': 'unknown'}

    print(f"[*] Format: {binary_info.get('format')} {binary_info.get('arch', '')}")

    # Extract strings
    print("[*] Extracting strings...")
    strings = extract_strings(data)
    utf8_strings = extract_utf8_strings(data)
    all_strings = list(set(strings + utf8_strings))
    print(f"[+] Found {len(all_strings)} unique strings")

    # Detect Rust
    rust_info = detect_rust(all_strings)
    print(f"[*] Rust detection: {rust_info['is_rust']} (confidence: {rust_info['confidence']:.0%})")
    if rust_info['rustc_version']:
        print(f"[+] rustc version: {rust_info['rustc_version']}")

    # Symbols
    print("[*] Extracting symbols...")
    symbols = extract_symbols(all_strings)
    demangled_count = sum(1 for s in symbols if s['is_demangled'])
    print(f"[+] Found {len(symbols)} symbols ({demangled_count} demangled)")

    # Panic paths
    print("[*] Extracting panic paths...")
    panic_paths = extract_panic_paths(all_strings)
    print(f"[+] Found {len(panic_paths)} source paths")

    module_tree = build_module_tree(panic_paths)

    # Frameworks
    print("[*] Detecting frameworks...")
    frameworks = detect_frameworks(all_strings)
    for fw in frameworks:
        print(f"[+] Framework: {fw['name']} ({fw['type']}, confidence: {fw['confidence']:.0%})")

    # Crates
    crates = detect_crates(all_strings, symbols)
    if crates:
        print(f"[+] Detected crates: {', '.join(crates[:15])}")

    # License
    print("[*] Scanning for license logic...")
    license_info = find_license_functions(symbols, all_strings)
    if license_info['has_licensing']:
        print(f"[+] Found {len(license_info['functions'])} license functions, "
              f"{len(license_info['strings'])} license strings")
    else:
        print("[-] No obvious license logic detected")

    # Tauri detection
    is_tauri = any(fw['name'] == 'tauri' for fw in frameworks)
    if is_tauri:
        print("[+] Tauri app detected - chain tauri-unpacker for frontend assets")

    return {
        'file': str(filepath),
        'size': size,
        'binary': binary_info,
        'rust': rust_info,
        'symbols': {
            'total': len(symbols),
            'demangled': demangled_count,
            'items': symbols[:500],
        },
        'panic_paths': {
            'total': len(panic_paths),
            'items': panic_paths,
        },
        'module_tree': module_tree,
        'frameworks': frameworks,
        'crates': crates,
        'license': license_info,
        'is_tauri': is_tauri,
        'recommendations': build_recommendations(rust_info, frameworks, license_info, is_tauri),
    }


def build_recommendations(rust: dict, frameworks: list, license: dict, is_tauri: bool) -> list[str]:
    """Build actionable recommendations based on analysis."""
    recs = []

    if not rust['is_rust']:
        recs.append("Binary may not be Rust — verify with binary-identifier")
        return recs

    if is_tauri:
        recs.append("Run tauri-unpacker to extract embedded web assets (HTML/JS/CSS)")
        recs.append("Frontend JS likely contains license UI and IPC commands")

    if license['has_licensing']:
        recs.append("License logic detected — use IDA/Ghidra to trace validation flow")
        if license['functions']:
            top = license['functions'][0]['symbol']
            recs.append(f"Start analysis at: {top}")

    web_frameworks = [fw for fw in frameworks if fw['type'] == 'web-server']
    if web_frameworks:
        recs.append(f"Web server ({web_frameworks[0]['name']}) — run network-interceptor for API analysis")

    if any(fw['name'] == 'reqwest' for fw in frameworks):
        recs.append("HTTP client (reqwest) detected — app makes network calls, intercept with mitmproxy")

    if not license['has_licensing'] and not is_tauri:
        recs.append("No obvious license logic — try memory-dumper at runtime for decrypted secrets")
        recs.append("Use frida-hooker with function_tracer template for dynamic analysis")

    return recs


# --- Output -------------------------------------------------------------------

def write_outputs(analysis: dict, out_dir: Path):
    """Write analysis results to files."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # JSON report
    json_path = out_dir / 'rust_info.json'
    json_path.write_text(json.dumps(analysis, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"[+] Full analysis: {json_path}")

    # Demangled symbols
    sym_path = out_dir / 'demangled_symbols.txt'
    lines = []
    for sym in analysis['symbols']['items']:
        if sym['is_demangled']:
            lines.append(f"{sym['demangled']}")
        else:
            lines.append(f"{sym['mangled']}  (not demangled)")
    sym_path.write_text('\n'.join(lines), encoding='utf-8')
    print(f"[+] Symbols: {sym_path} ({len(lines)} entries)")

    # Module tree
    tree_path = out_dir / 'module_tree.txt'
    tree_lines = format_tree(analysis['module_tree'])
    if tree_lines:
        tree_path.write_text('\n'.join(tree_lines), encoding='utf-8')
        print(f"[+] Module tree: {tree_path}")
    else:
        print("[-] No module tree (no panic paths found)")

    # License targets
    if analysis['license']['has_licensing']:
        lic_path = out_dir / 'license_targets.txt'
        lines = ["# License-related functions", ""]
        for f in analysis['license']['functions']:
            lines.append(f"[func] {f['symbol']}  (keyword: {f['keyword']})")
        lines.append("")
        lines.append("# License-related strings")
        lines.append("")
        for s in analysis['license']['strings']:
            lines.append(f"[str] {s['string']}")
        lic_path.write_text('\n'.join(lines), encoding='utf-8')
        print(f"[+] License targets: {lic_path}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyse a Rust native binary")
    ap.add_argument('target', help='Path to Rust binary')
    ap.add_argument('--out', help='Output directory for analysis results')
    ap.add_argument('--json', help='Output single JSON file (alternative to --out)')
    ap.add_argument('--symbols-only', action='store_true', help='Only extract and demangle symbols')
    args = ap.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"[!] Not found: {target}", file=sys.stderr)
        return 1

    if args.symbols_only:
        data = target.read_bytes()[:MAX_READ]
        strings = extract_strings(data)
        symbols = extract_symbols(strings)
        for sym in symbols:
            print(f"{sym['demangled']}" if sym['is_demangled'] else f"{sym['mangled']}")
        return 0

    analysis = analyze_binary(target)

    # Print summary
    print(f"\n{'=' * 60}")
    print(f"[+] Summary for {target.name}")
    print(f"    Rust: {'Yes' if analysis['rust']['is_rust'] else 'Maybe'} "
          f"(confidence: {analysis['rust']['confidence']:.0%})")
    print(f"    Symbols: {analysis['symbols']['total']} "
          f"({analysis['symbols']['demangled']} demangled)")
    print(f"    Source paths: {analysis['panic_paths']['total']}")
    print(f"    Frameworks: {', '.join(fw['name'] for fw in analysis['frameworks']) or 'none'}")
    print(f"    Crates: {len(analysis['crates'])}")
    print(f"    License logic: {'Yes' if analysis['license']['has_licensing'] else 'No'}")

    if analysis['recommendations']:
        print(f"\n[*] Recommendations:")
        for rec in analysis['recommendations']:
            print(f"    -> {rec}")

    if args.out:
        write_outputs(analysis, Path(args.out))
    elif args.json:
        json_path = Path(args.json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(analysis, indent=2, ensure_ascii=False), encoding='utf-8')
        print(f"\n[+] JSON: {json_path}")
    else:
        print("\n[*] Use --out or --json to save results")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
