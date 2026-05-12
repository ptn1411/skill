#!/usr/bin/env python3
"""
reconstruct_nuitka_source.py — Reconstruct Python source from Nuitka extracted constants.

Takes the categorized strings JSON from extract_rsrc_strings.py and produces a best-effort
Python source reconstruction. Optionally uses IDA decompilation data for better structure.

The reconstruction pipeline:
1. Import recovery — detect module names → generate import statements
2. Class/function skeleton — detect class/method names → build structure
3. Constant placement — map strings to their likely locations
4. URL/API reconstruction — detect HTTP patterns → rebuild request code
5. GUI detection — tkinter/Qt patterns → rebuild UI code
6. JS/HTML embedding — preserve embedded code blocks verbatim

Usage:
    python reconstruct_nuitka_source.py --strings extracted_strings.json --out reconstructed/
    python reconstruct_nuitka_source.py --strings extracted.json --ida-analysis ida.json --out reconstructed/
    python reconstruct_nuitka_source.py --strings extracted.json --module-name my_app --out reconstructed/
"""

import argparse
import json
import re
import sys
import textwrap
from collections import defaultdict
from pathlib import Path


# ── Import Analysis ───────────────────────────────────────────────────────────

STDLIB_MODULES = {
    'os', 'sys', 'json', 'threading', 'datetime', 'urllib', 'http', 'queue',
    'pathlib', 'subprocess', 'socket', 'ssl', 'hashlib', 'base64', 'struct',
    're', 'io', 'time', 'logging', 'asyncio', 'collections', 'functools',
    'itertools', 'typing', 'dataclasses', 'abc', 'enum', 'multiprocessing',
    'concurrent', 'signal', 'shutil', 'glob', 'tempfile', 'csv', 'sqlite3',
    'xml', 'html', 'email', 'smtplib', 'ftplib', 'argparse', 'configparser',
    'getpass', 'platform', 'uuid', 'traceback', 'inspect', 'copy', 'math',
    'random', 'string', 'textwrap', 'codecs', 'pickle', 'shelve', 'dbm',
    'gzip', 'zipfile', 'tarfile', 'webbrowser', 'pprint', 'warnings',
}

THIRD_PARTY_MODULES = {
    'playwright': 'playwright',
    'pyotp': 'pyotp',
    'requests': 'requests',
    'aiohttp': 'aiohttp',
    'flask': 'flask',
    'django': 'django',
    'fastapi': 'fastapi',
    'selenium': 'selenium',
    'beautifulsoup4': 'bs4',
    'bs4': 'bs4',
    'lxml': 'lxml',
    'pandas': 'pandas',
    'numpy': 'numpy',
    'PIL': 'PIL',
    'cv2': 'cv2',
    'pyautogui': 'pyautogui',
    'pynput': 'pynput',
    'cryptography': 'cryptography',
    'pycryptodome': 'Crypto',
    'paramiko': 'paramiko',
    'psutil': 'psutil',
    'colorama': 'colorama',
    'tqdm': 'tqdm',
    'click': 'click',
    'rich': 'rich',
    'httpx': 'httpx',
}

TKINTER_WIDGETS = {
    'tk', 'ttk', 'Tk', 'Frame', 'Label', 'Button', 'Entry', 'Text',
    'Listbox', 'Canvas', 'Menu', 'Menubutton', 'OptionMenu', 'Scale',
    'Scrollbar', 'Spinbox', 'Toplevel', 'messagebox', 'filedialog',
    'scrolledtext', 'Notebook', 'Treeview', 'Combobox', 'Progressbar',
    'Checkbutton', 'Radiobutton', 'LabelFrame', 'PanedWindow',
}


def recover_imports(categories: dict) -> list[str]:
    """Generate import statements from detected module names and patterns."""
    imports = []
    seen = set()

    import_entries = categories.get('imports', [])
    for entry in import_entries:
        mod = entry['value'].strip()
        if mod in seen:
            continue
        seen.add(mod)

        if mod in STDLIB_MODULES:
            imports.append(f'import {mod}')
        elif mod in THIRD_PARTY_MODULES:
            imports.append(f'import {THIRD_PARTY_MODULES[mod]}')

    # Detect tkinter usage from widget names in functions/constants
    all_values = set()
    for cat in ('functions', 'classes', 'constants'):
        for entry in categories.get(cat, []):
            all_values.add(entry['value'])

    if all_values & TKINTER_WIDGETS:
        if 'tkinter' not in seen:
            imports.insert(0, 'import tkinter as tk')
        if 'ttk' in all_values and 'ttk' not in seen:
            imports.insert(1, 'from tkinter import ttk, messagebox, scrolledtext')

    # Detect playwright
    if any('playwright' in e['value'] for cat in categories.values() for e in cat
           if isinstance(e, dict)):
        if 'playwright' not in seen:
            imports.append('from playwright.sync_api import sync_playwright')

    # Detect pyotp
    if any('totp' in e['value'].lower() or 'pyotp' in e['value'].lower()
           for cat in categories.values() for e in cat if isinstance(e, dict)):
        if 'pyotp' not in seen:
            imports.append('import pyotp')

    return sorted(set(imports), key=lambda x: (
        0 if x.startswith('import ') and x.split()[1].split('.')[0] in STDLIB_MODULES else
        1 if x.startswith('from ') and x.split()[1].split('.')[0] in STDLIB_MODULES else
        2
    ))


# ── Constant Reconstruction ──────────────────────────────────────────────────

def extract_module_constants(categories: dict) -> list[str]:
    """Reconstruct module-level constants from string patterns."""
    constants = []
    seen = set()

    for entry in categories.get('constants', []):
        val = entry['value']
        if val in seen or len(val) < 4:
            continue

        # URL-like constants
        if re.match(r'https?://', val):
            name = re.sub(r'[^a-zA-Z0-9]', '_', val.split('/')[-1] or 'BASE_URL').upper()
            if name.startswith('_'):
                name = 'URL' + name
            constants.append(f'{name} = {val!r}')
            seen.add(val)

        # Port numbers in format "localhost:NNNN"
        port_match = re.search(r'localhost:(\d+)', val)
        if port_match:
            constants.append(f'PORT = {port_match.group(1)}')
            seen.add(val)

    for entry in categories.get('urls', []):
        val = entry['value']
        if val in seen:
            continue
        if 'redirect' in val.lower():
            constants.append(f'REDIRECT_URI = {val!r}')
        elif '/api/' in val:
            endpoint = val.split('/api/')[-1].replace('/', '_').upper()
            constants.append(f'API_{endpoint} = {val!r}')
        seen.add(val)

    return constants


# ── Class/Function Skeleton ───────────────────────────────────────────────────

def detect_classes(categories: dict) -> list[dict]:
    """Detect class definitions from class names and method patterns."""
    classes = []
    class_names = set()

    for entry in categories.get('classes', []):
        name = entry['value']
        if name[0].isupper() and name.isidentifier() and len(name) > 2:
            class_names.add(name)

    # Group methods by likely class ownership
    methods = defaultdict(list)
    func_entries = categories.get('functions', [])

    for entry in func_entries:
        name = entry['value']
        if name.startswith('__') and name.endswith('__'):
            methods['_dunder_'].append(name)
        elif name.startswith('_'):
            methods['_private_'].append(name)
        else:
            methods['_public_'].append(name)

    for cls_name in sorted(class_names):
        classes.append({
            'name': cls_name,
            'methods': [],
            'attributes': [],
        })

    return classes


def detect_functions(categories: dict) -> list[str]:
    """Detect standalone function definitions."""
    functions = []
    skip = {'self', 'cls', 'args', 'kwargs', 'super', 'print', 'len', 'str',
            'int', 'float', 'bool', 'list', 'dict', 'set', 'tuple', 'type',
            'range', 'enumerate', 'zip', 'map', 'filter', 'sorted', 'reversed',
            'open', 'input', 'format', 'repr', 'hash', 'id', 'dir', 'vars',
            'getattr', 'setattr', 'hasattr', 'delattr', 'isinstance', 'issubclass',
            'property', 'staticmethod', 'classmethod', 'lambda'}

    for entry in categories.get('functions', []):
        name = entry['value']
        if name not in skip and name.isidentifier() and not name.startswith('_'):
            functions.append(name)

    return sorted(set(functions))


# ── JS/HTML Block Extraction ─────────────────────────────────────────────────

def extract_code_blocks(categories: dict) -> list[dict]:
    """Extract embedded JavaScript/HTML code blocks as named constants."""
    blocks = []
    for i, entry in enumerate(categories.get('html_js', [])):
        val = entry['value']
        if len(val) > 50:
            if '<' in val and '>' in val:
                name = f'HTML_BLOCK_{i}'
            elif 'function' in val or 'document.' in val or '=>' in val:
                name = f'JS_CODE_{i}'
            else:
                name = f'EMBEDDED_CODE_{i}'
            blocks.append({'name': name, 'value': val})
    return blocks


# ── Error Message Analysis ────────────────────────────────────────────────────

def analyze_error_messages(categories: dict) -> list[str]:
    """Extract error handling patterns from error message strings."""
    comments = []
    for entry in categories.get('error_messages', []):
        val = entry['value']
        comments.append(f'# Error pattern: {val[:120]}')
    return comments


# ── Source Assembly ───────────────────────────────────────────────────────────

def assemble_source(module_name: str, imports: list[str], constants: list[str],
                    code_blocks: list[dict], classes: list[dict],
                    functions: list[str], error_patterns: list[str],
                    format_strings: list[str],
                    ida_data: dict | None = None) -> str:
    """Assemble all pieces into a Python source file."""
    lines = []

    # Header
    lines.append(f'"""')
    lines.append(f'{module_name}.py')
    lines.append(f'Reconstructed from Nuitka-compiled binary by ida-nuitka-reconstructor')
    lines.append(f'"""')
    lines.append('')

    # Imports
    if imports:
        stdlib = [i for i in imports if not any(
            i.endswith(m) or f'import {m}' in i
            for m in THIRD_PARTY_MODULES.values()
        )]
        thirdparty = [i for i in imports if i not in stdlib]

        for imp in stdlib:
            lines.append(imp)
        if stdlib and thirdparty:
            lines.append('')
        for imp in thirdparty:
            lines.append(imp)
        lines.append('')

    # Module-level constants
    if constants:
        lines.append('# ── Constants ─────────────────────────────────────────')
        lines.append('')
        for const in constants:
            lines.append(const)
        lines.append('')

    # Embedded JS/HTML blocks
    if code_blocks:
        lines.append('# ── Embedded Code ─────────────────────────────────────')
        lines.append('')
        for block in code_blocks:
            val = block['value']
            if '\n' in val or len(val) > 80:
                lines.append(f'{block["name"]} = """')
                lines.append(val)
                lines.append('"""')
            else:
                lines.append(f'{block["name"]} = {val!r}')
            lines.append('')

    # Format strings as comments (reveal variable names)
    if format_strings:
        lines.append('# ── Format Strings (reveal variable/logic patterns) ──')
        for fs in format_strings[:30]:
            lines.append(f'# {fs}')
        lines.append('')

    # Functions
    if functions:
        lines.append('# ── Functions ─────────────────────────────────────────')
        lines.append('')
        for func_name in functions:
            lines.append(f'def {func_name}():')
            lines.append(f'    """TODO: Reconstruct from decompilation."""')
            lines.append(f'    ...')
            lines.append('')

    # Classes
    if classes:
        lines.append('# ── Classes ───────────────────────────────────────────')
        lines.append('')
        for cls in classes:
            lines.append(f'class {cls["name"]}:')
            if cls.get('methods'):
                for method in cls['methods']:
                    lines.append(f'    def {method}(self):')
                    lines.append(f'        ...')
                    lines.append('')
            else:
                lines.append(f'    """TODO: Reconstruct methods from decompilation."""')
                lines.append(f'    ...')
            lines.append('')

    # IDA decompilation hints
    if ida_data and 'decompiled' in ida_data:
        lines.append('# ── IDA Decompilation (pseudo-C → Python hints) ─────')
        lines.append('')
        for func_name, dec_data in ida_data['decompiled'].items():
            lines.append(f'# --- {func_name} ---')
            dec_str = str(dec_data)
            for line in dec_str.split('\n')[:30]:
                lines.append(f'# {line}')
            lines.append('')

    # Error patterns
    if error_patterns:
        lines.append('# ── Error Patterns ────────────────────────────────────')
        for ep in error_patterns[:20]:
            lines.append(ep)
        lines.append('')

    # Entry point
    lines.append('')
    lines.append('if __name__ == "__main__":')
    lines.append('    pass  # TODO: Reconstruct main() entry point')
    lines.append('')

    return '\n'.join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Reconstruct Python source from Nuitka extracted constants"
    )
    ap.add_argument('--strings', required=True, help='Extracted strings JSON from extract_rsrc_strings.py')
    ap.add_argument('--ida-analysis', help='Optional IDA analysis JSON for structure hints')
    ap.add_argument('--module-name', default=None, help='Output module name (default: from binary name)')
    ap.add_argument('--out', default='reconstructed', help='Output directory')
    args = ap.parse_args()

    strings_path = Path(args.strings)
    if not strings_path.exists():
        print(f"[!] Strings file not found: {strings_path}", file=sys.stderr)
        sys.exit(1)

    data = json.loads(strings_path.read_text(encoding='utf-8'))
    categories = data.get('categories', {})

    module_name = args.module_name or data.get('binary', 'module').rsplit('.', 1)[0]
    print(f"[*] Reconstructing: {module_name}")
    print(f"[*] Total strings: {data.get('total_strings', 0)}")

    # Load IDA data if available
    ida_data = None
    if args.ida_analysis:
        ida_path = Path(args.ida_analysis)
        if ida_path.exists():
            ida_data = json.loads(ida_path.read_text(encoding='utf-8'))
            print(f"[*] IDA analysis loaded: {len(ida_data.get('decompiled', {}))} decompiled functions")

    # Pipeline
    print("[*] Phase 1: Recovering imports...")
    imports = recover_imports(categories)
    print(f"    Found {len(imports)} imports")

    print("[*] Phase 2: Extracting constants...")
    constants = extract_module_constants(categories)
    print(f"    Found {len(constants)} constants")

    print("[*] Phase 3: Extracting code blocks...")
    code_blocks = extract_code_blocks(categories)
    print(f"    Found {len(code_blocks)} embedded code blocks")

    print("[*] Phase 4: Detecting classes...")
    classes = detect_classes(categories)
    print(f"    Found {len(classes)} classes")

    print("[*] Phase 5: Detecting functions...")
    functions = detect_functions(categories)
    print(f"    Found {len(functions)} functions")

    print("[*] Phase 6: Analyzing error patterns...")
    error_patterns = analyze_error_messages(categories)
    print(f"    Found {len(error_patterns)} error patterns")

    # Format strings (reveal variable names)
    format_strings = [e['value'] for e in categories.get('format_strings', [])]

    # Assemble
    print("[*] Assembling source...")
    source = assemble_source(
        module_name, imports, constants, code_blocks,
        classes, functions, error_patterns, format_strings,
        ida_data,
    )

    # Write output
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f'{module_name}.py'
    out_file.write_text(source, encoding='utf-8')

    # Also write a strings dump for manual review
    dump_file = out_dir / f'{module_name}_strings.txt'
    dump_lines = []
    for cat_name, entries in categories.items():
        if not entries:
            continue
        dump_lines.append(f"\n{'='*60}")
        dump_lines.append(f"  {cat_name.upper()} ({len(entries)})")
        dump_lines.append(f"{'='*60}")
        for e in entries:
            v = e['value'][:300].replace('\n', '\\n')
            dump_lines.append(f"  {v}")
    dump_file.write_text('\n'.join(dump_lines), encoding='utf-8')

    # Summary
    line_count = source.count('\n')
    print(f"\n[+] Source written: {out_file} ({line_count} lines)")
    print(f"[+] Strings dump: {dump_file}")
    print(f"\n[+] Reconstruction summary:")
    print(f"    Imports    : {len(imports)}")
    print(f"    Constants  : {len(constants)}")
    print(f"    Code blocks: {len(code_blocks)}")
    print(f"    Classes    : {len(classes)}")
    print(f"    Functions  : {len(functions)}")
    print(f"    Errors     : {len(error_patterns)}")
    print(f"    Total lines: {line_count}")


if __name__ == '__main__':
    main()
