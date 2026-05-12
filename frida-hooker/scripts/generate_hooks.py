#!/usr/bin/env python3
"""
generate_hooks.py — Generate Frida hook scripts from templates or IDA exports.

Templates: license_bypass, ssl_pinning_bypass, function_tracer,
           crypto_intercept, anti_debug_bypass.
IDA export: JSON with function name/address pairs → targeted Frida hooks.

Usage:
    python generate_hooks.py --template license_bypass --out hooks/bypass.js
    python generate_hooks.py --template function_tracer --target-module "app.dll" --out hooks/trace.js
    python generate_hooks.py --ida-export funcs.json --filter "license,check" --out hooks/targeted.js
    python generate_hooks.py --address 0x140001234 --module "target.exe" --out hooks/custom.js
"""

import argparse
import json
import sys
from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent.parent / 'templates'

AVAILABLE_TEMPLATES = [
    'license_bypass',
    'ssl_pinning_bypass',
    'function_tracer',
    'crypto_intercept',
    'anti_debug_bypass',
]


def load_template(name: str) -> str:
    """Load a JS template file."""
    path = TEMPLATES_DIR / f'{name}.js'
    if not path.exists():
        print(f"[!] Template not found: {path}", file=sys.stderr)
        return ''
    return path.read_text(encoding='utf-8')


def customize_template(template: str, target_module: str | None = None,
                       addresses: list[str] | None = None) -> str:
    """Apply customizations to a template."""
    if target_module:
        template = template.replace('TARGET_MODULE', target_module)
        template = template.replace("'target.exe'", f"'{target_module}'")
        template = template.replace("'target.dll'", f"'{target_module}'")

    if addresses:
        addr_lines = []
        for addr in addresses:
            addr_lines.append(f"    ptr('{addr}'),")
        addr_block = '\n'.join(addr_lines)
        template = template.replace('// CUSTOM_ADDRESSES', addr_block)

    return template


def generate_from_ida_export(export_path: Path, filter_keywords: list[str],
                             target_module: str | None = None) -> str:
    """Generate hook script from IDA function export."""
    data = json.loads(export_path.read_text(encoding='utf-8'))

    functions = []
    if isinstance(data, list):
        functions = data
    elif isinstance(data, dict):
        for name, addr in data.items():
            functions.append({'name': name, 'address': addr})

    if filter_keywords:
        filtered = []
        for func in functions:
            name = func.get('name', '').lower()
            if any(kw.lower() in name for kw in filter_keywords):
                filtered.append(func)
        functions = filtered

    if not functions:
        print("[!] No matching functions found in IDA export", file=sys.stderr)
        return ''

    print(f"[*] Generating hooks for {len(functions)} functions")

    lines = [
        "'use strict';",
        "",
        "// Auto-generated from IDA export",
        f"// Functions: {len(functions)}",
        "",
    ]

    if target_module:
        lines.append(f"const baseAddr = Module.findBaseAddress('{target_module}');")
        lines.append("if (!baseAddr) {")
        lines.append(f"    console.log('[!] Module not found: {target_module}');")
        lines.append("}")
        lines.append("")

    for func in functions:
        name = func.get('name', 'unknown')
        addr = func.get('address', '0x0')
        if isinstance(addr, int):
            addr = hex(addr)

        safe_name = name.replace("'", "\\'")

        if target_module:
            lines.extend([
                f"// Hook: {name} @ {addr}",
                "if (baseAddr) {",
                f"    const addr_{name[:30]} = baseAddr.add({addr});",
                f"    Interceptor.attach(addr_{name[:30]}, {{",
                f"        onEnter(args) {{",
                f"            console.log('[CALL] {safe_name}');",
                f"            console.log('  arg0: ' + args[0]);",
                f"            console.log('  arg1: ' + args[1]);",
                f"            console.log('  arg2: ' + args[2]);",
                f"        }},",
                f"        onLeave(retval) {{",
                f"            console.log('[RET]  {safe_name} => ' + retval);",
                f"        }}",
                f"    }});",
                "}",
                "",
            ])
        else:
            lines.extend([
                f"// Hook: {name} @ {addr}",
                f"Interceptor.attach(ptr('{addr}'), {{",
                f"    onEnter(args) {{",
                f"        console.log('[CALL] {safe_name}');",
                f"        console.log('  arg0: ' + args[0]);",
                f"        console.log('  arg1: ' + args[1]);",
                f"    }},",
                f"    onLeave(retval) {{",
                f"        console.log('[RET]  {safe_name} => ' + retval);",
                f"    }}",
                f"}});",
                "",
            ])

    lines.append("console.log('[+] All hooks installed');")
    return '\n'.join(lines)


def generate_address_hook(address: str, module: str | None = None) -> str:
    """Generate a simple hook for a specific address."""
    lines = [
        "'use strict';",
        "",
        f"// Custom hook at {address}",
        "",
    ]

    if module:
        lines.extend([
            f"const base = Module.findBaseAddress('{module}');",
            f"const target = base.add({address});",
            "",
            "Interceptor.attach(target, {",
        ])
    else:
        lines.extend([
            f"Interceptor.attach(ptr('{address}'), {{",
        ])

    lines.extend([
        "    onEnter(args) {",
        f"        console.log('[CALL] {address}');",
        "        console.log('  arg0: ' + args[0]);",
        "        console.log('  arg1: ' + args[1]);",
        "        console.log('  arg2: ' + args[2]);",
        "        console.log('  arg3: ' + args[3]);",
        "        // Dump first arg as string (if pointer to string)",
        "        try {",
        "            const s = args[0].readUtf8String();",
        "            if (s) console.log('  arg0_str: ' + s.substring(0, 200));",
        "        } catch(e) {}",
        "        try {",
        "            const s = args[0].readUtf16String();",
        "            if (s) console.log('  arg0_utf16: ' + s.substring(0, 200));",
        "        } catch(e) {}",
        "    },",
        "    onLeave(retval) {",
        f"        console.log('[RET]  {address} => ' + retval);",
        "    }",
        "});",
        "",
        f"console.log('[+] Hook installed at {address}');",
    ])

    return '\n'.join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate Frida hook scripts")
    ap.add_argument('--template', choices=AVAILABLE_TEMPLATES,
                    help='Use a built-in template')
    ap.add_argument('--ida-export', help='Generate from IDA JSON export')
    ap.add_argument('--address', help='Hook a specific address (hex)')
    ap.add_argument('--module', '--target-module', dest='module',
                    help='Target module name (e.g., "app.dll")')
    ap.add_argument('--filter', help='Comma-separated keywords to filter IDA functions')
    ap.add_argument('--out', help='Output JS file')
    ap.add_argument('--list', action='store_true', help='List available templates')
    args = ap.parse_args()

    if args.list:
        print("[*] Available templates:")
        for t in AVAILABLE_TEMPLATES:
            path = TEMPLATES_DIR / f'{t}.js'
            exists = "+" if path.exists() else "-"
            print(f"    [{exists}] {t}")
        return 0

    if not args.out:
        print("[!] --out is required (unless --list)", file=sys.stderr)
        return 1

    script = ''

    if args.template:
        print(f"[*] Loading template: {args.template}")
        script = load_template(args.template)
        if not script:
            return 1
        script = customize_template(script, args.module)
        print(f"[+] Template loaded ({len(script)} bytes)")

    elif args.ida_export:
        export_path = Path(args.ida_export)
        if not export_path.exists():
            print(f"[!] Not found: {export_path}", file=sys.stderr)
            return 1
        filters = [f.strip() for f in args.filter.split(',')] if args.filter else []
        script = generate_from_ida_export(export_path, filters, args.module)
        if not script:
            return 1

    elif args.address:
        print(f"[*] Generating hook for address: {args.address}")
        script = generate_address_hook(args.address, args.module)

    else:
        print("[!] Specify --template, --ida-export, or --address", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(script, encoding='utf-8')
    print(f"[+] Hook script: {out_path}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
