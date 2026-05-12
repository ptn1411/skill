#!/usr/bin/env python3
"""
ida_mcp_analyze.py — Automated binary analysis via IDA Pro MCP server.

Connects to a running IDA Pro instance through the MCP HTTP bridge and extracts:
- Exports and entry points
- Function list with filters
- Pseudo-C decompilation of key functions
- PE section layout via py_eval
- Cross-references for interesting functions

Usage:
    python ida_mcp_analyze.py --url http://127.0.0.1:13337/mcp --out ida_analysis.json
    python ida_mcp_analyze.py --url http://127.0.0.1:13337/mcp --decompile run_code --out ida_analysis.json
    python ida_mcp_analyze.py --url http://127.0.0.1:13337/mcp --filter nuitka --out ida_analysis.json
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path


class IDAMCPClient:
    """HTTP client for IDA Pro MCP JSON-RPC bridge."""

    def __init__(self, base_url: str, timeout: int = 120):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self._id = 0

    def _call(self, tool_name: str, arguments: dict | None = None) -> dict:
        """Call an IDA MCP tool via JSON-RPC tools/call."""
        self._id += 1
        payload = {
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'id': self._id,
            'params': {
                'name': tool_name,
                'arguments': arguments or {},
            },
        }

        body = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            self.base_url,
            data=body,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = json.loads(resp.read().decode('utf-8'))
                if 'error' in raw:
                    return {'error': raw['error']}
                result = raw.get('result', raw)
                # MCP tools/call returns {content: [{type, text}]}
                if isinstance(result, dict) and 'content' in result:
                    texts = [c.get('text', '') for c in result['content'] if c.get('type') == 'text']
                    combined = '\n'.join(texts)
                    try:
                        return json.loads(combined)
                    except (json.JSONDecodeError, ValueError):
                        return {'text': combined}
                return result
        except urllib.error.URLError as e:
            return {'error': f'Connection failed: {e}'}
        except Exception as e:
            return {'error': str(e)}

    def list_tools(self) -> list[str]:
        """List available MCP tools."""
        self._id += 1
        payload = {
            'jsonrpc': '2.0',
            'method': 'tools/list',
            'id': self._id,
            'params': {},
        }
        body = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            self.base_url, data=body,
            headers={'Content-Type': 'application/json'}, method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = json.loads(resp.read().decode('utf-8'))
                tools = raw.get('result', {}).get('tools', [])
                return [t.get('name', '') for t in tools]
        except Exception:
            return []

    def list_functions(self, filt: str = '', offset: int = 0, count: int = 100) -> dict:
        return self._call('list_funcs', {
            'queries': {'filter': filt, 'offset': offset, 'count': count}
        })

    def decompile(self, address_or_name: str) -> dict:
        return self._call('decompile', {'address': address_or_name})

    def py_eval(self, code: str) -> dict:
        return self._call('py_eval', {'code': code})

    def py_exec(self, code: str) -> dict:
        return self._call('py_exec_file', {'code': code})

    def get_xrefs_to(self, address: str) -> dict:
        return self._call('xrefs_to', {'address': address})

    def find_regex(self, pattern: str) -> dict:
        return self._call('find_regex', {'pattern': pattern})

    def survey_binary(self) -> dict:
        return self._call('survey_binary', {})

    def export_funcs(self) -> dict:
        return self._call('export_funcs', {})


PE_SECTION_CODE = """
import idautils, idc, ida_segment
result = []
for seg_ea in idautils.Segments():
    seg = ida_segment.getseg(seg_ea)
    name = idc.get_segm_name(seg_ea)
    result.append({
        'name': name,
        'start': hex(seg.start_ea),
        'end': hex(seg.end_ea),
        'size': seg.size(),
        'perm': seg.perm,
    })
print(repr(result))
"""

BINARY_INFO_CODE = """
import idautils, idc, ida_nalt
info = {
    'filename': idc.get_input_file_path(),
    'md5': ida_nalt.retrieve_input_file_md5().hex() if ida_nalt.retrieve_input_file_md5() else 'N/A',
    'entry_point': hex(idc.get_inf_attr(idc.INF_START_EA)),
    'file_type': idc.get_inf_attr(idc.INF_FILETYPE),
}
print(repr(info))
"""

EXPORTS_CODE = """
import idautils
exports = []
for i, (ea, ordinal, name) in enumerate(idautils.Entries()):
    exports.append({'address': hex(ea), 'ordinal': ordinal, 'name': name})
    if i > 200:
        break
print(repr(exports))
"""

NUITKA_DETECT_CODE = """
import idc, idautils
markers = []
for seg_ea in idautils.Segments():
    name = idc.get_segm_name(seg_ea)
    if name in ('.rdata', '.data'):
        ea = seg_ea
        end = idc.get_segm_end(seg_ea)
        while ea < end and ea < seg_ea + 0x10000:
            s = idc.get_strlit_contents(ea)
            if s:
                text = s.decode('utf-8', errors='ignore')
                if any(kw in text.lower() for kw in ['nuitka', '__compiled__', 'onefile', 'run_code']):
                    markers.append({'address': hex(ea), 'string': text[:200]})
            ea = idc.next_head(ea, end)
print(repr(markers))
"""


def safe_result(result: dict | list | str, key: str = 'text') -> str:
    """Extract text from MCP result, handling various response shapes."""
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        if 'error' in result:
            return f"[ERROR] {result['error']}"
        if key in result:
            return str(result[key])
        return json.dumps(result, indent=2, default=str)
    if isinstance(result, list):
        return json.dumps(result, indent=2, default=str)
    return str(result)


def analyze(client: IDAMCPClient, decompile_targets: list[str],
            func_filter: str, results: dict) -> None:
    """Run full IDA MCP analysis pipeline."""

    # 0. List available tools
    print("[*] Phase 0: Listing MCP tools...")
    tools = client.list_tools()
    results['available_tools'] = tools
    print(f"    {len(tools)} tools available")

    # 1. Binary info via py_eval
    print("[*] Phase 1: Binary metadata...")
    info_result = client.py_eval(BINARY_INFO_CODE)
    results['binary_info'] = info_result
    print(f"    {safe_result(info_result)[:200]}")

    # 2. Exports via py_eval (export_funcs requires addrs param)
    print("[*] Phase 2: Exports...")
    exports_result = client.py_eval(EXPORTS_CODE)
    results['exports'] = exports_result
    print(f"    {safe_result(exports_result)[:300]}")

    # 3. PE sections (IDA-mapped) via py_eval
    print("[*] Phase 3: PE sections (IDA view)...")
    sections_result = client.py_eval(PE_SECTION_CODE)
    results['ida_sections'] = sections_result
    print(f"    {safe_result(sections_result)[:400]}")

    # 4. Function list
    print(f"[*] Phase 4: Functions (filter='{func_filter}')...")
    funcs = client.list_functions(filt=func_filter, count=200)
    results['functions'] = funcs
    text = safe_result(funcs)
    func_count = text.count('"name"') if '"name"' in text else '?'
    print(f"    Functions found: {func_count}")

    # 5. Nuitka markers
    print("[*] Phase 5: Nuitka detection markers...")
    nuitka_result = client.py_eval(NUITKA_DETECT_CODE)
    results['nuitka_markers'] = nuitka_result
    print(f"    {safe_result(nuitka_result)[:300]}")

    # 6. Decompile targets
    results['decompiled'] = {}
    targets_to_decompile = list(decompile_targets)

    # Auto-detect exports to decompile if no explicit targets given
    if not targets_to_decompile:
        exports_text = safe_result(exports_result)
        skip_names = {'DllEntryPoint', 'TlsCallback_0', 'TlsCallback_1', '_DllMainCRTStartup'}
        # Try to parse export names from various result formats
        for name_candidate in ['run_code', 'main', 'PyInit_']:
            if name_candidate in exports_text:
                targets_to_decompile.append(name_candidate)

    if targets_to_decompile:
        print(f"[*] Phase 6: Decompiling {len(targets_to_decompile)} targets...")
        for target in targets_to_decompile:
            print(f"    Decompiling: {target}")
            dec = client.decompile(target)
            results['decompiled'][target] = dec
            dec_text = safe_result(dec)
            if '[ERROR]' not in dec_text:
                print(f"      OK ({len(dec_text)} chars)")
            else:
                print(f"      {dec_text[:100]}")
            time.sleep(0.5)
    else:
        print("[*] Phase 6: No decompile targets identified (specify with --decompile)")


def main():
    ap = argparse.ArgumentParser(description="Analyze binary via IDA Pro MCP server")
    ap.add_argument('--url', default='http://127.0.0.1:13337/mcp',
                    help='IDA MCP server URL (default: http://127.0.0.1:13337/mcp)')
    ap.add_argument('--decompile', action='append', default=[],
                    help='Function name or address to decompile (repeat for multiple)')
    ap.add_argument('--filter', default='', help='Filter string for function listing')
    ap.add_argument('--timeout', type=int, default=120, help='Request timeout in seconds')
    ap.add_argument('--out', default='ida_analysis.json', help='Output JSON file')
    args = ap.parse_args()

    print(f"[*] Connecting to IDA MCP: {args.url}")
    client = IDAMCPClient(args.url, timeout=args.timeout)

    # Quick connectivity check
    tools = client.list_tools()
    if not tools:
        print("[!] Cannot connect to IDA MCP or no tools available.", file=sys.stderr)
        print("[!] Make sure IDA Pro is open with a binary loaded and MCP server is running.")
        sys.exit(1)
    print(f"[+] Connected to IDA MCP ({len(tools)} tools available)")

    results = {'mcp_url': args.url, 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ')}
    analyze(client, args.decompile, args.filter, results)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False, default=str),
                        encoding='utf-8')
    print(f"\n[+] Analysis saved: {out_path}")

    # Summary
    exp_count = len(results.get('exports', [])) if isinstance(results.get('exports'), list) else 0
    dec_count = len(results.get('decompiled', {}))
    print(f"[+] Exports: {exp_count} | Decompiled: {dec_count}")


if __name__ == '__main__':
    main()
