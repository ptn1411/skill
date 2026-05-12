#!/usr/bin/env python3
"""
analyze_tauri.py — Analyse extracted Tauri frontend assets.

Scans JS/HTML for IPC commands (invoke/listen/emit), API endpoints,
license logic, secrets, and security-relevant Tauri config.

Usage:
    python analyze_tauri.py output/tauri-unpacked --out output/tauri-analysis
"""

import argparse
import json
import re
import sys
from pathlib import Path


# --- IPC command extraction ---------------------------------------------------

def extract_ipc_commands(content: str) -> list[dict]:
    """Find Tauri IPC invoke() calls."""
    commands = []
    patterns = [
        # Tauri v1: __TAURI__.invoke('command', {args})
        re.compile(r'__TAURI__\.invoke\s*\(\s*[\'"](\w+)[\'"]', re.MULTILINE),
        # Tauri v2: invoke('command', {args})
        re.compile(r'(?:await\s+)?invoke\s*\(\s*[\'"](\w+)[\'"]', re.MULTILINE),
        # @tauri-apps/api import style
        re.compile(r'tauri\.invoke\s*\(\s*[\'"](\w+)[\'"]', re.MULTILINE),
        # tauri::command in Rust comments/strings
        re.compile(r'#\[tauri::command\]\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)', re.MULTILINE),
    ]

    seen = set()
    for pat in patterns:
        for m in pat.finditer(content):
            cmd = m.group(1)
            if cmd not in seen:
                seen.add(cmd)
                # Try to extract arguments
                start = m.end()
                args_match = re.match(r'\s*,\s*(\{[^}]*\})', content[start:start + 500])
                commands.append({
                    'command': cmd,
                    'args_hint': args_match.group(1)[:200] if args_match else None,
                    'offset': m.start(),
                })

    return commands


def extract_event_listeners(content: str) -> list[dict]:
    """Find Tauri event listen/emit calls."""
    events = []
    patterns = [
        (re.compile(r'(?:listen|once)\s*\(\s*[\'"]([^"\']+)[\'"]', re.MULTILINE), 'listen'),
        (re.compile(r'emit\s*\(\s*[\'"]([^"\']+)[\'"]', re.MULTILINE), 'emit'),
        (re.compile(r'__TAURI__\.event\.(?:listen|once)\s*\(\s*[\'"]([^"\']+)[\'"]', re.MULTILINE), 'listen'),
        (re.compile(r'__TAURI__\.event\.emit\s*\(\s*[\'"]([^"\']+)[\'"]', re.MULTILINE), 'emit'),
    ]

    seen = set()
    for pat, direction in patterns:
        for m in pat.finditer(content):
            event = m.group(1)
            key = (event, direction)
            if key not in seen:
                seen.add(key)
                events.append({
                    'event': event,
                    'direction': direction,
                    'offset': m.start(),
                })

    return events


# --- API / network endpoint extraction ----------------------------------------

def extract_endpoints(content: str) -> list[dict]:
    """Find API endpoints and network calls."""
    endpoints = []
    patterns = [
        re.compile(r'''(?:fetch|axios\.\w+|http\.\w+)\s*\(\s*[`'"]([^`'"]+)[`'"]''', re.MULTILINE),
        re.compile(r'''(?:url|endpoint|api_?url|base_?url|server)\s*[:=]\s*[`'"]([^`'"]+)[`'"]''', re.IGNORECASE | re.MULTILINE),
        re.compile(r'''https?://[a-zA-Z0-9._/\-:@?=&%#+]+''', re.MULTILINE),
    ]

    seen = set()
    for pat in patterns:
        for m in pat.finditer(content):
            url = m.group(1) if pat.groups else m.group()
            if url not in seen and not url.startswith('http://schemas.') and 'w3.org' not in url:
                seen.add(url)
                endpoints.append({
                    'url': url[:500],
                    'offset': m.start(),
                })

    return endpoints


# --- Secret / key extraction --------------------------------------------------

def extract_secrets(content: str) -> list[dict]:
    """Find potential secrets, API keys, and tokens."""
    secrets = []
    patterns = [
        (re.compile(r'''(?:api_?key|apikey|secret|token|password|auth)\s*[:=]\s*[`'"]([^`'"]{8,})[`'"]''', re.IGNORECASE), 'api-key'),
        (re.compile(r'''(?:Bearer|Basic)\s+([A-Za-z0-9+/=._-]{20,})'''), 'auth-token'),
        (re.compile(r'''(?:sk|pk|rk)[-_](?:live|test|prod)[-_][A-Za-z0-9]{10,}'''), 'stripe-key'),
        (re.compile(r'''AIza[A-Za-z0-9_-]{35}'''), 'google-api-key'),
        (re.compile(r'''[A-Za-z0-9]{32,}\.apps\.googleusercontent\.com'''), 'google-oauth'),
        (re.compile(r'''gh[ps]_[A-Za-z0-9]{36,}'''), 'github-token'),
        (re.compile(r'''xox[bpsa]-[A-Za-z0-9-]{10,}'''), 'slack-token'),
    ]

    seen = set()
    for pat, kind in patterns:
        for m in pat.finditer(content):
            value = m.group(1) if pat.groups else m.group()
            if value not in seen:
                seen.add(value)
                secrets.append({
                    'type': kind,
                    'value': value[:100],
                    'offset': m.start(),
                })

    return secrets


# --- License logic detection --------------------------------------------------

def extract_license_logic(content: str) -> list[dict]:
    """Find license-related UI and logic."""
    findings = []
    patterns = [
        (re.compile(r'''(?:license|serial|activation)\s*(?:key|code|number)''', re.IGNORECASE), 'license-field'),
        (re.compile(r'''(?:trial|demo|free)\s*(?:version|period|expired|mode)''', re.IGNORECASE), 'trial-check'),
        (re.compile(r'''(?:invalid|expired|wrong)\s*(?:license|key|serial|code)''', re.IGNORECASE), 'validation-error'),
        (re.compile(r'''(?:enter|input|provide)\s*(?:your\s+)?(?:license|serial|activation)''', re.IGNORECASE), 'license-prompt'),
        (re.compile(r'''(?:registered|activated|licensed)\s*(?:to|user|version)''', re.IGNORECASE), 'license-status'),
        (re.compile(r'''(?:days?\s*remaining|expires?\s*(?:on|in|at))''', re.IGNORECASE), 'expiry-check'),
        (re.compile(r'''(?:purchase|buy|upgrade)\s*(?:license|premium|pro)''', re.IGNORECASE), 'purchase-prompt'),
        (re.compile(r'''checkLicense|validateKey|isLicensed|isActivated|isRegistered|isPro|isPremium'''), 'license-function'),
    ]

    seen = set()
    for pat, kind in patterns:
        for m in pat.finditer(content):
            context = content[max(0, m.start() - 50):m.end() + 50]
            key = (kind, m.group()[:50])
            if key not in seen:
                seen.add(key)
                findings.append({
                    'type': kind,
                    'match': m.group()[:100],
                    'context': context.strip()[:200],
                    'offset': m.start(),
                })

    return findings


# --- Tauri config analysis ----------------------------------------------------

def analyze_config(config: dict) -> dict:
    """Analyse Tauri config for security-relevant settings."""
    analysis = {
        'product_name': None,
        'identifier': None,
        'csp': None,
        'allowed_apis': [],
        'security_notes': [],
    }

    # Product info
    pkg = config.get('package', config)
    analysis['product_name'] = pkg.get('productName') or config.get('productName')
    analysis['identifier'] = config.get('identifier') or pkg.get('identifier')

    # Tauri config
    tauri = config.get('tauri', {})
    security = tauri.get('security', {})

    # CSP
    csp = security.get('csp')
    analysis['csp'] = csp
    if csp and 'unsafe-inline' in str(csp):
        analysis['security_notes'].append("CSP allows unsafe-inline — XSS risk")
    if csp and 'unsafe-eval' in str(csp):
        analysis['security_notes'].append("CSP allows unsafe-eval — code injection risk")
    if not csp:
        analysis['security_notes'].append("No CSP configured — unrestricted script execution")

    # Allowlist (Tauri v1)
    allowlist = tauri.get('allowlist', {})
    for api_name, api_config in allowlist.items():
        if isinstance(api_config, dict) and api_config.get('all'):
            analysis['allowed_apis'].append(f"{api_name} (all)")
        elif isinstance(api_config, dict):
            scopes = [k for k, v in api_config.items() if v]
            if scopes:
                analysis['allowed_apis'].append(f"{api_name}: {', '.join(scopes)}")
        elif api_config:
            analysis['allowed_apis'].append(api_name)

    # Dangerous permissions
    if allowlist.get('shell', {}).get('all') or allowlist.get('shell', {}).get('execute'):
        analysis['security_notes'].append("Shell execute allowed — can run arbitrary commands")
    if allowlist.get('fs', {}).get('all') or allowlist.get('fs', {}).get('readFile'):
        analysis['security_notes'].append("Filesystem access allowed — can read sensitive files")
    if allowlist.get('http', {}).get('all') or allowlist.get('http', {}).get('request'):
        analysis['security_notes'].append("HTTP requests allowed — can exfiltrate data")

    # Permissions (Tauri v2)
    plugins = config.get('plugins', {})
    for plugin_name, plugin_config in plugins.items():
        if isinstance(plugin_config, dict):
            analysis['allowed_apis'].append(f"plugin:{plugin_name}")

    return analysis


# --- Main analysis ------------------------------------------------------------

def analyze_directory(source_dir: Path) -> dict:
    """Analyse all extracted Tauri assets."""
    all_content = []
    files = []

    # Read all JS/HTML/CSS files
    for pattern in ('**/*.js', '**/*.html', '**/*.htm', '**/*.css', '**/*.ts', '**/*.jsx', '**/*.tsx', '**/*.mjs'):
        for f in source_dir.glob(pattern):
            if f.is_file():
                try:
                    content = f.read_text(encoding='utf-8', errors='replace')
                    all_content.append(content)
                    files.append(str(f.relative_to(source_dir)))
                except Exception:
                    pass

    combined = '\n'.join(all_content)
    print(f"[*] Analysing {len(files)} files ({len(combined)} chars total)")

    # IPC
    ipc_commands = extract_ipc_commands(combined)
    print(f"[+] IPC commands: {len(ipc_commands)}")
    for cmd in ipc_commands[:10]:
        print(f"    invoke('{cmd['command']}')")

    # Events
    events = extract_event_listeners(combined)
    print(f"[+] Events: {len(events)}")

    # Endpoints
    endpoints = extract_endpoints(combined)
    print(f"[+] API endpoints: {len(endpoints)}")

    # Secrets
    secrets = extract_secrets(combined)
    if secrets:
        print(f"[+] Potential secrets: {len(secrets)}")
        for s in secrets[:5]:
            print(f"    [{s['type']}] {s['value'][:30]}...")

    # License
    license_logic = extract_license_logic(combined)
    if license_logic:
        print(f"[+] License logic: {len(license_logic)} findings")
        for l in license_logic[:5]:
            print(f"    [{l['type']}] {l['match']}")

    # Config
    config_analysis = None
    config_file = source_dir / 'tauri_config.json'
    if not config_file.exists():
        config_file = source_dir.parent / 'tauri_config.json'
    if config_file.exists():
        try:
            config = json.loads(config_file.read_text(encoding='utf-8'))
            config_analysis = analyze_config(config)
            if config_analysis['security_notes']:
                print(f"[+] Security notes:")
                for note in config_analysis['security_notes']:
                    print(f"    [!] {note}")
        except Exception:
            pass

    return {
        'files_analyzed': files,
        'ipc_commands': ipc_commands,
        'events': events,
        'endpoints': endpoints,
        'secrets': secrets,
        'license': license_logic,
        'config_analysis': config_analysis,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyse extracted Tauri frontend assets")
    ap.add_argument('source_dir', help='Directory with extracted Tauri assets')
    ap.add_argument('--out', required=True, help='Output directory for analysis results')
    args = ap.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        print(f"[!] Not found: {source_dir}", file=sys.stderr)
        return 1

    analysis = analyze_directory(source_dir)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / 'tauri_analysis.json'
    json_path.write_text(json.dumps(analysis, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"\n[+] Analysis saved: {json_path}")

    # Summary
    print(f"\n{'=' * 60}")
    print(f"[+] Tauri Frontend Analysis Summary")
    print(f"    Files: {len(analysis['files_analyzed'])}")
    print(f"    IPC commands: {len(analysis['ipc_commands'])}")
    print(f"    Events: {len(analysis['events'])}")
    print(f"    Endpoints: {len(analysis['endpoints'])}")
    print(f"    Secrets: {len(analysis['secrets'])}")
    print(f"    License findings: {len(analysis['license'])}")

    if analysis['ipc_commands']:
        print(f"\n[*] Recommendations:")
        print(f"    -> Hook IPC commands via Frida or Tauri dev tools")
        print(f"    -> Intercept network calls with mitmproxy")
    if analysis['license']:
        print(f"    -> Analyse license validation flow in JS and Rust backend")
        print(f"    -> Try javascript-deobfuscator on extracted JS")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
