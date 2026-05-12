#!/usr/bin/env python3
"""
analyze_traffic.py — Analyze captured HTTP traffic for RE-relevant patterns.

Finds API endpoints, auth tokens, OAuth flows, license validation calls.
Can generate replay scripts for specific requests.

Usage:
    python analyze_traffic.py captured.har --out analysis/
    python analyze_traffic.py captured.json --out analysis/
    python analyze_traffic.py captured.har --replay 3 --out replay.py
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse


def load_traffic(path: Path) -> list[dict]:
    """Load traffic from HAR or simplified JSON."""
    data = json.loads(path.read_text(encoding='utf-8'))

    if isinstance(data, list):
        return data

    # HAR format
    if 'log' in data:
        entries = []
        for entry in data['log'].get('entries', []):
            req = entry.get('request', {})
            resp = entry.get('response', {})
            entries.append({
                'method': req.get('method', ''),
                'url': req.get('url', ''),
                'request_headers': {h['name']: h['value'] for h in req.get('headers', [])},
                'request_body': req.get('postData', {}).get('text', ''),
                'status': resp.get('status', 0),
                'response_headers': {h['name']: h['value'] for h in resp.get('headers', [])},
                'response_body': resp.get('content', {}).get('text', ''),
            })
        return entries
    return []


def find_api_endpoints(traffic: list[dict]) -> list[dict]:
    """Group unique endpoints by base URL."""
    endpoints = defaultdict(lambda: {'methods': set(), 'count': 0, 'statuses': set()})
    for entry in traffic:
        url = entry.get('url', '')
        if not url:
            continue
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        endpoints[base]['methods'].add(entry.get('method', ''))
        endpoints[base]['count'] += 1
        endpoints[base]['statuses'].add(entry.get('status', 0))

    return [
        {'url': url, 'methods': sorted(info['methods']),
         'count': info['count'], 'statuses': sorted(info['statuses'])}
        for url, info in sorted(endpoints.items(), key=lambda x: -x[1]['count'])
    ]


def find_auth_tokens(traffic: list[dict]) -> list[dict]:
    """Extract authentication tokens from headers and bodies."""
    tokens = []
    seen = set()

    for i, entry in enumerate(traffic):
        headers = entry.get('request_headers', {})

        # Authorization header
        auth = headers.get('Authorization') or headers.get('authorization', '')
        if auth and auth not in seen:
            seen.add(auth)
            token_type = 'Bearer' if 'Bearer' in auth else 'Basic' if 'Basic' in auth else 'Other'
            tokens.append({
                'type': token_type,
                'value': auth,
                'request_index': i,
                'url': entry.get('url', ''),
            })

        # API key headers
        for key in ['X-API-Key', 'X-Api-Key', 'x-api-key', 'Api-Key']:
            val = headers.get(key, '')
            if val and val not in seen:
                seen.add(val)
                tokens.append({
                    'type': 'API-Key',
                    'value': val,
                    'request_index': i,
                    'url': entry.get('url', ''),
                })

        # Set-Cookie (session tokens)
        resp_headers = entry.get('response_headers', {})
        for key in ['Set-Cookie', 'set-cookie']:
            cookie = resp_headers.get(key, '')
            if cookie and ('session' in cookie.lower() or 'token' in cookie.lower()):
                if cookie not in seen:
                    seen.add(cookie)
                    tokens.append({
                        'type': 'Session-Cookie',
                        'value': cookie[:200],
                        'request_index': i,
                        'url': entry.get('url', ''),
                    })

    return tokens


def find_license_calls(traffic: list[dict]) -> list[dict]:
    """Identify license-related API calls."""
    license_keywords = [
        'license', 'activate', 'verify', 'register', 'validate',
        'auth', 'login', 'check', 'trial', 'subscription',
    ]
    body_keywords = [
        'hwid', 'machine_id', 'serial', 'key', 'expir', 'device',
        'fingerprint', 'activation', 'license_key',
    ]

    calls = []
    for i, entry in enumerate(traffic):
        url = entry.get('url', '').lower()
        body = (entry.get('request_body', '') + entry.get('response_body', '')).lower()

        url_match = any(kw in url for kw in license_keywords)
        body_match = any(kw in body for kw in body_keywords)

        if url_match or body_match:
            calls.append({
                'request_index': i,
                'method': entry.get('method', ''),
                'url': entry.get('url', ''),
                'status': entry.get('status', 0),
                'matched_url': url_match,
                'matched_body': body_match,
                'request_body_preview': entry.get('request_body', '')[:500],
                'response_body_preview': entry.get('response_body', '')[:500],
            })

    return calls


def detect_oauth_flow(traffic: list[dict]) -> dict | None:
    """Detect OAuth2 flows."""
    oauth_patterns = {
        'authorize': re.compile(r'/(?:oauth|auth).*/authorize', re.I),
        'token': re.compile(r'/(?:oauth|auth).*/token', re.I),
        'callback': re.compile(r'/(?:callback|redirect)', re.I),
        'code_exchange': re.compile(r'code=|grant_type=authorization_code', re.I),
    }

    detected = {}
    for i, entry in enumerate(traffic):
        url = entry.get('url', '')
        body = entry.get('request_body', '') + entry.get('response_body', '')
        combined = url + ' ' + body

        for step_name, pattern in oauth_patterns.items():
            if pattern.search(combined) and step_name not in detected:
                detected[step_name] = {
                    'request_index': i,
                    'url': entry.get('url', ''),
                    'method': entry.get('method', ''),
                }

    if len(detected) >= 2:
        return {'flow_type': 'OAuth2 Authorization Code', 'steps': detected}
    return None


def generate_replay_script(entry: dict, out_path: Path) -> None:
    """Generate standalone Python requests script to replay a request."""
    method = entry.get('method', 'GET')
    url = entry.get('url', '')
    headers = entry.get('request_headers', {})
    body = entry.get('request_body', '')

    # Filter out hop-by-hop headers
    skip = {'host', 'content-length', 'transfer-encoding', 'connection'}
    clean_headers = {k: v for k, v in headers.items() if k.lower() not in skip}

    lines = [
        '#!/usr/bin/env python3',
        '"""Auto-generated replay script."""',
        'import requests',
        '',
        f'url = {url!r}',
        f'headers = {json.dumps(clean_headers, indent=4)}',
    ]

    if body:
        lines.append(f'data = {body!r}')
        lines.append(f'resp = requests.{method.lower()}(url, headers=headers, data=data)')
    else:
        lines.append(f'resp = requests.{method.lower()}(url, headers=headers)')

    lines.extend([
        'print(f"Status: {resp.status_code}")',
        'print(f"Headers: {dict(resp.headers)}")',
        'print(f"Body: {resp.text[:2000]}")',
        '',
    ])

    out_path.write_text('\n'.join(lines), encoding='utf-8')


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze captured HTTP traffic")
    ap.add_argument('traffic_file', help='HAR or JSON traffic file')
    ap.add_argument('--out', default='network-analysis', help='Output directory')
    ap.add_argument('--replay', type=int, help='Generate replay script for request at index N')
    ap.add_argument('--json', action='store_true', help='JSON output only')
    args = ap.parse_args()

    path = Path(args.traffic_file)
    if not path.exists():
        print(f"[!] Not found: {path}", file=sys.stderr)
        return 1

    print(f"[*] Loading: {path.name}")
    traffic = load_traffic(path)
    print(f"[*] Loaded {len(traffic)} requests")

    if args.replay is not None:
        if args.replay >= len(traffic):
            print(f"[!] Index {args.replay} out of range (0-{len(traffic)-1})")
            return 1
        out = Path(args.out) if args.out.endswith('.py') else Path(args.out) / 'replay.py'
        out.parent.mkdir(parents=True, exist_ok=True)
        generate_replay_script(traffic[args.replay], out)
        print(f"[+] Replay script: {out}")
        return 0

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("[*] Finding API endpoints...")
    endpoints = find_api_endpoints(traffic)

    print("[*] Extracting auth tokens...")
    tokens = find_auth_tokens(traffic)

    print("[*] Finding license calls...")
    license_calls = find_license_calls(traffic)

    print("[*] Detecting OAuth flows...")
    oauth = detect_oauth_flow(traffic)

    results = {
        'total_requests': len(traffic),
        'endpoints': endpoints,
        'auth_tokens': tokens,
        'license_calls': license_calls,
        'oauth_flow': oauth,
    }

    (out_dir / 'analysis.json').write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding='utf-8')

    print(f"\n[+] Analysis complete:")
    print(f"    Endpoints     : {len(endpoints)}")
    print(f"    Auth tokens   : {len(tokens)}")
    print(f"    License calls : {len(license_calls)}")
    print(f"    OAuth flow    : {'Yes' if oauth else 'None'}")
    print(f"    Report: {out_dir / 'analysis.json'}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
