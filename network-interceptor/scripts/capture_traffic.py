#!/usr/bin/env python3
"""
capture_traffic.py — Capture HTTP(S) traffic via mitmproxy.

Starts mitmdump in non-interactive mode, captures to HAR format.
Configure target app to use proxy at localhost:<port>.

Usage:
    python capture_traffic.py --port 8080 --duration 120 --out captured.har
    python capture_traffic.py --port 8080 --host api.example.com --out captured.har
    python capture_traffic.py --stop 12345
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path


def check_mitmproxy() -> str | None:
    """Find mitmdump executable."""
    path = shutil.which('mitmdump')
    if path:
        return path
    # Try common locations
    for candidate in [
        Path(sys.prefix) / 'Scripts' / 'mitmdump.exe',
        Path.home() / '.local' / 'bin' / 'mitmdump',
    ]:
        if candidate.exists():
            return str(candidate)
    return None


def start_capture(port: int, host_filter: str | None, output: Path,
                  duration: int, flow_file: Path | None = None) -> dict:
    """Start mitmdump capture process."""
    mitmdump = check_mitmproxy()
    if not mitmdump:
        print("[!] mitmdump not found. Install: pip install mitmproxy", file=sys.stderr)
        return {'error': 'mitmdump not found'}

    cmd = [mitmdump, '-p', str(port), '--set', f'hardump={output}']

    if host_filter:
        cmd.extend(['--set', f'view_filter=~d {host_filter}'])

    if flow_file:
        cmd.extend(['-w', str(flow_file)])

    print(f"[*] Starting mitmdump on port {port}")
    print(f"[*] Output: {output}")
    if host_filter:
        print(f"[*] Host filter: {host_filter}")
    print(f"[*] Duration: {duration}s")
    print(f"[i] Configure app proxy: http://localhost:{port}")
    print(f"[i] CA cert: ~/.mitmproxy/mitmproxy-ca-cert.pem")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        print(f"[+] mitmdump started (PID: {proc.pid})")

        if duration > 0:
            print(f"[*] Capturing for {duration}s... (Ctrl+C to stop early)")
            try:
                proc.wait(timeout=duration)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=5)
            print(f"[+] Capture complete")
        else:
            print(f"[+] Running until stopped. PID: {proc.pid}")
            print(f"[i] Stop with: python capture_traffic.py --stop {proc.pid}")

        return {
            'pid': proc.pid,
            'port': port,
            'output': str(output),
            'status': 'completed' if duration > 0 else 'running',
        }

    except Exception as e:
        return {'error': str(e)}


def stop_capture(pid: int) -> bool:
    """Stop a running mitmdump process."""
    try:
        if sys.platform == 'win32':
            subprocess.run(['taskkill', '/PID', str(pid), '/F'],
                          capture_output=True)
        else:
            os.kill(pid, signal.SIGTERM)
        print(f"[+] Stopped process {pid}")
        return True
    except Exception as e:
        print(f"[!] Failed to stop PID {pid}: {e}")
        return False


def convert_har_to_json(har_path: Path, json_path: Path) -> dict:
    """Convert HAR to simplified JSON for analysis."""
    try:
        har_data = json.loads(har_path.read_text(encoding='utf-8'))
    except Exception as e:
        return {'error': f'Cannot parse HAR: {e}'}

    entries = []
    for entry in har_data.get('log', {}).get('entries', []):
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
            'time_ms': entry.get('time', 0),
        })

    json_path.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding='utf-8')
    return {'entries': len(entries), 'output': str(json_path)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture HTTP(S) traffic via mitmproxy")
    ap.add_argument('--port', type=int, default=8080, help='Proxy port (default: 8080)')
    ap.add_argument('--host', help='Filter by host (e.g., api.example.com)')
    ap.add_argument('--duration', type=int, default=120, help='Capture duration in seconds (0=manual stop)')
    ap.add_argument('--out', default='captured.har', help='Output HAR file')
    ap.add_argument('--flow-file', help='Also save raw flow file')
    ap.add_argument('--stop', type=int, help='Stop a running capture by PID')
    ap.add_argument('--convert', help='Convert existing HAR to simplified JSON')
    args = ap.parse_args()

    if args.stop:
        return 0 if stop_capture(args.stop) else 1

    if args.convert:
        har = Path(args.convert)
        if not har.exists():
            print(f"[!] HAR not found: {har}", file=sys.stderr)
            return 1
        result = convert_har_to_json(har, Path(args.out).with_suffix('.json'))
        print(f"[+] Converted: {result}")
        return 0

    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    flow = Path(args.flow_file) if args.flow_file else None

    result = start_capture(args.port, args.host, output, args.duration, flow)
    if 'error' in result:
        print(f"[!] {result['error']}", file=sys.stderr)
        return 1

    # Auto-convert HAR to JSON if capture completed
    if result.get('status') == 'completed' and output.exists():
        json_out = output.with_suffix('.json')
        convert_har_to_json(output, json_out)
        print(f"[+] Also saved as JSON: {json_out}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
