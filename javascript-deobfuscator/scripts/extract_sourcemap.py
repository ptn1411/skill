#!/usr/bin/env python3
"""
extract_sourcemap.py — Advanced JS Source Recovery & Secret Scanner.
Downloads sourcemaps, extracts original source, and scans for tokens/secrets.
"""
import requests
import json
import os
import sys
import urllib3
import re
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common secret patterns
SECRET_PATTERNS = {
    'Firebase Key': r'AIza[0-9A-Za-z-_]{35}',
    'Google API': r'AIza[0-9A-Za-z-_]{35}',
    'Amazon AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'Amazon AWS Secret Key': r'[^A-Za-z0-9/+=][A-Za-z0-9/+=]{40}[^A-Za-z0-9/+=]',
    'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    'Github Token': r'ghp_[a-zA-Z0-9]{36}',
    'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
    'Private Key': r'-----BEGIN (RSA|EC|DSA|GPG|OPENSSH) PRIVATE KEY-----',
    'Generic Secret': r'(?i)(api_key|secret|password|token|auth|credential)["\']?\s*[:=]\s*["\']([^"\'\s]{10,})["\']',
    'JWT Token': r'ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
}

def sanitize_path(path: str) -> str:
    for prefix in ["webpack://", "vite://", "/", "./", "../"]:
        while path.startswith(prefix):
            path = path[len(prefix):]
    path = path.replace("\x00", "").replace("..", "_")
    return path

def scan_for_secrets(file_path, content):
    findings = []
    for name, pattern in SECRET_PATTERNS.items():
        matches = re.finditer(pattern, content)
        for match in matches:
            val = match.group(0) if name != 'Generic Secret' else match.group(2)
            findings.append({'type': name, 'value': val, 'file': file_path})
    return findings

def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_sourcemap.py <URL> [OUTPUT_DIR]")
        return 1

    url = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "extracted_source"
    
    print(f"[*] Sourcemap: {url}")
    print(f"[*] Output:    {out_dir}\n")

    print("[1] Downloading sourcemap...")
    try:
        r = requests.get(url, timeout=60, verify=False)
        r.raise_for_status()
    except Exception as e:
        print(f"    ERROR: {e}")
        return 1

    print("[2] Parsing JSON...")
    try:
        data = r.json()
    except Exception as e:
        print(f"    ERROR: Invalid JSON - {e}")
        return 1

    sources = data.get("sources", [])
    contents = data.get("sourcesContent", [])

    if not sources or not contents:
        print("    ERROR: No sourcesContent found.")
        return 1

    print(f"\n[3] Extracting and Scanning files...\n")
    os.makedirs(out_dir, exist_ok=True)

    all_findings = []
    saved = 0

    for i, (source_path, content) in enumerate(zip(sources, contents)):
        if not content: continue
        
        clean_path = sanitize_path(source_path)
        full_path = Path(out_dir) / clean_path
        
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding='utf-8', errors='replace')
        saved += 1

        # Scan for secrets
        findings = scan_for_secrets(clean_path, content)
        all_findings.extend(findings)

        if saved % 50 == 0:
            print(f"  [+] Saved {saved} files...")

    print(f"\n[4] Secret Scan Results:")
    if not all_findings:
        print("    - No obvious secrets found.")
    else:
        for f in all_findings:
            print(f"  [!] FOUND {f['type']} in {f['file']}")
            print(f"      Value: {f['value'][:50]}{'...' if len(f['value']) > 50 else ''}")

    print(f"\n{'='*60}")
    print(f"Done! Saved: {saved} files to {out_dir}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
