#!/usr/bin/env python3
"""
web_recon.py — Passive/active web recon for authorized targets (Windows-first, stdlib).

Native checks (no install needed):
  * Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, ...)
  * Cookie flags (Secure, HttpOnly, SameSite)
  * TLS version + certificate summary
  * CORS reflection (Origin echo + credentials)
  * Server / X-Powered-By tech disclosure

Optional external tools (run only if installed AND requested):
  * nuclei  (--nuclei)  template-based vuln/misconfig scan
  * ffuf    (--ffuf WORDLIST)  content/endpoint discovery

Writes FINDINGS.md + findings.json to --out.

Usage:
    python web_recon.py https://example.com --out output/web
    python web_recon.py https://example.com --nuclei --out output/web
    python web_recon.py https://example.com --ffuf wordlist.txt --out output/web

Only test sites you own or are explicitly authorized to assess (MASTER_POLICY.md).
"""

import argparse
import json
import shutil
import socket
import ssl
import subprocess
import sys
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

UA = "web-app-scanner/1.0 (authorized-recon)"

# header -> (severity, advice) when MISSING
SECURITY_HEADERS = {
    "content-security-policy": ("high", "No CSP — add one to mitigate XSS/data injection."),
    "strict-transport-security": ("high", "No HSTS — add to force HTTPS and prevent downgrade."),
    "x-frame-options": ("medium", "Missing — add DENY/SAMEORIGIN (or CSP frame-ancestors) to stop clickjacking."),
    "x-content-type-options": ("medium", "Missing — add 'nosniff' to stop MIME sniffing."),
    "referrer-policy": ("low", "Missing — add e.g. 'strict-origin-when-cross-origin'."),
    "permissions-policy": ("low", "Missing — restrict powerful features (camera, geolocation, ...)."),
}
DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


def fetch(url: str, extra_headers: dict | None = None, timeout: int = 15):
    req = Request(url, headers={"User-Agent": UA, **(extra_headers or {})})
    try:
        resp = urlopen(req, timeout=timeout, context=ssl.create_default_context())
        return resp.status, dict(resp.getheaders()), None
    except HTTPError as e:
        return e.code, dict(e.headers or {}), None
    except URLError as e:
        return None, {}, str(e.reason)
    except Exception as e:  # noqa
        return None, {}, str(e)


def lower_headers(headers: dict) -> dict:
    return {k.lower(): v for k, v in headers.items()}


def analyze_headers(headers: dict) -> list[dict]:
    """Pure function — testable without network."""
    h = lower_headers(headers)
    findings = []
    for name, (sev, advice) in SECURITY_HEADERS.items():
        if name not in h:
            findings.append({"severity": sev, "category": "headers",
                             "title": f"Missing {name}", "detail": advice})
    for name in DISCLOSURE_HEADERS:
        if name in h and h[name].strip():
            findings.append({"severity": "low", "category": "disclosure",
                             "title": f"{name} discloses tech", "detail": h[name]})
    return findings


def analyze_cookies(headers: dict) -> list[dict]:
    findings = []
    raw = headers.get("set-cookie") or headers.get("Set-Cookie")
    if not raw:
        return findings
    for line in (raw if isinstance(raw, list) else [raw]):
        c = SimpleCookie()
        try:
            c.load(line)
        except Exception:
            continue
        for name, morsel in c.items():
            attrs = line.lower()
            missing = []
            if "secure" not in attrs:
                missing.append("Secure")
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            if "samesite" not in attrs:
                missing.append("SameSite")
            if missing:
                findings.append({"severity": "medium", "category": "cookies",
                                 "title": f"Cookie '{name}' missing {', '.join(missing)}",
                                 "detail": "Set these flags to protect session cookies."})
    return findings


def check_tls(host: str, port: int = 443) -> list[dict]:
    findings = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ver = ssock.version()
                cert = ssock.getpeercert()
                if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
                    findings.append({"severity": "high", "category": "tls",
                                     "title": f"Weak TLS protocol {ver}",
                                     "detail": "Disable TLS < 1.2."})
                else:
                    findings.append({"severity": "info", "category": "tls",
                                     "title": f"TLS {ver}", "detail": "OK"})
                subject = dict(x[0] for x in cert.get("subject", []))
                findings.append({"severity": "info", "category": "tls",
                                 "title": "Certificate",
                                 "detail": f"CN={subject.get('commonName','?')} exp={cert.get('notAfter','?')}"})
    except Exception as e:
        findings.append({"severity": "info", "category": "tls",
                         "title": "TLS check failed", "detail": str(e)})
    return findings


def check_cors(url: str) -> list[dict]:
    evil = "https://evil.example.com"
    status, headers, err = fetch(url, extra_headers={"Origin": evil})
    if err:
        return []
    h = lower_headers(headers)
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "")
    findings = []
    if acao == evil or acao == "*":
        sev = "high" if (acao == evil and acac.lower() == "true") else "medium"
        findings.append({"severity": sev, "category": "cors",
                         "title": "Permissive CORS",
                         "detail": f"ACAO reflects/allows origin ({acao}); credentials={acac or 'n/a'}."})
    return findings


def run_tool(name: str, cmd: list[str], out_file: Path) -> dict | None:
    if not shutil.which(name):
        print(f"[i] {name} not installed; skipping.")
        return None
    print(f"[*] Running {name} ...")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        out_file.write_text(proc.stdout + "\n" + proc.stderr, encoding="utf-8")
        return {"tool": name, "output_file": str(out_file), "returncode": proc.returncode}
    except Exception as e:
        print(f"[!] {name} failed: {e}")
        return None


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def to_markdown(url: str, status, findings: list[dict], tools: list[dict]) -> str:
    lines = [f"# Web Recon — {url}", "", f"HTTP status: {status}", ""]
    real = [f for f in findings if f["severity"] != "info"]
    from collections import Counter
    c = Counter(f["severity"] for f in real)
    if c:
        lines.append("**Issues:** " + "  ".join(
            f"{k}: {c[k]}" for k in sorted(c, key=lambda s: SEV_ORDER.get(s, 9))))
        lines.append("")
    lines.append("| Severity | Category | Finding | Detail |")
    lines.append("|---|---|---|---|")
    for f in sorted(findings, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
        detail = str(f["detail"]).replace("|", "\\|")[:120]
        lines.append(f"| {f['severity']} | {f['category']} | {f['title']} | {detail} |")
    lines.append("")
    if tools:
        lines.append("## External tool output")
        for t in tools:
            lines.append(f"- **{t['tool']}** → `{t['output_file']}` (exit {t['returncode']})")
        lines.append("")
    lines.append("## Remediation (defensive)")
    lines.append("- Add the missing security headers and set Secure/HttpOnly/SameSite on cookies.")
    lines.append("- Enforce TLS >= 1.2 and a valid certificate.")
    lines.append("- Lock down CORS to explicit trusted origins; never combine `*`/reflected origin with credentials.")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Authorized web recon.")
    ap.add_argument("url", nargs="?", help="Target URL (https://...).")
    ap.add_argument("--out", default="output/web")
    ap.add_argument("--nuclei", action="store_true", help="Run nuclei if installed.")
    ap.add_argument("--ffuf", metavar="WORDLIST", help="Run ffuf content discovery with this wordlist.")
    ap.add_argument("--check", action="store_true", help="Report which optional tools are available.")
    args = ap.parse_args()

    if args.check:
        for t in ("nuclei", "ffuf", "nikto"):
            print(f"[{'+' if shutil.which(t) else 'i'}] {t}: {shutil.which(t) or 'not installed'}")
        return 0

    if not args.url:
        ap.error("url is required (unless --check).")

    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https"):
        ap.error("URL must start with http:// or https://")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Fetching {args.url}")
    status, headers, err = fetch(args.url)
    if err and status is None:
        print(f"[!] Request failed: {err}", file=sys.stderr)
        return 1

    findings = analyze_headers(headers) + analyze_cookies(headers)
    if parsed.scheme == "https":
        findings += check_tls(parsed.hostname, parsed.port or 443)
    findings += check_cors(args.url)

    tools = []
    if args.nuclei:
        r = run_tool("nuclei", ["nuclei", "-u", args.url, "-silent"], out_dir / "nuclei.txt")
        if r:
            tools.append(r)
    if args.ffuf:
        base = args.url.rstrip("/") + "/FUZZ"
        r = run_tool("ffuf", ["ffuf", "-u", base, "-w", args.ffuf, "-mc", "200,204,301,302,401,403"],
                     out_dir / "ffuf.txt")
        if r:
            tools.append(r)

    (out_dir / "findings.json").write_text(
        json.dumps({"url": args.url, "status": status, "findings": findings, "tools": tools},
                   indent=2), encoding="utf-8")
    (out_dir / "FINDINGS.md").write_text(to_markdown(args.url, status, findings, tools), encoding="utf-8")

    real = sum(1 for f in findings if f["severity"] != "info")
    print(f"[+] {real} issue(s). Report: {out_dir / 'FINDINGS.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
