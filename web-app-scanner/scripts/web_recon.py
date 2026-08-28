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
import re
import shutil
import socket
import ssl
import subprocess
import sys
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlparse, urljoin, urldefrag
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

UA = "web-app-scanner/2.0 (authorized-recon)"

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
    """Advanced CORS: reflection, null origin, and subdomain/prefix/suffix trust bypasses."""
    host = urlparse(url).hostname or ""
    # (origin_to_send, human_label)
    probes = [
        ("https://evil.example.com", "arbitrary origin reflected"),
        ("null", "null origin trusted"),
        (f"https://evil.{host}", "arbitrary subdomain trusted"),
        (f"https://{host}.evil.example.com", "suffix trust bypass"),
        (f"https://{host}evil.example.com", "prefix/substring trust bypass"),
        ("http://" + host, "insecure http origin trusted"),
    ]
    findings = []
    seen = set()
    for origin, label in probes:
        _, headers, err = fetch(url, extra_headers={"Origin": origin})
        if err:
            continue
        h = lower_headers(headers)
        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "").lower()
        reflected = acao == origin or (origin == "null" and acao == "null")
        wildcard = acao == "*"
        if not (reflected or wildcard):
            continue
        creds = acac == "true"
        if reflected and creds:
            sev = "high"
        elif reflected or (wildcard and creds):
            sev = "medium"
        else:
            sev = "low"
        title = "Permissive CORS — " + (label if reflected else "wildcard ACAO")
        if title in seen:
            continue
        seen.add(title)
        findings.append({"severity": sev, "category": "cors", "title": title,
                         "detail": f"ACAO={acao!r} for Origin={origin!r}; credentials={acac or 'n/a'}."})
    return findings


_HREF_RE = re.compile(r"""(?:href|src|action)\s*=\s*['"]([^'"#]+)['"]""", re.I)


def _fetch_body(url: str, timeout: int = 15) -> str:
    req = Request(url, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urlopen(req, timeout=timeout,
                     context=ctx if url.lower().startswith("https") else None) as resp:
            ctype = resp.headers.get("Content-Type", "")
            if "html" not in ctype.lower():
                return ""
            return resp.read(400_000).decode("utf-8", "replace")
    except Exception:  # noqa
        return ""


def crawl(base_url: str, depth: int = 1, max_pages: int = 40) -> list[str]:
    """BFS same-host link discovery. Returns URLs found (params-first ordering)."""
    host = urlparse(base_url).netloc
    seen = {base_url}
    ordered = [base_url]
    frontier = [(base_url, 0)]
    while frontier and len(seen) < max_pages:
        current, d = frontier.pop(0)
        if d >= depth:
            continue
        body = _fetch_body(current)
        for raw in _HREF_RE.findall(body):
            link = urldefrag(urljoin(current, raw))[0]
            p = urlparse(link)
            if p.scheme not in ("http", "https") or p.netloc != host:
                continue
            if link not in seen:
                seen.add(link)
                ordered.append(link)
                frontier.append((link, d + 1))
                if len(seen) >= max_pages:
                    break
    # URLs carrying query params are the interesting active-test surface
    ordered.sort(key=lambda u: (0 if urlparse(u).query else 1))
    return ordered


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
    lines.append("| Severity | Category | Finding | Detail | URL |")
    lines.append("|---|---|---|---|---|")
    for f in sorted(findings, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
        detail = str(f["detail"]).replace("|", "\\|")[:120]
        u = str(f.get("url", "")).replace("|", "\\|")[:80]
        lines.append(f"| {f['severity']} | {f['category']} | {f['title']} | {detail} | {u} |")
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
    ap.add_argument("--active", action="store_true",
                    help="Run non-destructive active vuln checks (exposed files, XSS, redirect, LFI).")
    ap.add_argument("--crawl", type=int, default=0, metavar="DEPTH",
                    help="Crawl same-host links to DEPTH and test discovered URLs (implies wider --active surface).")
    ap.add_argument("--max-pages", type=int, default=40, help="Crawl page cap.")
    ap.add_argument("--authorized", action="store_true",
                    help="Confirm authorization (required for --active).")
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

    # --- Active, non-destructive vulnerability checks (authorized only) ---
    if args.active or args.crawl:
        if not args.authorized:
            print("[!] --active / --crawl send probes to the target. Re-run with --authorized.",
                  file=sys.stderr)
            return 2
        try:
            import vuln_checks
        except ImportError as e:
            print(f"[!] vuln_checks module unavailable: {e}", file=sys.stderr)
            return 1
        targets = [args.url]
        if args.crawl:
            targets = crawl(args.url, depth=args.crawl, max_pages=args.max_pages)
            print(f"[*] Crawled {len(targets)} URL(s); running active checks ...")
        seen_keys = set()
        for t in targets:
            for f in vuln_checks.run_active(t):
                key = (f.get("category"), f.get("title"), f.get("url"))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(f)

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
