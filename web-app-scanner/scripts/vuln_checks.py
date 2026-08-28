#!/usr/bin/env python3
"""
vuln_checks.py — Non-destructive active web vulnerability checks (stdlib).

Importable by web_recon.py (via `--active`) or runnable standalone on one URL.
Every check is detection-only: it sends benign probes and looks for a signature.
No data is dumped, no state is modified, no exploitation is performed.

Checks:
  * exposed_files   — /.git/HEAD, /.env, /server-status, backups, security.txt, ...
  * open_redirect   — redirect/next/url params that send Location to an external host
  * reflected_xss   — query params reflected unencoded into the HTML body
  * path_traversal  — file/path params returning /etc/passwd or win.ini signatures
  * dir_listing     — "Index of /" autoindex pages
  * header_injection — CRLF in a param reflected into response headers (response splitting)
  * ssti            — template expression ({{a*b}}, ${a*b}, ...) evaluated server-side
  * ssrf            — url-taking param that fetches cloud metadata (169.254.169.254)

Usage (standalone):
    python vuln_checks.py "https://app.local/item?id=1&next=/home"

Only test targets you own or are authorized to assess (MASTER_POLICY.md §1).
"""

import re
import ssl
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from urllib.request import Request, build_opener, HTTPRedirectHandler, HTTPSHandler
from urllib.error import HTTPError, URLError

UA = "web-app-scanner/2.0 (authorized-active)"
TIMEOUT = 15
MARKER = "zqx9k7vscan"  # unique, unlikely to occur naturally

# path -> (signature substring or None for any-200, severity, note)
SENSITIVE_PATHS = {
    "/.git/HEAD": ("ref:", "high", "Exposed .git — source/history may be recoverable."),
    "/.git/config": ("[core]", "high", "Exposed .git config."),
    "/.env": ("=", "high", "Exposed .env — likely secrets/credentials."),
    "/.svn/entries": (None, "medium", "Exposed .svn metadata."),
    "/.DS_Store": (None, "low", "Exposed .DS_Store — leaks file names."),
    "/server-status": ("Apache Server Status", "medium", "Apache mod_status exposed."),
    "/actuator/env": ("propertySources", "high", "Spring Actuator env exposed — secrets."),
    "/phpinfo.php": ("phpinfo()", "medium", "phpinfo() exposed — environment disclosure."),
    "/.well-known/security.txt": (None, "info", "security.txt present (good practice)."),
    "/backup.zip": (None, "medium", "Backup archive reachable."),
    "/config.php.bak": (None, "high", "Backup of config with possible secrets."),
}

TRAVERSAL_PARAMS = ("file", "path", "page", "doc", "document", "template",
                    "include", "dir", "download", "load", "read")
TRAVERSAL_PAYLOADS = (
    ("../../../../../../etc/passwd", re.compile(r"root:.*:0:0:")),
    ("..\\..\\..\\..\\..\\..\\windows\\win.ini", re.compile(r"\[extensions\]|for 16-bit app support", re.I)),
)
REDIRECT_PARAMS = ("redirect", "redirect_uri", "redirecturl", "url", "next", "return",
                   "returnurl", "return_to", "dest", "destination", "continue", "goto", "r", "u")
EVIL_HOST = "example.org"  # benign external marker host
INJ_HEADER = "x-scanner-inj"  # marker header for CRLF / response-splitting detection
# params commonly reflected into response headers (Location, Set-Cookie, Content-Language, ...)
HEADER_INJ_PARAMS = REDIRECT_PARAMS + ("lang", "locale", "lang_code", "sid", "sessionid", "cb")

# SSTI: two uncommon factors; server-side eval yields the product, plain reflection does not.
_A, _B = 73, 79
_PRODUCT = str(_A * _B)  # "5767"
SSTI_PAYLOADS = (f"{{{{{_A}*{_B}}}}}", f"${{{_A}*{_B}}}", f"#{{{_A}*{_B}}}",
                 f"<%= {_A}*{_B} %>", f"${{{{{_A}*{_B}}}}}", f"{{{_A}*{_B}}}")

# SSRF: params that commonly accept a URL/host the server will fetch.
SSRF_PARAMS = ("url", "uri", "link", "src", "source", "dest", "target", "image",
               "img", "imageurl", "callback", "webhook", "fetch", "proxy", "host",
               "domain", "feed", "load", "site", "page_url", "next")
_META_SIG = re.compile(r"ami-id|instance-id|iam/|reservation-id|placement/|hostname|"
                       r"computeMetadata|service-accounts|azEnvironment|vmId", re.I)
_PASSWD_SIG = re.compile(r"root:.*:0:0:")
# (payload, signature, severity, label). Multiple encodings defeat naive IP/host filters.
# 169.254.169.254 == 2852039166 (decimal) == 0xA9FEA9FE (hex).
SSRF_PROBES = [
    ("http://169.254.169.254/latest/meta-data/", _META_SIG, "critical", "AWS IMDSv1 metadata"),
    ("http://2852039166/latest/meta-data/", _META_SIG, "critical", "AWS metadata via decimal-IP filter bypass"),
    ("http://0xA9FEA9FE/latest/meta-data/", _META_SIG, "critical", "AWS metadata via hex-IP filter bypass"),
    ("http://[::ffff:169.254.169.254]/latest/meta-data/", _META_SIG, "critical", "AWS metadata via IPv6-mapped bypass"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", _META_SIG, "critical", "Azure IMDS metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", _META_SIG, "critical", "GCP metadata"),
    ("file:///etc/passwd", _PASSWD_SIG, "high", "SSRF to local file (file:// scheme)"),
]


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _opener(follow_redirects: bool):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # active checks care about content, not cert validity
    handlers = [HTTPSHandler(context=ctx)]
    if not follow_redirects:
        handlers.append(_NoRedirect())
    return build_opener(*handlers)


def _get(url: str, follow_redirects: bool = True, read_body: bool = True):
    """Return (status, headers_dict, body_str). status None on transport error."""
    req = Request(url, headers={"User-Agent": UA})
    try:
        with _opener(follow_redirects).open(req, timeout=TIMEOUT) as resp:
            body = resp.read(200_000).decode("utf-8", "replace") if read_body else ""
            # file:// responses have no HTTP status; treat a readable body as 200.
            status = getattr(resp, "status", None) or 200
            headers = dict(resp.getheaders()) if hasattr(resp, "getheaders") else {}
            return status, headers, body
    except HTTPError as e:
        body = ""
        if read_body:
            try:
                body = e.read(200_000).decode("utf-8", "replace")
            except Exception:  # noqa
                body = ""
        return e.code, dict(e.headers or {}), body
    except (URLError, ssl.SSLError, ConnectionError, OSError, ValueError):
        return None, {}, ""
    except Exception:  # noqa
        return None, {}, ""


def _set_param(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[key] = value
    return urlunparse(p._replace(query=urlencode(q)))


def _base(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def check_exposed_files(url: str) -> list[dict]:
    findings = []
    base = _base(url)
    for path, (sig, sev, note) in SENSITIVE_PATHS.items():
        status, _, body = _get(base + path, follow_redirects=False)
        if status != 200:
            continue
        if sig is None or sig in body:
            findings.append({"severity": sev, "category": "exposure",
                             "title": f"Reachable {path}", "detail": note,
                             "url": base + path})
    return findings


def check_open_redirect(url: str) -> list[dict]:
    findings = []
    p = urlparse(url)
    existing = {k.lower() for k, _ in parse_qsl(p.query)}
    params = [k for k in REDIRECT_PARAMS if k in existing] or ["next", "redirect", "url"]
    payload = f"https://{EVIL_HOST}/"
    for key in params:
        test = _set_param(url, key, payload)
        status, headers, _ = _get(test, follow_redirects=False, read_body=False)
        loc = {k.lower(): v for k, v in headers.items()}.get("location", "")
        if status and 300 <= status < 400 and loc:
            netloc = urlparse(loc if "//" in loc else "https://" + loc.lstrip("/")).netloc.lower()
            if netloc == EVIL_HOST or loc.startswith(payload) or loc.startswith("//" + EVIL_HOST):
                findings.append({"severity": "medium", "category": "open-redirect",
                                 "title": f"Open redirect via '{key}'",
                                 "detail": f"Location -> {loc[:80]}", "url": test})
                break
    return findings


def check_reflected_xss(url: str) -> list[dict]:
    findings = []
    p = urlparse(url)
    params = [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]
    if not params:
        params = ["q"]  # probe a common param even if none present
    probe = f'{MARKER}"><svg/onload=1>'
    for key in params:
        test = _set_param(url, key, probe)
        status, headers, body = _get(test)
        ctype = {k.lower(): v for k, v in headers.items()}.get("content-type", "")
        if status and "html" in ctype.lower() and probe in body:
            findings.append({"severity": "high", "category": "xss",
                             "title": f"Reflected XSS candidate in '{key}'",
                             "detail": "Injected markup reflected unencoded in HTML response.",
                             "url": test})
    return findings


def check_path_traversal(url: str) -> list[dict]:
    findings = []
    p = urlparse(url)
    existing = {k.lower() for k, _ in parse_qsl(p.query)}
    params = [k for k in TRAVERSAL_PARAMS if k in existing]
    if not params and not existing:
        params = ["file"]  # light probe
    for key in params:
        for payload, sig in TRAVERSAL_PAYLOADS:
            test = _set_param(url, key, payload)
            status, _, body = _get(test)
            if status == 200 and sig.search(body):
                findings.append({"severity": "high", "category": "path-traversal",
                                 "title": f"Path traversal via '{key}'",
                                 "detail": "Local file content returned (LFI).",
                                 "url": test})
                break
    return findings


def check_header_injection(url: str) -> list[dict]:
    """CRLF injection / HTTP response splitting: a param value breaks into a new header."""
    findings = []
    p = urlparse(url)
    existing = [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]
    params = existing or ["redirect", "next", "url"]
    # CRLF then a marker header; urlencode turns \r\n into %0D%0A
    payload = f"{MARKER}\r\n{INJ_HEADER}: {MARKER}"
    for key in list(dict.fromkeys(params + list(HEADER_INJ_PARAMS)))[:8]:
        test = _set_param(url, key, payload)
        status, headers, _ = _get(test, follow_redirects=False, read_body=False)
        low = {k.lower(): v for k, v in headers.items()}
        if INJ_HEADER in low and MARKER in low.get(INJ_HEADER, ""):
            findings.append({"severity": "high", "category": "header-injection",
                             "title": f"CRLF header injection via '{key}'",
                             "detail": "Param value split into a new response header (response splitting).",
                             "url": test})
            break
    return findings


def check_ssti(url: str) -> list[dict]:
    """Server-Side Template Injection: an expression is evaluated, not just reflected."""
    findings = []
    p = urlparse(url)
    params = [k for k, _ in parse_qsl(p.query, keep_blank_values=True)] or ["q", "name"]
    for key in params:
        for payload in SSTI_PAYLOADS:
            test = _set_param(url, key, payload)
            status, _, body = _get(test)
            # evaluated result present AND the raw expression absent => real evaluation
            if status and _PRODUCT in body and payload not in body:
                findings.append({"severity": "high", "category": "ssti",
                                 "title": f"Template injection (SSTI) in '{key}'",
                                 "detail": f"'{payload}' evaluated to {_PRODUCT} server-side.",
                                 "url": test})
                return findings  # one confirmed engine is enough
    return findings


def check_ssrf(url: str, callback: str | None = None) -> list[dict]:
    """SSRF: a url-taking param fetches attacker-supplied targets (metadata/file proof + OAST)."""
    findings = []
    p = urlparse(url)
    existing = {k.lower() for k, _ in parse_qsl(p.query)}
    hit_params = [k for k in SSRF_PARAMS if k in existing]
    for key in hit_params:
        for payload, sig, sev, label in SSRF_PROBES:
            test = _set_param(url, key, payload)
            status, _, body = _get(test)
            if status and sig.search(body):
                findings.append({"severity": sev, "category": "ssrf",
                                 "title": f"SSRF via '{key}' — {label}",
                                 "detail": "Server fetched an internal/metadata/file target — high impact.",
                                 "url": test})
                return findings  # confirmed; stop probing this endpoint
    # Blind SSRF: fire an OAST callback the tester controls, then check their collaborator.
    if callback and hit_params:
        for key in hit_params:
            marker = f"{MARKER}-{key}"
            probe = callback.rstrip("/") + "/" + marker
            _get(_set_param(url, key, probe), read_body=False)
        findings.append({"severity": "info", "category": "ssrf",
                         "title": f"OAST SSRF probe sent via {', '.join(hit_params)}",
                         "detail": f"Injected {callback} into url-param(s); check your collaborator for a hit.",
                         "url": url})
    elif hit_params:
        findings.append({"severity": "info", "category": "ssrf",
                         "title": f"SSRF candidate param(s): {', '.join(hit_params)}",
                         "detail": "URL-taking parameter — verify with an out-of-band (OOB) callback (--ssrf-callback).",
                         "url": url})
    return findings


def check_dir_listing(url: str) -> list[dict]:
    status, _, body = _get(url)
    if status == 200 and re.search(r"<title>\s*Index of /|Directory listing for", body, re.I):
        return [{"severity": "low", "category": "exposure",
                 "title": "Directory listing enabled", "detail": "Autoindex exposes file names.",
                 "url": url}]
    return []


ACTIVE_CHECKS = (check_exposed_files, check_open_redirect, check_reflected_xss,
                 check_path_traversal, check_header_injection, check_ssti,
                 check_ssrf, check_dir_listing)


def run_active(url: str, callback: str | None = None) -> list[dict]:
    """Run all active checks against a single URL. Never raises."""
    findings = []
    for chk in ACTIVE_CHECKS:
        try:
            findings.extend(chk(url, callback) if chk is check_ssrf else chk(url))
        except Exception as e:  # noqa
            findings.append({"severity": "info", "category": "error",
                             "title": f"{chk.__name__} failed", "detail": str(e), "url": url})
    return findings


def main() -> int:
    import argparse
    import json
    import sys
    ap = argparse.ArgumentParser(description="Non-destructive active web vuln checks.")
    ap.add_argument("url")
    ap.add_argument("--authorized", action="store_true",
                    help="Confirm you own/are authorized to test this target (required).")
    ap.add_argument("--ssrf-callback", help="OAST/collaborator URL for blind-SSRF confirmation.")
    args = ap.parse_args()
    if not args.authorized:
        print("[!] Active checks send probes to the target. Re-run with --authorized.", file=sys.stderr)
        return 2
    if urlparse(args.url).scheme not in ("http", "https"):
        ap.error("URL must start with http:// or https://")
    findings = run_active(args.url, args.ssrf_callback)
    real = [f for f in findings if f["severity"] not in ("info",)]
    print(json.dumps(findings, indent=2))
    print(f"\n[+] {len(real)} active finding(s).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
