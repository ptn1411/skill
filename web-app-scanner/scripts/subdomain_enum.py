#!/usr/bin/env python3
"""
subdomain_enum.py — Subdomain discovery for authorized targets (Windows-first, stdlib).

Passive sources (low-impact, no target traffic):
  * crt.sh   Certificate Transparency logs (queries the public crt.sh service)
  * subfinder (optional, only if installed)  passive source aggregation

Active source (gated behind --authorized, sends DNS/HTTP to the target zone):
  * --brute WORDLIST   resolve WORD.domain for each word (DNS brute force)

For every candidate it resolves DNS and probes HTTP(S) liveness, then writes
subdomains.json + SUBDOMAINS.md to --out.

Usage:
    python subdomain_enum.py example.com --out output/subs
    python subdomain_enum.py example.com --brute wordlists/subdomains.txt --authorized --out output/subs
    python subdomain_enum.py --check

Only enumerate domains you own or are explicitly authorized to assess (MASTER_POLICY.md §1).
Note: crt.sh discovery sends the target domain name to the public crt.sh service.
"""

import argparse
import concurrent.futures
import json
import shutil
import socket
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

UA = "web-app-scanner/2.0 (authorized-recon)"
TIMEOUT = 12


def _clean_host(name: str, apex: str) -> str | None:
    name = name.strip().lower().lstrip("*.").rstrip(".")
    if not name or " " in name:
        return None
    if name == apex or name.endswith("." + apex):
        return name
    return None


def passive_crtsh(domain: str) -> set[str]:
    """Query crt.sh Certificate Transparency logs. Returns a set of hostnames."""
    found: set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = Request(url, headers={"User-Agent": UA})
    try:
        with urlopen(req, timeout=25, context=ssl.create_default_context()) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except (HTTPError, URLError, ValueError, TimeoutError) as e:
        print(f"[i] crt.sh unavailable: {e}")
        return found
    except Exception as e:  # noqa
        print(f"[i] crt.sh error: {e}")
        return found
    for entry in data if isinstance(data, list) else []:
        for field in ("name_value", "common_name"):
            val = entry.get(field, "")
            for line in str(val).splitlines():
                host = _clean_host(line, domain)
                if host:
                    found.add(host)
    print(f"[+] crt.sh: {len(found)} unique name(s)")
    return found


def passive_subfinder(domain: str) -> set[str]:
    """Run subfinder if installed (passive mode)."""
    found: set[str] = set()
    if not shutil.which("subfinder"):
        return found
    print("[*] Running subfinder ...")
    try:
        r = subprocess.run(["subfinder", "-d", domain, "-silent"],
                           capture_output=True, text=True, timeout=300)
        for line in r.stdout.splitlines():
            host = _clean_host(line, domain)
            if host:
                found.add(host)
        print(f"[+] subfinder: {len(found)} name(s)")
    except Exception as e:  # noqa
        print(f"[i] subfinder failed: {e}")
    return found


def dns_brute(domain: str, wordlist: Path, workers: int = 40) -> set[str]:
    """Resolve WORD.domain for each word in the wordlist. Active DNS traffic."""
    found: set[str] = set()
    try:
        words = [w.strip() for w in wordlist.read_text(encoding="utf-8", errors="ignore").splitlines()
                 if w.strip() and not w.startswith("#")]
    except OSError as e:
        print(f"[!] cannot read wordlist {wordlist}: {e}")
        return found
    print(f"[*] DNS brute: {len(words)} candidate label(s)")

    def probe(word: str) -> str | None:
        host = f"{word}.{domain}"
        if resolve(host):
            return host
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for host in ex.map(probe, words):
            if host:
                found.add(host)
    print(f"[+] DNS brute: {len(found)} resolvable name(s)")
    return found


def resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, socket.timeout, OSError):
        return None


# Dangling-CNAME takeover fingerprints (subset of can-i-take-over-xyz).
# (service, cname substring, body signature regex)
import re as _re
TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages", "github.io", _re.compile(r"There isn't a GitHub Pages site here", _re.I)),
    ("AWS/S3", "amazonaws.com", _re.compile(r"NoSuchBucket|The specified bucket does not exist", _re.I)),
    ("Heroku", "herokudns.com", _re.compile(r"No such app|no-such-app", _re.I)),
    ("Heroku", "herokuapp.com", _re.compile(r"No such app|no-such-app", _re.I)),
    ("Azure", "azurewebsites.net", _re.compile(r"404 Web Site not found", _re.I)),
    ("Azure", "cloudapp.net", _re.compile(r"404 Web Site not found", _re.I)),
    ("Azure TM", "trafficmanager.net", _re.compile(r"404 Web Site not found", _re.I)),
    ("Fastly", "fastly.net", _re.compile(r"Fastly error: unknown domain", _re.I)),
    ("Shopify", "myshopify.com", _re.compile(r"Sorry, this shop is currently unavailable", _re.I)),
    ("Surge.sh", "surge.sh", _re.compile(r"project not found", _re.I)),
    ("Bitbucket", "bitbucket.io", _re.compile(r"Repository not found", _re.I)),
    ("Zendesk", "zendesk.com", _re.compile(r"Help Center Closed", _re.I)),
    ("Pantheon", "pantheonsite.io", _re.compile(r"The gods are wise|404 error unknown site", _re.I)),
    ("Readme.io", "readme.io", _re.compile(r"Project doesnt exist", _re.I)),
    ("Ghost", "ghost.io", _re.compile(r"The thing you were looking for is no longer here", _re.I)),
    ("AWS/CloudFront", "cloudfront.net", _re.compile(r"The request could not be satisfied", _re.I)),
    ("Vercel", "vercel.app", _re.compile(r"The deployment could not be found|DEPLOYMENT_NOT_FOUND", _re.I)),
    ("Netlify", "netlify.app", _re.compile(r"Not Found - Request ID|no such site", _re.I)),
    ("Tumblr", "domains.tumblr.com", _re.compile(r"Whatever you were looking for doesn't currently exist", _re.I)),
    ("WordPress", "wordpress.com", _re.compile(r"Do you want to register .*\.wordpress\.com", _re.I)),
    ("Tilda", "tilda.ws", _re.compile(r"Please renew your subscription", _re.I)),
    ("Help Scout", "helpscoutdocs.com", _re.compile(r"No settings were found for this company", _re.I)),
    ("Desk", "desk.com", _re.compile(r"Please try again or try Desk\.com free", _re.I)),
]
_CNAME_RE = _re.compile(r"canonical name\s*=\s*([A-Za-z0-9._-]+)", _re.I)
# Stale DNS verification tokens left after a service was decommissioned (takeover hint).
_VERIFICATION_TAGS = ("_github-pages-challenge", "asuid.", "_dnsauth", "_amazonses",
                      "google-site-verification", "_acme-challenge")


def get_txt(host: str) -> list[str]:
    """Return TXT record strings via nslookup (best-effort)."""
    try:
        r = subprocess.run(["nslookup", "-type=TXT", host],
                           capture_output=True, text=True, timeout=10)
    except Exception:  # noqa
        return []
    return _re.findall(r'text\s*=\s*"([^"]*)"', r.stdout or "", _re.I)


def get_cname(host: str) -> str | None:
    """Resolve CNAME via nslookup (built into Windows & most Linux). Returns lowercase target."""
    try:
        r = subprocess.run(["nslookup", "-type=CNAME", host],
                           capture_output=True, text=True, timeout=10)
    except Exception:  # noqa
        return None
    m = _CNAME_RE.search(r.stdout or "")
    return m.group(1).rstrip(".").lower() if m else None


def check_takeover(host: str) -> dict | None:
    """Flag a dangling CNAME pointing to a decommissioned service (potential takeover)."""
    cname = get_cname(host)
    if not cname:
        return None
    for service, needle, sig in TAKEOVER_FINGERPRINTS:
        if needle not in cname:
            continue
        # Fetch the host and look for the service's "not claimed" fingerprint.
        for scheme in ("https", "http"):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = Request(f"{scheme}://{host}/", headers={"User-Agent": UA})
                with urlopen(req, timeout=TIMEOUT,
                             context=ctx if scheme == "https" else None) as resp:
                    body = resp.read(60_000).decode("utf-8", "replace")
            except HTTPError as e:
                try:
                    body = e.read(60_000).decode("utf-8", "replace")
                except Exception:  # noqa
                    body = ""
            except Exception:  # noqa
                continue
            if sig.search(body):
                detail = f"CNAME -> {cname}; unclaimed-service fingerprint matched."
                tags = [t for host_txt in get_txt(host) for t in _VERIFICATION_TAGS
                        if t in host_txt or t in host]
                if tags:
                    detail += f" Stale verification token(s): {', '.join(sorted(set(tags)))}."
                return {"severity": "high", "category": "subdomain-takeover",
                        "title": f"Potential {service} subdomain takeover",
                        "detail": detail, "cname": cname, "service": service}
    return None


def check_alive(host: str) -> dict | None:
    """Probe https:// then http://. Return {host, ip, url, scheme, status, server} or None."""
    ip = resolve(host)
    if not ip:
        return None
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        req = Request(url, headers={"User-Agent": UA})
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # liveness only; TLS validity checked by web_recon
            with urlopen(req, timeout=TIMEOUT,
                         context=ctx if scheme == "https" else None) as resp:
                return {"host": host, "ip": ip, "url": url, "scheme": scheme,
                        "status": resp.status, "server": resp.headers.get("Server", "")}
        except HTTPError as e:
            return {"host": host, "ip": ip, "url": url, "scheme": scheme,
                    "status": e.code, "server": (e.headers or {}).get("Server", "")}
        except (URLError, socket.timeout, ssl.SSLError, ConnectionError, OSError):
            continue
        except Exception:  # noqa
            continue
    return {"host": host, "ip": ip, "url": None, "scheme": None,
            "status": None, "server": ""}  # resolves but no web service


def to_markdown(domain: str, results: list[dict]) -> str:
    alive = [r for r in results if r.get("url")]
    takeovers = [r for r in results if r.get("takeover")]
    lines = [f"# Subdomain Enumeration — {domain}", "",
             f"Discovered: **{len(results)}** subdomain(s) · Web-alive: **{len(alive)}** · "
             f"Potential takeover: **{len(takeovers)}**", ""]
    if takeovers:
        lines += ["## ⚠ Potential subdomain takeover", "",
                  "| Host | CNAME | Service |", "|---|---|---|"]
        for r in takeovers:
            tk = r["takeover"]
            lines.append(f"| {r['host']} | {tk['cname']} | {tk['service']} |")
        lines.append("")
    lines += ["## Hosts", "", "| Host | IP | Web | Status | Server |", "|---|---|---|---|---|"]
    for r in sorted(results, key=lambda x: x["host"]):
        web = r.get("url") or "—"
        status = r.get("status") if r.get("status") is not None else "—"
        server = (r.get("server") or "").replace("|", "\\|")[:40]
        flag = " ⚠takeover" if r.get("takeover") else ""
        lines.append(f"| {r['host']}{flag} | {r.get('ip','?')} | {web} | {status} | {server} |")
    lines.append("")
    lines.append("Feed the web-alive URLs into `web_recon.py --active` "
                 "(or run `scan_all.py` to chain both).")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Authorized subdomain enumeration.")
    ap.add_argument("domain", nargs="?", help="Apex domain, e.g. example.com")
    ap.add_argument("--out", default="output/subs")
    ap.add_argument("--brute", metavar="WORDLIST", help="DNS brute force with this wordlist (active).")
    ap.add_argument("--authorized", action="store_true",
                    help="Confirm authorization (required for --brute active DNS traffic).")
    ap.add_argument("--no-crtsh", action="store_true", help="Skip crt.sh passive source.")
    ap.add_argument("--takeover", action="store_true",
                    help="Check each host for dangling-CNAME subdomain takeover.")
    ap.add_argument("--workers", type=int, default=40, help="Liveness probe concurrency.")
    ap.add_argument("--check", action="store_true", help="Report which optional tools are available.")
    args = ap.parse_args()

    if args.check:
        print(f"[{'+' if shutil.which('subfinder') else 'i'}] subfinder: "
              f"{shutil.which('subfinder') or 'not installed (crt.sh still works)'}")
        return 0

    if not args.domain:
        ap.error("domain is required (unless --check).")
    domain = args.domain.strip().lower().lstrip("*.").rstrip(".")
    if "/" in domain or ":" in domain:
        ap.error("Provide a bare domain (example.com), not a URL.")

    if args.brute and not args.authorized:
        print("[!] --brute sends active DNS queries to the target zone.", file=sys.stderr)
        print("    Re-run with --authorized to confirm scope.", file=sys.stderr)
        return 2

    candidates: set[str] = set()
    if not args.no_crtsh:
        candidates |= passive_crtsh(domain)
    candidates |= passive_subfinder(domain)
    if args.brute:
        candidates |= dns_brute(domain, Path(args.brute), args.workers)
    candidates.add(domain)  # always include the apex

    print(f"[*] Probing liveness for {len(candidates)} host(s) ...")
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for r in ex.map(check_alive, sorted(candidates)):
            if r:
                results.append(r)

    if args.takeover:
        print("[*] Checking for dangling-CNAME subdomain takeover ...")
        hosts = [r["host"] for r in results]
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.workers, 20)) as ex:
            takeovers = list(ex.map(check_takeover, hosts))
        n = 0
        for r, tk in zip(results, takeovers):
            if tk:
                r["takeover"] = tk
                n += 1
                print(f"[!] Potential takeover: {r['host']} -> {tk['cname']} ({tk['service']})")
        print(f"[+] Takeover check: {n} potential finding(s)")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "subdomains.json").write_text(
        json.dumps({"domain": domain, "count": len(results), "subdomains": results}, indent=2),
        encoding="utf-8")
    (out_dir / "SUBDOMAINS.md").write_text(to_markdown(domain, results), encoding="utf-8")

    alive = [r for r in results if r.get("url")]
    print(f"[+] {len(results)} resolvable, {len(alive)} web-alive. "
          f"Report: {out_dir / 'SUBDOMAINS.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
