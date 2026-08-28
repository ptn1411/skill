#!/usr/bin/env python3
"""
assess.py — Master dispatcher: classify a target and route to the right skill.

One entry point for authorized assessment. It looks at the target and decides
which toolkit skill fits, then runs it (or just prints the decision with --dry-run).

Routing:
    IPv4 / CIDR / IP-range        -> network-scanner   (nmap port/service scan)
    http(s):// URL (web app)      -> web-app-scanner    (headers/TLS/CORS recon)
    http(s):// ...*.js.map        -> orchestrate.py     (JS sourcemap recovery)
    'winlogs' / 'eventlog' / host -> windows-log-hunter (event-log threat hunt)
    existing file / directory     -> orchestrate.py     (artifact audit)

Usage:
    python scripts/assess.py 192.168.1.0/24
    python scripts/assess.py https://app.local
    python scripts/assess.py winlogs --hours 48
    python scripts/assess.py "C:/path/to/app.exe"
    python scripts/assess.py https://app.local --dry-run
    python scripts/assess.py 10.0.0.5 --type network -- -p 22,80,443

Only assess targets you own or are authorized to test (see MASTER_POLICY.md).
"""

import argparse
import ipaddress
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable

CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
RANGE_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}-\d{1,3}$")
LOG_SENTINELS = {"winlogs", "winlog", "eventlog", "eventlogs", "logs", "localhost", "."}


def is_ip_like(t: str) -> bool:
    if CIDR_RE.match(t) or RANGE_RE.match(t):
        return True
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


def classify(target: str, forced: str | None = None) -> tuple[str, str]:
    """Return (kind, reason). kind in {network, web, jsmap, winlog, artifact, unknown}."""
    if forced:
        return forced, "forced by --type"

    t = target.strip()

    if t.lower() in LOG_SENTINELS:
        return "winlog", "log sentinel / local host -> event-log hunt"

    if "://" in t:
        if t.lower().endswith(".js.map") or t.lower().endswith(".map"):
            return "jsmap", "sourcemap URL -> JS recovery"
        if t.lower().startswith(("http://", "https://")):
            return "web", "http(s) URL -> web app recon"
        return "unknown", "unrecognized URL scheme"

    if is_ip_like(t):
        return "network", "IP / CIDR / range -> port & service scan"

    p = Path(t)
    if p.exists():
        return "artifact", "existing path -> artifact audit"

    # bare hostname (has a dot, not a path) -> treat as network host
    if re.match(r"^[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", t):
        return "network", "hostname -> port & service scan (use a full URL for web recon)"

    return "unknown", "could not classify target"


def run(cmd: list[str]) -> int:
    print(f"[*] exec: {' '.join(cmd)}\n")
    return subprocess.run(cmd).returncode


def build_command(kind: str, target: str, out: str, extra: list[str]) -> list[str] | None:
    if kind == "network":
        s = REPO_ROOT / "network-scanner" / "scripts" / "nmap_scan.py"
        return [PYTHON, str(s), target, "--out", f"{out}/nmap", *extra]
    if kind == "web":
        s = REPO_ROOT / "web-app-scanner" / "scripts" / "web_recon.py"
        return [PYTHON, str(s), target, "--out", f"{out}/web", *extra]
    if kind == "winlog":
        s = REPO_ROOT / "windows-log-hunter" / "scripts" / "hunt_eventlog.py"
        return [PYTHON, str(s), "--out", f"{out}/hunt", *extra]
    if kind in ("artifact", "jsmap"):
        s = REPO_ROOT / "scripts" / "orchestrate.py"
        return [PYTHON, str(s), target, "--out", out, *extra]
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Master assessment dispatcher.")
    ap.add_argument("target", help="IP/CIDR, URL, 'winlogs', or file/dir path.")
    ap.add_argument("--type", choices=["network", "web", "winlog", "artifact", "jsmap"],
                    help="Force the target kind instead of auto-detecting.")
    ap.add_argument("--out", default="output", help="Base output directory (default: output).")
    ap.add_argument("--dry-run", action="store_true", help="Show routing decision without running.")
    ap.add_argument("extra", nargs="*", help="Extra args forwarded to the chosen skill (after --).")
    args = ap.parse_args()

    kind, reason = classify(args.target, args.type)
    print(f"[=] Target : {args.target}")
    print(f"[=] Route  : {kind}  ({reason})")

    if kind == "unknown":
        print("[!] Could not classify. Force it with --type "
              "{network|web|winlog|artifact|jsmap}.", file=sys.stderr)
        return 2

    extra = [a for a in args.extra if a != "--"]
    cmd = build_command(kind, args.target, args.out.rstrip("/"), extra)
    if not cmd:
        print("[!] No command for this kind.", file=sys.stderr)
        return 2

    if args.dry_run:
        print(f"[i] would run: {' '.join(cmd)}")
        return 0

    return run(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
