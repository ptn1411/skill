#!/usr/bin/env python3
"""
nmap_scan.py — Authorized Nmap reconnaissance wrapper (Windows-first, cross-platform).

Locates the nmap binary (PATH or default Windows install), runs a chosen scan
profile against an authorized target, saves raw output (XML + .nmap), and calls
the parser to emit a defensive findings report.

Usage:
    python nmap_scan.py --check
    python nmap_scan.py 192.168.1.0/24 --profile discovery --out output/nmap
    python nmap_scan.py 192.168.1.10   --profile service   --out output/nmap
    python nmap_scan.py 10.0.0.5 --profile service --out output/nmap -- -p 22,80,443

Only scan hosts you own or are explicitly authorized to assess (see MASTER_POLICY.md).
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

# profile -> nmap flag list
PROFILES = {
    "discovery":    ["-sn"],
    "quick":        ["-T4", "-F"],
    "service":      ["-sV", "-T4", "--top-ports", "1000"],
    "full":         ["-p-", "-sV", "-T4"],
    "os":           ["-O", "-sV"],
    "safe-scripts": ["-sV", "-sC"],
    "vuln":         ["-sV", "--script", "vuln"],
}

# NSE categories / flags refused unless --allow-intrusive is set
INTRUSIVE_TOKENS = ("dos", "exploit", "brute", "intrusive")

WINDOWS_DEFAULT_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]


def find_nmap() -> str | None:
    """Return path to nmap binary, or None."""
    found = shutil.which("nmap")
    if found:
        return found
    for p in WINDOWS_DEFAULT_PATHS:
        if Path(p).exists():
            return p
    return None


def is_admin() -> bool:
    """Best-effort admin/root check for raw-packet scan capability."""
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def check(nmap: str | None) -> int:
    print("[*] network-scanner environment check")
    if not nmap:
        print("[!] nmap NOT found.")
        print("    Install (recommended): download the latest installer from")
        print("      https://nmap.org/download.html  and run it AS ADMINISTRATOR")
        print("      (it bundles Npcap, whose driver needs elevation).")
        print("    Note: 'winget install Insecure.Nmap' is currently broken (stale 7.80 URL).")
        return 1
    print(f"[+] nmap found: {nmap}")
    try:
        out = subprocess.run([nmap, "--version"], capture_output=True, text=True, timeout=15)
        print("    " + out.stdout.splitlines()[0])
    except Exception as e:
        print(f"[!] Could not run nmap --version: {e}")
    print(f"[+] Admin/root privileges: {'yes' if is_admin() else 'NO (falls back to -sT connect scan / no -O/-sS)'}")
    return 0


def contains_intrusive(tokens: list[str]) -> bool:
    joined = " ".join(tokens).lower()
    return any(t in joined for t in INTRUSIVE_TOKENS)


def main() -> int:
    ap = argparse.ArgumentParser(description="Authorized Nmap reconnaissance wrapper.")
    ap.add_argument("target", nargs="?", help="Host, CIDR, or range to scan (must be authorized).")
    ap.add_argument("--profile", default="service", choices=list(PROFILES.keys()),
                    help="Scan profile (default: service).")
    ap.add_argument("--out", default="output/nmap", help="Output directory (default: output/nmap).")
    ap.add_argument("--name", default="scan", help="Base name for output files (default: scan).")
    ap.add_argument("--allow-intrusive", action="store_true",
                    help="Permit dos/exploit/brute/intrusive NSE (requires explicit authorization).")
    ap.add_argument("--check", action="store_true", help="Check environment and exit.")
    ap.add_argument("--no-parse", action="store_true", help="Skip the findings parser.")
    ap.add_argument("extra", nargs="*", help="Extra raw nmap flags after --.")
    args = ap.parse_args()

    nmap = find_nmap()
    if args.check:
        return check(nmap)

    if not nmap:
        print("[!] nmap not found. Run with --check for install instructions.", file=sys.stderr)
        return 1
    if not args.target:
        ap.error("target is required (unless --check).")

    extra = [a for a in args.extra if a != "--"]
    flags = PROFILES[args.profile]

    if (contains_intrusive(flags) or contains_intrusive(extra)) and not args.allow_intrusive:
        print("[!] Refusing intrusive NSE (dos/exploit/brute/intrusive) without --allow-intrusive.", file=sys.stderr)
        print("    Confirm you are authorized for active/intrusive testing, then re-run with --allow-intrusive.", file=sys.stderr)
        return 2

    if args.profile in ("os", "full") and not is_admin() and os.name == "nt":
        print("[i] Not running as Administrator — OS detection / raw scans may be limited. "
              "Re-run PowerShell as Admin for full results.")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    xml_path = out_dir / f"{args.name}.xml"

    # -oA writes .xml/.nmap/.gnmap with the given base
    cmd = [nmap, *flags, *extra, "-oX", str(xml_path),
           "-oN", str(out_dir / f"{args.name}.nmap"), args.target]

    print(f"[*] Target      : {args.target}")
    print(f"[*] Profile     : {args.profile}  ({' '.join(flags)})")
    if extra:
        print(f"[*] Extra flags : {' '.join(extra)}")
    print(f"[*] Command     : {' '.join(cmd)}\n")

    try:
        proc = subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        return 130

    if proc.returncode != 0:
        print(f"[!] nmap exited with code {proc.returncode}.", file=sys.stderr)

    print(f"\n[+] Raw output: {xml_path}")

    if not args.no_parse and xml_path.exists():
        parser = Path(__file__).with_name("parse_nmap.py")
        if parser.exists():
            print("[*] Parsing findings...")
            subprocess.run([sys.executable, str(parser), str(xml_path), "--out", str(out_dir)])
    return 0


if __name__ == "__main__":
    sys.exit(main())
