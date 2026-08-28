#!/usr/bin/env python3
"""
sqli_test.py — Authorized SQL injection testing via sqlmap (safe defaults).

Wraps sqlmap for detection of SQLi on a target you own/are authorized to test.
Enforces guardrails:
  * Requires --authorized (explicit confirmation of scope).
  * Defaults to --level 1 --risk 1 --batch (low-impact detection).
  * Blocks data-exfiltration / OS-takeover switches (--dump*, --os-shell,
    --os-pwn, --file-read, --sql-shell, ...) unless --allow-exploit is set,
    which is intended only for a documented, authorized engagement.

Accepts either a URL or a saved raw HTTP request file (e.g. exported from Burp).

Usage:
    python sqli_test.py --check
    python sqli_test.py "https://app.local/item?id=1" --authorized --out output/sqli
    python sqli_test.py --request req.txt --authorized --out output/sqli
    python sqli_test.py "https://app.local/item?id=1" --authorized --level 3 --risk 2 --out output/sqli

Detection only by default. Never run against systems you are not authorized to test.
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

# switches that turn detection into exploitation / data theft — gated
EXPLOIT_FLAGS = ("--dump", "--dump-all", "--os-shell", "--os-pwn", "--os-cmd",
                 "--file-read", "--file-write", "--sql-shell", "--passwords",
                 "--all", "--reg-read")


def find_sqlmap() -> list[str] | None:
    """Return a command prefix that launches sqlmap, or None."""
    exe = shutil.which("sqlmap")
    if exe:
        return [exe]
    # pip-installed module
    try:
        r = subprocess.run([sys.executable, "-m", "sqlmap", "--version"],
                           capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            return [sys.executable, "-m", "sqlmap"]
    except Exception:
        pass
    return None


def check() -> int:
    cmd = find_sqlmap()
    if not cmd:
        print("[!] sqlmap not found.")
        print("    Install: pip install sqlmap   (or clone https://github.com/sqlmapproject/sqlmap)")
        return 1
    print(f"[+] sqlmap launcher: {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd + ["--version"], capture_output=True, text=True, timeout=20)
        print("    " + (r.stdout or r.stderr).strip().splitlines()[0])
    except Exception as e:
        print(f"[!] version check failed: {e}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Authorized SQLi testing via sqlmap.")
    ap.add_argument("url", nargs="?", help="Target URL with parameter(s).")
    ap.add_argument("--request", help="Path to a saved raw HTTP request (Burp export).")
    ap.add_argument("--authorized", action="store_true",
                    help="Confirm you own or are authorized to test this target (required).")
    ap.add_argument("--allow-exploit", action="store_true",
                    help="Permit data-dump / OS switches (documented engagements only).")
    ap.add_argument("--level", type=int, default=1, choices=range(1, 6))
    ap.add_argument("--risk", type=int, default=1, choices=range(1, 4))
    ap.add_argument("--out", default="output/sqli")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("extra", nargs="*", help="Extra sqlmap flags after --.")
    args = ap.parse_args()

    if args.check:
        return check()

    if not args.url and not args.request:
        ap.error("Provide a URL or --request FILE.")

    # --- Authorization guardrails run BEFORE we look for sqlmap ---
    if not args.authorized:
        print("[!] Refusing to run without --authorized.", file=sys.stderr)
        print("    SQLi testing is intrusive. Only test targets you own or are authorized to assess", file=sys.stderr)
        print("    (written engagement, bug-bounty scope, CTF, or your own lab). Re-run with --authorized.", file=sys.stderr)
        return 2

    extra = [a for a in args.extra if a != "--"]
    lowered = " ".join(extra).lower()
    hit = [f for f in EXPLOIT_FLAGS if f in lowered]
    if hit and not args.allow_exploit:
        print(f"[!] Blocked exploitation switch(es): {', '.join(hit)}", file=sys.stderr)
        print("    These dump data or take over the host. Use --allow-exploit only within a", file=sys.stderr)
        print("    documented, authorized engagement.", file=sys.stderr)
        return 2

    cmd = find_sqlmap()
    if not cmd:
        print("[!] sqlmap not found. Run with --check for install instructions.", file=sys.stderr)
        return 1

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    target = ["-r", args.request] if args.request else ["-u", args.url]
    full = cmd + target + [
        "--batch",
        "--level", str(args.level),
        "--risk", str(args.risk),
        "--output-dir", str(out_dir),
    ] + extra

    print(f"[*] Target : {args.request or args.url}")
    print(f"[*] Mode   : detection (level {args.level}, risk {args.risk})"
          + (" + EXPLOIT" if args.allow_exploit and hit else ""))
    print(f"[*] Command: {' '.join(full)}\n")

    try:
        proc = subprocess.run(full)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        return 130

    print(f"\n[+] sqlmap exit code: {proc.returncode}")
    print(f"[+] Session/output under: {out_dir}")
    print("[i] Review sqlmap's log for injectable parameters, DBMS, and technique.")
    print("[i] Defensive fix: use parameterized queries / prepared statements and least-privilege DB accounts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
