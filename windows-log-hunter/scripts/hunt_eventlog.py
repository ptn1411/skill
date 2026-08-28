#!/usr/bin/env python3
"""
hunt_eventlog.py — Blue-team Windows Event Log threat hunt (CLI, Windows-first).

Two engines:
  * hayabusa (if installed / --engine hayabusa): fast Sigma-based timeline over
    evtx files or the live log directory.
  * native  (default): PowerShell Get-WinEvent sweep of high-signal event IDs,
    no external tools required.

Both feed parse_findings.py, which writes FINDINGS.md + findings.json.

Usage:
    python hunt_eventlog.py --check
    python hunt_eventlog.py --hours 24 --out output/hunt
    python hunt_eventlog.py --engine hayabusa --logdir C:\\Windows\\System32\\winevt\\Logs --out output/hunt

Defensive use only. Analyze systems you own or are authorized to assess.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def find_powershell() -> str | None:
    for exe in ("pwsh", "powershell"):
        p = shutil.which(exe)
        if p:
            return p
    return None


def find_hayabusa() -> str | None:
    for name in ("hayabusa", "hayabusa.exe"):
        p = shutil.which(name)
        if p:
            return p
    return None


def check() -> int:
    print("[*] windows-log-hunter environment check")
    ps = find_powershell()
    print(f"[+] PowerShell : {ps or 'NOT found'}")
    hb = find_hayabusa()
    print(f"[{'+' if hb else 'i'}] hayabusa   : {hb or 'not found (optional; native engine used)'}")
    if os.name != "nt":
        print("[i] Not on Windows — native engine needs Windows Event Log. hayabusa can parse .evtx anywhere.")
    is_admin = False
    if os.name == "nt":
        try:
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass
        print(f"[{'+' if is_admin else 'i'}] Admin      : {'yes' if is_admin else 'NO - Security log may be unreadable; run PowerShell as Administrator'}")
    return 0 if ps or hb else 1


def run_native(hours: int, max_events: int, out_dir: Path) -> Path | None:
    ps = find_powershell()
    if not ps:
        print("[!] PowerShell not found; cannot run native engine.", file=sys.stderr)
        return None
    events_json = out_dir / "events.json"
    script = HERE / "native_hunt.ps1"
    cmd = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
           "-Hours", str(hours), "-Max", str(max_events), "-Out", str(events_json)]
    print(f"[*] Native hunt: last {hours}h, up to {max_events}/category")
    subprocess.run(cmd)
    return events_json if events_json.exists() else None


def run_hayabusa(hb: str, logdir: str, out_dir: Path) -> Path | None:
    csv_out = out_dir / "hayabusa.csv"
    cmd = [hb, "csv-timeline", "-d", logdir, "-o", str(csv_out),
           "-p", "standard", "--no-wizard", "-w"]
    print(f"[*] hayabusa timeline over {logdir}")
    subprocess.run(cmd)
    return csv_out if csv_out.exists() else None


def main() -> int:
    ap = argparse.ArgumentParser(description="Windows Event Log threat hunt (blue team).")
    ap.add_argument("--engine", choices=["native", "hayabusa"], default="native")
    ap.add_argument("--hours", type=int, default=24, help="Lookback window (native engine).")
    ap.add_argument("--max", type=int, default=200, help="Max events per category (native engine).")
    ap.add_argument("--logdir", default=r"C:\Windows\System32\winevt\Logs",
                    help="evtx directory (hayabusa engine).")
    ap.add_argument("--out", default="output/hunt", help="Output directory.")
    ap.add_argument("--check", action="store_true", help="Check environment and exit.")
    ap.add_argument("--no-parse", action="store_true")
    args = ap.parse_args()

    if args.check:
        return check()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    engine = args.engine
    if engine == "hayabusa" and not find_hayabusa():
        print("[!] hayabusa requested but not found; falling back to native.", file=sys.stderr)
        engine = "native"

    if engine == "hayabusa":
        raw = run_hayabusa(find_hayabusa(), args.logdir, out_dir)
        kind = "hayabusa"
    else:
        raw = run_native(args.hours, args.max, out_dir)
        kind = "native"

    if not raw:
        print("[!] No raw output produced.", file=sys.stderr)
        return 1

    print(f"[+] Raw: {raw}")
    if not args.no_parse:
        parser = HERE / "parse_findings.py"
        if parser.exists():
            subprocess.run([sys.executable, str(parser), str(raw),
                            "--kind", kind, "--out", str(out_dir)])
    return 0


if __name__ == "__main__":
    sys.exit(main())
