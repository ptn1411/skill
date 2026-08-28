#!/usr/bin/env python3
"""
scan_all.py — Whole-system web assessment orchestrator (authorized targets).

Chains the pieces into one run:
    1. subdomain_enum.py  — discover subdomains + web-alive hosts
    2. web_recon.py       — passive recon + (optional) active vuln checks per host
    3. aggregate          — one severity-ranked FINDINGS_ALL.md across the estate

Usage:
    python scan_all.py example.com --out output/scan
    python scan_all.py example.com --active --authorized --crawl 1 --out output/scan
    python scan_all.py example.com --active --authorized --brute wordlists/subs.txt --nuclei

Only assess domains you own or are explicitly authorized to test (MASTER_POLICY.md §1).
--active / --brute send probes to the target and REQUIRE --authorized.
"""

import argparse
import concurrent.futures
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _safe_name(host: str) -> str:
    return "".join(c if c.isalnum() or c in ".-" else "_" for c in host)


def run_subdomains(domain: str, out: Path, brute: str | None, authorized: bool,
                   takeover: bool) -> list[dict]:
    cmd = [sys.executable, str(SCRIPTS / "subdomain_enum.py"), domain, "--out", str(out / "subs")]
    if takeover:
        cmd.append("--takeover")
    if brute:
        cmd += ["--brute", brute]
        if authorized:
            cmd.append("--authorized")
    print(f"[*] Subdomain enumeration: {domain}")
    subprocess.run(cmd)
    data_file = out / "subs" / "subdomains.json"
    if not data_file.exists():
        return []
    data = json.loads(data_file.read_text(encoding="utf-8"))
    return [s for s in data.get("subdomains", []) if s.get("url")]


def scan_host(sub: dict, out: Path, active: bool, authorized: bool,
              crawl: int, nuclei: bool) -> dict:
    host = sub["host"]
    url = sub["url"]
    host_dir = out / "hosts" / _safe_name(host)
    cmd = [sys.executable, str(SCRIPTS / "web_recon.py"), url, "--out", str(host_dir)]
    if active:
        cmd.append("--active")
        if crawl:
            cmd += ["--crawl", str(crawl)]
        if authorized:
            cmd.append("--authorized")
    if nuclei:
        cmd.append("--nuclei")
    try:
        subprocess.run(cmd, timeout=1800)
    except subprocess.TimeoutExpired:
        print(f"[!] {host}: web_recon timed out")
    findings_file = host_dir / "findings.json"
    findings = []
    if findings_file.exists():
        try:
            findings = json.loads(findings_file.read_text(encoding="utf-8")).get("findings", [])
        except Exception:  # noqa
            findings = []
    return {"host": host, "url": url, "findings": findings}


def aggregate(domain: str, results: list[dict], out: Path) -> None:
    all_real = [f for r in results for f in r["findings"] if f.get("severity") != "info"]
    counts = Counter(f["severity"] for f in all_real)
    lines = [f"# Whole-System Findings — {domain}", "",
             f"Hosts assessed: **{len(results)}** · Non-info findings: **{len(all_real)}**", ""]
    if counts:
        lines.append("**Totals:** " + "  ".join(
            f"{k}: {counts[k]}" for k in sorted(counts, key=lambda s: SEV_ORDER.get(s, 9))))
        lines.append("")

    # Top-line per-host summary
    lines += ["## Hosts", "", "| Host | crit | high | med | low |", "|---|---|---|---|---|"]
    for r in sorted(results, key=lambda x: x["host"]):
        c = Counter(f["severity"] for f in r["findings"] if f.get("severity") != "info")
        lines.append(f"| {r['host']} | {c.get('critical',0)} | {c.get('high',0)} "
                     f"| {c.get('medium',0)} | {c.get('low',0)} |")
    lines.append("")

    # Detailed findings grouped by host (skip info)
    lines.append("## Findings by host")
    for r in sorted(results, key=lambda x: x["host"]):
        real = [f for f in r["findings"] if f.get("severity") != "info"]
        if not real:
            continue
        lines += ["", f"### {r['host']}", "",
                  "| Severity | Category | Finding | URL |", "|---|---|---|---|"]
        for f in sorted(real, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
            u = str(f.get("url", r["url"])).replace("|", "\\|")[:80]
            lines.append(f"| {f['severity']} | {f['category']} | {f['title']} | {u} |")

    (out / "FINDINGS_ALL.md").write_text("\n".join(lines), encoding="utf-8")
    (out / "findings_all.json").write_text(
        json.dumps({"domain": domain, "hosts": results}, indent=2), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Whole-system authorized web assessment.")
    ap.add_argument("domain", nargs="?", help="Apex domain, e.g. example.com")
    ap.add_argument("--out", default="output/scan")
    ap.add_argument("--active", action="store_true", help="Run active vuln checks per host.")
    ap.add_argument("--crawl", type=int, default=0, metavar="DEPTH", help="Crawl depth per host.")
    ap.add_argument("--brute", metavar="WORDLIST", help="DNS brute wordlist for subdomain discovery.")
    ap.add_argument("--nuclei", action="store_true", help="Run nuclei per host if installed.")
    ap.add_argument("--authorized", action="store_true", help="Confirm scope (required for --active/--brute).")
    ap.add_argument("--max-subs", type=int, default=25, help="Cap number of hosts scanned (safety).")
    ap.add_argument("--workers", type=int, default=6, help="Concurrent hosts.")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if args.check:
        for s in ("subdomain_enum.py", "web_recon.py", "vuln_checks.py"):
            print(f"[{'+' if (SCRIPTS / s).exists() else '!'}] {s}")
        return 0

    if not args.domain:
        ap.error("domain is required (unless --check).")
    if (args.active or args.brute) and not args.authorized:
        print("[!] --active / --brute send probes to the target. Re-run with --authorized.", file=sys.stderr)
        return 2

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    alive = run_subdomains(args.domain, out, args.brute, args.authorized, args.active)
    if not alive:
        print("[!] No web-alive hosts discovered.")
        aggregate(args.domain, [], out)
        return 0
    if len(alive) > args.max_subs:
        print(f"[i] {len(alive)} hosts found; scanning first {args.max_subs} "
              f"(raise with --max-subs).")
        alive = alive[:args.max_subs]

    print(f"[*] Scanning {len(alive)} host(s) with {args.workers} worker(s) ...")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(scan_host, s, out, args.active, args.authorized, args.crawl, args.nuclei)
                for s in alive]
        for fut in concurrent.futures.as_completed(futs):
            r = fut.result()
            n = sum(1 for f in r["findings"] if f.get("severity") != "info")
            print(f"[+] {r['host']}: {n} finding(s)")
            results.append(r)

    # Fold subdomain-takeover findings (from subdomain_enum) into the matching host.
    takeover_map = {s["host"]: s["takeover"] for s in alive if s.get("takeover")}
    for r in results:
        tk = takeover_map.get(r["host"])
        if tk:
            r["findings"].append(tk)

    aggregate(args.domain, results, out)
    total = sum(1 for r in results for f in r["findings"] if f.get("severity") != "info")
    print(f"\n[+] Done. {total} finding(s) across {len(results)} host(s).")
    print(f"[+] Report: {out / 'FINDINGS_ALL.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
