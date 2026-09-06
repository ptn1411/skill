#!/usr/bin/env python3
"""
full_assess.py — Chained assessment orchestrator for LIVE targets.

Unlike assess.py (which routes to a single skill), this runs the relevant child
skills one after another and writes ONE consolidated report:

    network target (IP/CIDR/host)
        1) network-scanner  -> nmap service scan
        2) parse open ports -> for each web port, web-app-scanner recon
        3) consolidate       -> output/assessment/REPORT.md

    web URL
        1) web-app-scanner recon on the URL
        2) network-scanner on its host (full port/service picture)
        3) consolidate

    artifact / sourcemap
        delegate to orchestrate.py (which already chains the RE sub-skills)

SQL injection is intentionally NOT auto-run: it is intrusive and requires the
explicit --authorized flag on sqli_test.py. This chain is read-only recon.

Usage:
    python scripts/full_assess.py 192.168.1.10
    python scripts/full_assess.py https://example.com --out output
    python scripts/full_assess.py 10.0.0.0/24 --profile quick

Only assess targets you own or are authorized to test (MASTER_POLICY.md).
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import assess  # reuse classify()

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8081, 9443}
WEB_SERVICES = {"http", "https", "http-alt", "http-proxy", "https-alt", "http-mgmt"}


class Step:
    def __init__(self, name, skill, cmd, rc, report):
        self.name, self.skill, self.cmd, self.rc, self.report = name, skill, cmd, rc, report


def run_step(name: str, skill: str, cmd: list[str], report: Path | None) -> Step:
    print(f"\n{'='*70}\n[STEP] {name}  ({skill})\n{'='*70}")
    print("  $ " + " ".join(cmd))
    try:
        rc = subprocess.run(cmd).returncode
    except Exception as e:
        print(f"  [!] failed: {e}")
        rc = 1
    return Step(name, skill, cmd, rc, report if (report and report.exists()) else None)


def scan_network(target: str, out: Path, profile: str) -> Step:
    s = REPO_ROOT / "network-scanner" / "scripts" / "nmap_scan.py"
    nmap_out = out / "nmap"
    cmd = [PYTHON, str(s), target, "--profile", profile, "--out", str(nmap_out)]
    return run_step("Network scan", "network-scanner", cmd, nmap_out / "FINDINGS.md")


def web_endpoints_from_nmap(out: Path) -> list[str]:
    """Read nmap findings.json and derive http(s):// endpoints from open web ports."""
    fj = out / "nmap" / "findings.json"
    if not fj.exists():
        return []
    try:
        data = json.loads(fj.read_text(encoding="utf-8"))
    except Exception:
        return []
    urls = []
    for host in data.get("hosts", []):
        addr = host.get("address", "")
        for p in host.get("ports", []):
            port = p.get("port")
            svc = (p.get("service") or "").lower()
            if port in WEB_PORTS or svc in WEB_SERVICES:
                scheme = "https" if port in (443, 8443, 9443) or "https" in svc else "http"
                default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
                urls.append(f"{scheme}://{addr}" + ("" if default else f":{port}"))
    return sorted(set(urls))


def recon_web(url: str, out: Path, idx: int) -> Step:
    s = REPO_ROOT / "web-app-scanner" / "scripts" / "web_recon.py"
    web_out = out / f"web-{idx}"
    cmd = [PYTHON, str(s), url, "--out", str(web_out)]
    return run_step(f"Web recon: {url}", "web-app-scanner", cmd, web_out / "FINDINGS.md")


def delegate_orchestrate(target: str, out: Path) -> Step:
    s = REPO_ROOT / "scripts" / "orchestrate.py"
    cmd = [PYTHON, str(s), target, "--out", str(out)]
    return run_step("Artifact audit", "orchestrate.py", cmd, out / "REPORT.md")


def consolidate(target: str, kind: str, steps: list[Step], out: Path) -> Path:
    adir = out / "assessment"
    adir.mkdir(parents=True, exist_ok=True)
    lines = [f"# Assessment Report — {target}", "",
             f"- Target kind: **{kind}**",
             f"- Steps run: {len(steps)}", ""]
    lines.append("## Steps")
    lines.append("")
    lines.append("| # | Step | Skill | Result | Sub-report |")
    lines.append("|---|---|---|---|---|")
    for i, st in enumerate(steps, 1):
        status = "OK" if st.rc == 0 else f"FAIL ({st.rc})"
        rep = str(st.report.relative_to(out)).replace("\\", "/") if st.report else "—"
        lines.append(f"| {i} | {st.name} | {st.skill} | {status} | {rep} |")
    lines.append("")

    # inline the child findings for a single-file read
    for st in steps:
        if st.report:
            lines.append(f"## {st.name} — findings")
            lines.append("")
            try:
                body = st.report.read_text(encoding="utf-8")
            except Exception as e:
                body = f"_(could not read {st.report}: {e})_"
            lines.append(body)
            lines.append("")

    lines.append("## Next steps (defensive)")
    lines.append("- For any web endpoint with parameters, run authorized SQLi testing:")
    lines.append("  `python web-app-scanner/scripts/sqli_test.py \"<url>\" --authorized`")
    lines.append("- Prioritise: exposed management ports (RDP/SSH/SMB), missing security headers, weak TLS.")
    lines.append("")
    lines.append("---")
    lines.append("## Ủng hộ dự án")
    lines.append("")
    lines.append("Nếu dự án giúp ích cho công việc nghiên cứu hoặc phòng thủ của bạn, bạn có thể ủng hộ để duy trì tài liệu, test và các workflow mới. Mọi khoản đóng góp đều hoàn toàn tự nguyện.")
    lines.append("")
    lines.append("- Ngân hàng: **TPBank**")
    lines.append("- Chủ tài khoản: **PHAM THANH NAM**")
    lines.append("- Số tài khoản: **69238686888**")
    report = adir / "REPORT.md"
    report.write_text("\n".join(lines), encoding="utf-8")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="Chained live-target assessment orchestrator.")
    ap.add_argument("target")
    ap.add_argument("--out", default="output", help="Base output dir (default: output).")
    ap.add_argument("--profile", default="service", help="network-scanner profile (default: service).")
    ap.add_argument("--type", choices=["network", "web", "winlog", "artifact", "jsmap"])
    args = ap.parse_args()

    kind, reason = assess.classify(args.target, args.type)
    print(f"[=] Target : {args.target}")
    print(f"[=] Kind   : {kind}  ({reason})")

    out = Path(args.out.rstrip("/"))
    out.mkdir(parents=True, exist_ok=True)
    steps: list[Step] = []

    if kind in ("artifact", "jsmap"):
        steps.append(delegate_orchestrate(args.target, out))

    elif kind == "winlog":
        s = REPO_ROOT / "windows-log-hunter" / "scripts" / "hunt_eventlog.py"
        steps.append(run_step("Windows log hunt", "windows-log-hunter",
                              [PYTHON, str(s), "--out", str(out / "hunt")],
                              out / "hunt" / "FINDINGS.md"))

    elif kind == "network":
        steps.append(scan_network(args.target, out, args.profile))
        urls = web_endpoints_from_nmap(out)
        if urls:
            print(f"\n[i] Discovered {len(urls)} web endpoint(s): {', '.join(urls)}")
        else:
            print("\n[i] No web ports discovered (or nmap unavailable) — skipping web recon.")
        for i, url in enumerate(urls, 1):
            steps.append(recon_web(url, out, i))

    elif kind == "web":
        steps.append(recon_web(args.target, out, 1))
        host = urlparse(args.target).hostname
        if host:
            steps.append(scan_network(host, out, args.profile))

    else:
        print("[!] Could not classify target. Use --type.", file=sys.stderr)
        return 2

    report = consolidate(args.target, kind, steps, out)
    ok = sum(1 for s in steps if s.rc == 0)
    print(f"\n[+] Done: {ok}/{len(steps)} step(s) OK.")
    print(f"[+] Consolidated report: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
