#!/usr/bin/env python3
"""
parse_findings.py — Turn a hunt engine's raw output into a defensive report.

Supports:
  --kind native    JSON array from native_hunt.ps1
  --kind hayabusa  CSV timeline from hayabusa csv-timeline

Emits FINDINGS.md + findings.json into --out.

Usage:
    python parse_findings.py output/hunt/events.json --kind native --out output/hunt
    python parse_findings.py output/hunt/hayabusa.csv --kind hayabusa --out output/hunt
"""

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def load_native(path: Path) -> list[dict]:
    raw = path.read_text(encoding="utf-8-sig").strip()
    if not raw:
        return []
    data = json.loads(raw)
    if isinstance(data, dict):  # single event -> ConvertTo-Json emits an object
        data = [data]
    return data


def load_hayabusa(path: Path) -> list[dict]:
    out = []
    with path.open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            # hayabusa columns vary; map the common ones defensively
            level = (row.get("Level") or row.get("level") or "info").lower()
            sev = {"crit": "critical", "critical": "critical", "high": "high",
                   "med": "medium", "medium": "medium", "low": "low",
                   "info": "info", "informational": "info"}.get(level, "info")
            out.append({
                "time": row.get("Timestamp") or row.get("datetime") or "",
                "log": row.get("Channel") or "",
                "id": row.get("EventID") or row.get("EventId") or "",
                "category": row.get("MitreTactics") or row.get("RuleTitle") or "detection",
                "severity": sev,
                "description": row.get("RuleTitle") or row.get("Title") or "",
                "computer": row.get("Computer") or "",
                "message": (row.get("Details") or "")[:240],
            })
    return out


def to_markdown(events: list[dict]) -> str:
    real = [e for e in events if e.get("severity") != "info"]
    notes = [e for e in events if e.get("severity") == "info"]

    lines = ["# Windows Event Log — Hunt Findings", ""]
    lines.append(f"**Total signals:** {len(real)}  |  **Collection notes:** {len(notes)}")
    lines.append("")

    sev_counts = Counter(e.get("severity", "info") for e in real)
    if sev_counts:
        summary = "  ".join(f"{k}: {sev_counts[k]}" for k in
                            sorted(sev_counts, key=lambda s: SEV_ORDER.get(s, 9)))
        lines.append(f"**By severity:** {summary}")
        lines.append("")

    cat_counts = Counter(e.get("category", "?") for e in real)
    if cat_counts:
        lines.append("**By category:** " + ", ".join(f"{c} ({n})" for c, n in cat_counts.most_common()))
        lines.append("")

    # group by severity, most severe first
    grouped = defaultdict(list)
    for e in real:
        grouped[e.get("severity", "info")].append(e)

    for sev in sorted(grouped, key=lambda s: SEV_ORDER.get(s, 9)):
        rows = sorted(grouped[sev], key=lambda e: str(e.get("time", "")), reverse=True)
        lines.append(f"## {sev.upper()} ({len(rows)})")
        lines.append("")
        lines.append("| Time | Log | ID | Category | Description | Detail |")
        lines.append("|---|---|---|---|---|---|")
        for e in rows[:100]:
            detail = str(e.get("message", "")).replace("|", "\\|").replace("\n", " ")[:100]
            desc = str(e.get("description", "")).replace("|", "\\|")
            lines.append(f"| {e.get('time','')} | {e.get('log','')} | {e.get('id','')} | "
                         f"{e.get('category','')} | {desc} | {detail} |")
        if len(rows) > 100:
            lines.append(f"| ... | | | | _{len(rows)-100} more_ | |")
        lines.append("")

    if notes:
        lines.append("## Collection Notes")
        for n in notes:
            lines.append(f"- {n.get('description','')}: {str(n.get('message','')).splitlines()[0][:120]}")
        lines.append("")

    lines.append("## Triage guidance (defensive)")
    lines.append("- **1102 (log cleared)** and bursts of **4625 (failed logon)** → investigate first.")
    lines.append("- **4720 / 4732 / 4728** (new account, added to admin/global group) → verify it was authorized.")
    lines.append("- **7045 (new service)** and **4698 (scheduled task)** → common persistence; confirm origin.")
    lines.append("- Correlate suspicious **4104 PowerShell** / **4688 process** events with the timestamps above.")
    lines.append("- If the Security log shows a collection note, re-run PowerShell **as Administrator**.")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("raw", help="events.json (native) or hayabusa.csv")
    ap.add_argument("--kind", choices=["native", "hayabusa"], default="native")
    ap.add_argument("--out", default="output/hunt")
    args = ap.parse_args()

    raw_path = Path(args.raw)
    if not raw_path.exists():
        print(f"[!] Not found: {raw_path}", file=sys.stderr)
        return 1

    try:
        events = load_native(raw_path) if args.kind == "native" else load_hayabusa(raw_path)
    except Exception as e:
        print(f"[!] Failed to load {args.kind} output: {e}", file=sys.stderr)
        return 1

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "findings.json").write_text(json.dumps(events, indent=2), encoding="utf-8")
    (out_dir / "FINDINGS.md").write_text(to_markdown(events), encoding="utf-8")

    real = sum(1 for e in events if e.get("severity") != "info")
    print(f"[+] {real} signal(s) parsed.")
    print(f"[+] {out_dir / 'FINDINGS.md'}")
    print(f"[+] {out_dir / 'findings.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
