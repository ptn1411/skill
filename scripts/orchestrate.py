#!/usr/bin/env python3
"""
orchestrate.py — Master RE Orchestrator runtime.

Chains the toolkit's sub-skills end-to-end on an authorized target:

    Phase 1 (Recon)   binary-identifier
    Phase 2 (Breach)  electron-builder-unpacker | nuitka-decryptor | javascript-deobfuscator
    Phase 3 (Audit)   electron-app-analyzer + javascript-deobfuscator
    Phase 4 (Unlock)  binary-patcher | electron-builder-repacker          [manual gate]
    Phase 5 (Export)  writerpro-pentest + pentest-script-generator        [manual gate]

The script is deliberately conservative for destructive phases (4, 5) — those
require an explicit `--unlock` / `--export` flag because they modify binaries or
emit keygen artifacts.

Usage (cross-platform):
    python scripts/orchestrate.py <target> [--out DIR] [--unlock] [--export]
    python scripts/orchestrate.py --help

Examples:
    # Auto recon + breach + audit on an Electron app folder
    python scripts/orchestrate.py "C:/Program Files/MyApp"

    # Sourcemap recovery for a JS bundle URL
    python scripts/orchestrate.py https://example.com/assets/index.js.map

    # Full mission with unlock + export gates
    python scripts/orchestrate.py target.exe --unlock --export
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable


# --- Data model --------------------------------------------------------------

@dataclass
class PhaseResult:
    name: str
    skill: str
    command: list[str]
    returncode: int
    stdout_tail: str
    stderr_tail: str
    started_at: str
    duration_s: float
    artifacts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class MissionReport:
    target: str
    started_at: str
    finished_at: str = ""
    out_dir: str = ""
    fingerprint: dict = field(default_factory=dict)
    phases: list[PhaseResult] = field(default_factory=list)
    deliverables: dict = field(default_factory=dict)


# --- Helpers -----------------------------------------------------------------

def run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str, float]:
    started = datetime.now(timezone.utc)
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd or REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
        rc = proc.returncode
        out, err = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        rc = 124
        out = exc.stdout or ""
        err = (exc.stderr or "") + "\n[!] timeout after 600s"
    except FileNotFoundError as exc:
        rc = 127
        out = ""
        err = f"[!] command not found: {exc}"
    duration = (datetime.now(timezone.utc) - started).total_seconds()
    return rc, out, err, duration


def tail(text: str, lines: int = 40) -> str:
    return "\n".join(text.splitlines()[-lines:])


def make_phase(name: str, skill: str, cmd: list[str]) -> PhaseResult:
    started = datetime.now(timezone.utc)
    rc, out, err, dur = run(cmd)
    return PhaseResult(
        name=name,
        skill=skill,
        command=cmd,
        returncode=rc,
        stdout_tail=tail(out),
        stderr_tail=tail(err),
        started_at=started.isoformat(),
        duration_s=dur,
    )


# --- Phase 1: Recon ----------------------------------------------------------

def fingerprint_binary(target: Path) -> tuple[PhaseResult, dict]:
    """Run binary-identifier and parse text output into structured fingerprint."""
    script = REPO_ROOT / "binary-identifier" / "scripts" / "identify_app.py"
    phase = make_phase("recon", "binary-identifier", [PYTHON, str(script), str(target)])
    fp = {"languages": [], "packers": [], "encryption": [], "raw": phase.stdout_tail}
    section = None
    for line in phase.stdout_tail.splitlines():
        s = line.strip()
        if s.startswith("[Language/Compiler]"):
            section = "languages"
        elif s.startswith("[Packer/Protection]"):
            section = "packers"
        elif s.startswith("[Encryption/Hint]") or s.startswith("[Misc/Indicators]"):
            section = "encryption"
        elif s.startswith("[+]") and section:
            fp[section].append(s.removeprefix("[+]").strip())
    return phase, fp


# --- Strategy selection ------------------------------------------------------

def choose_breach_skill(target: Path, fp: dict) -> Optional[str]:
    """Return the sub-skill name to run in Phase 2, or None if nothing fits."""
    name = target.name.lower()
    if target.is_dir():
        # Heuristic: Electron apps ship resources/app.asar
        if any(p.name.lower() == "app.asar" for p in target.rglob("*.asar")):
            return "electron-builder-unpacker"
    if name.endswith(".asar"):
        return "electron-builder-unpacker"
    if name.endswith(".js.map") or "://" in str(target):
        return "javascript-deobfuscator"
    if "Python (Nuitka)" in fp.get("languages", []) or "Nuitka (Onefile)" in fp.get("packers", []):
        return "nuitka-decryptor"
    if "C# / .NET" in fp.get("languages", []):
        return "binary-identifier"  # hand-off note — needs dnSpy GUI
    return None


# --- Phase runners -----------------------------------------------------------

def run_electron_unpack(target: Path, out_dir: Path) -> PhaseResult:
    script = REPO_ROOT / "electron-builder-unpacker" / "scripts" / "unpack_electron_builder.py"
    cmd = [PYTHON, str(script), str(target), "--out", str(out_dir / "electron-unpacked")]
    return make_phase("breach", "electron-builder-unpacker", cmd)


def run_electron_analyze(source_dir: Path, out_dir: Path) -> PhaseResult:
    script = REPO_ROOT / "electron-app-analyzer" / "scripts" / "analyze_electron.py"
    cmd = [PYTHON, str(script), str(source_dir), "--out", str(out_dir / "electron-analysis")]
    return make_phase("audit", "electron-app-analyzer", cmd)


def run_js_extract(url_or_path: str, out_dir: Path) -> PhaseResult:
    script = REPO_ROOT / "javascript-deobfuscator" / "scripts" / "extract_sourcemap.py"
    cmd = [PYTHON, str(script), url_or_path, str(out_dir / "recovered_code")]
    return make_phase("breach", "javascript-deobfuscator", cmd)


def run_nuitka_extract(target: Path, out_dir: Path) -> PhaseResult:
    script = REPO_ROOT / "nuitka-decryptor" / "scripts" / "analyze_binary.py"
    cmd = [PYTHON, str(script), str(target)]
    phase = make_phase("breach", "nuitka-decryptor", cmd)
    # Mirror analyze stdout into output dir for record-keeping
    (out_dir / "nuitka").mkdir(parents=True, exist_ok=True)
    (out_dir / "nuitka" / "analyze.txt").write_text(
        phase.stdout_tail + "\n\n--- STDERR ---\n" + phase.stderr_tail,
        encoding="utf-8",
    )
    return phase


# --- Mission driver ----------------------------------------------------------

def execute_mission(target_arg: str, out_dir: Path, allow_unlock: bool, allow_export: bool) -> MissionReport:
    started = datetime.now(timezone.utc)
    report = MissionReport(target=target_arg, started_at=started.isoformat(), out_dir=str(out_dir))
    out_dir.mkdir(parents=True, exist_ok=True)

    is_url = "://" in target_arg
    target_path = Path(target_arg) if not is_url else None

    # Phase 1 — Recon (only meaningful for local paths)
    if target_path and target_path.exists() and target_path.is_file():
        recon, fp = fingerprint_binary(target_path)
        report.phases.append(recon)
        report.fingerprint = fp
    else:
        report.fingerprint = {"note": "skipped (URL or directory target)"}

    # Phase 2 — Breach (auto-select)
    if is_url or (target_arg.endswith(".js.map")):
        report.phases.append(run_js_extract(target_arg, out_dir))
    elif target_path:
        skill = choose_breach_skill(target_path, report.fingerprint if isinstance(report.fingerprint, dict) else {})
        if skill == "electron-builder-unpacker":
            report.phases.append(run_electron_unpack(target_path, out_dir))
        elif skill == "nuitka-decryptor":
            report.phases.append(run_nuitka_extract(target_path, out_dir))
        elif skill == "javascript-deobfuscator":
            report.phases.append(run_js_extract(str(target_path), out_dir))
        else:
            report.phases.append(PhaseResult(
                name="breach",
                skill="(none)",
                command=[],
                returncode=0,
                stdout_tail="No matching breach skill — manual triage required.",
                stderr_tail="",
                started_at=datetime.now(timezone.utc).isoformat(),
                duration_s=0.0,
                notes=["See TOOLS.md for tool-assisted strategies (dnSpy, x64dbg, Ghidra)."],
            ))

    # Phase 3 — Audit (only if we recovered an Electron source tree)
    electron_unpacked = out_dir / "electron-unpacked"
    if electron_unpacked.exists():
        report.phases.append(run_electron_analyze(electron_unpacked, out_dir))

    # Phase 4 — Unlock (gated)
    if allow_unlock:
        report.phases.append(PhaseResult(
            name="unlock",
            skill="(manual)",
            command=[],
            returncode=0,
            stdout_tail=(
                "Unlock phase requires interactive review. Use:\n"
                "  - electron-builder-repacker: edit recovered source, then run repack_electron_builder.py\n"
                "  - binary-patcher: identify offsets via x64dbg, then run apply_patch.py\n"
            ),
            stderr_tail="",
            started_at=datetime.now(timezone.utc).isoformat(),
            duration_s=0.0,
        ))

    # Phase 5 — Export (gated)
    if allow_export:
        report.phases.append(PhaseResult(
            name="export",
            skill="(manual)",
            command=[],
            returncode=0,
            stdout_tail=(
                "Export phase: review writerpro-pentest/scripts/keygen.py for the keygen template;\n"
                "use antigravity-kit/pentest-script-generator/scripts/generate.py for vuln scripts.\n"
            ),
            stderr_tail="",
            started_at=datetime.now(timezone.utc).isoformat(),
            duration_s=0.0,
        ))

    # Inventory deliverables
    deliverables: dict = {"source": [], "secrets": [], "keygen": [], "patch": []}
    for path in out_dir.rglob("*"):
        if not path.is_file():
            continue
        rel = str(path.relative_to(out_dir)).replace("\\", "/")
        lower = path.name.lower()
        if lower.endswith((".js", ".ts", ".jsx", ".tsx")) or "source" in rel:
            deliverables["source"].append(rel)
        if "secret" in lower or "endpoint" in lower or "finding" in lower:
            deliverables["secrets"].append(rel)
        if "keygen" in lower:
            deliverables["keygen"].append(rel)
        if "patch" in lower or "cracked" in lower:
            deliverables["patch"].append(rel)
    report.deliverables = deliverables

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def write_report(report: MissionReport, out_dir: Path) -> None:
    (out_dir / "mission.json").write_text(
        json.dumps(asdict(report), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    lines = [
        "# Master RE Orchestrator Report",
        "",
        f"- Target: `{report.target}`",
        f"- Started: {report.started_at}",
        f"- Finished: {report.finished_at}",
        f"- Output dir: `{report.out_dir}`",
        "",
        "## Fingerprint",
        "```json",
        json.dumps(report.fingerprint, indent=2, ensure_ascii=False),
        "```",
        "",
        "## Phases",
    ]
    for p in report.phases:
        status = "OK" if p.returncode == 0 else f"FAIL ({p.returncode})"
        lines.extend([
            f"### {p.name} — {p.skill} [{status}] ({p.duration_s:.1f}s)",
            "```",
            "$ " + " ".join(p.command) if p.command else "(no command)",
            "```",
            "<details><summary>stdout (tail)</summary>",
            "",
            "```",
            p.stdout_tail or "(empty)",
            "```",
            "</details>",
            "",
        ])
        if p.stderr_tail:
            lines.extend(["<details><summary>stderr (tail)</summary>", "", "```", p.stderr_tail, "```", "</details>", ""])

    lines.extend([
        "## Deliverables",
        "```json",
        json.dumps(report.deliverables, indent=2, ensure_ascii=False),
        "```",
    ])
    (out_dir / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# --- CLI ---------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Master RE Orchestrator — chain RE sub-skills on an authorized target.",
    )
    parser.add_argument("target", help="File path, directory, or sourcemap URL")
    parser.add_argument("--out", default="output", help="Output directory (default: ./output)")
    parser.add_argument("--unlock", action="store_true", help="Run Phase 4 (binary patching / code injection notes)")
    parser.add_argument("--export", action="store_true", help="Run Phase 5 (keygen / vuln-script export notes)")
    parser.add_argument("--require-tools", action="store_true", help="Verify external tooling (node, asar, upx) before starting")
    args = parser.parse_args()

    if args.require_tools:
        missing = [t for t in ("python", "node", "npx") if shutil.which(t) is None]
        if missing:
            print(f"[!] Missing tools: {', '.join(missing)}. See TOOLS.md.", file=sys.stderr)
            return 2

    out_dir = Path(args.out).resolve()
    report = execute_mission(args.target, out_dir, args.unlock, args.export)
    write_report(report, out_dir)

    failed = [p for p in report.phases if p.returncode != 0]
    print(f"[+] Phases run: {len(report.phases)} | failed: {len(failed)}")
    print(f"[+] Report: {out_dir / 'REPORT.md'}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
