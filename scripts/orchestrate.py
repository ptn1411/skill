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
        # Check if .encrypted files exist alongside → nuitka-decryptor
        # Otherwise → ida-nuitka-reconstructor (compiled-only, no encryption)
        parent = target.parent
        has_encrypted = any(parent.rglob("*.encrypted")) if parent.exists() else False
        return "nuitka-decryptor" if has_encrypted else "ida-nuitka-reconstructor"
    if "C# / .NET" in fp.get("languages", []):
        return "dotnet-decompiler"
    if "PyInstaller" in " ".join(fp.get("packers", [])):
        return "pyinstaller-unpacker"
    if "Tauri" in " ".join(fp.get("packers", [])):
        return "tauri-unpacker"
    if "Rust" in " ".join(fp.get("languages", [])):
        return "rust-binary-analyzer"
    if "Java" in " ".join(fp.get("languages", [])):
        return "java-decompiler"
    if name.endswith(".apk") or name.endswith(".xapk") or name.endswith(".apks"):
        return "android-apk-pentester"
    if "Android APK" in " ".join(fp.get("packers", [])):
        return "android-apk-pentester"
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


def run_ida_nuitka_reconstruct(target: Path, out_dir: Path) -> PhaseResult:
    """Run the full ida-nuitka-reconstructor pipeline: extract → reconstruct."""
    nuitka_out = out_dir / "nuitka-reconstructed"
    nuitka_out.mkdir(parents=True, exist_ok=True)
    strings_json = str(nuitka_out / "extracted_strings.json")

    # Step 1: Extract strings from PE .rsrc
    extract_script = REPO_ROOT / "ida-nuitka-reconstructor" / "scripts" / "extract_rsrc_strings.py"
    phase1 = make_phase("breach:extract", "ida-nuitka-reconstructor",
                        [PYTHON, str(extract_script), "--binary", str(target), "--out", strings_json,
                         "--dump-raw", str(nuitka_out / "raw_strings.txt")])

    if phase1.returncode != 0:
        phase1.notes.append("String extraction failed — check PE format")
        return phase1

    # Step 2: Reconstruct source
    recon_script = REPO_ROOT / "ida-nuitka-reconstructor" / "scripts" / "reconstruct_nuitka_source.py"
    phase2 = make_phase("breach:reconstruct", "ida-nuitka-reconstructor",
                        [PYTHON, str(recon_script), "--strings", strings_json,
                         "--out", str(nuitka_out / "source")])

    # Merge phases into one result
    combined = PhaseResult(
        name="breach",
        skill="ida-nuitka-reconstructor",
        command=phase1.command + ["&&"] + phase2.command,
        returncode=phase2.returncode,
        stdout_tail=phase1.stdout_tail + "\n---\n" + phase2.stdout_tail,
        stderr_tail=phase1.stderr_tail + "\n" + phase2.stderr_tail,
        started_at=phase1.started_at,
        duration_s=phase1.duration_s + phase2.duration_s,
        artifacts=[strings_json, str(nuitka_out / "source")],
        notes=phase1.notes + phase2.notes,
    )
    return combined


def run_dotnet_decompile(target: Path, out_dir: Path) -> PhaseResult:
    """Run dotnet-decompiler: decompile + analyze."""
    dotnet_out = out_dir / "dotnet-decompiled"
    dotnet_out.mkdir(parents=True, exist_ok=True)

    decompile_script = REPO_ROOT / "dotnet-decompiler" / "scripts" / "decompile_dotnet.py"
    phase1 = make_phase("breach:decompile", "dotnet-decompiler",
                        [PYTHON, str(decompile_script), str(target), "--out", str(dotnet_out)])

    if phase1.returncode != 0:
        phase1.notes.append("Decompilation failed — check .NET runtime / ilspycmd")
        return phase1

    analyze_script = REPO_ROOT / "dotnet-decompiler" / "scripts" / "analyze_dotnet.py"
    phase2 = make_phase("audit:dotnet", "dotnet-decompiler",
                        [PYTHON, str(analyze_script), str(dotnet_out), "--out", str(dotnet_out / "analysis")])

    return PhaseResult(
        name="breach", skill="dotnet-decompiler",
        command=phase1.command + ["&&"] + phase2.command,
        returncode=phase2.returncode,
        stdout_tail=phase1.stdout_tail + "\n---\n" + phase2.stdout_tail,
        stderr_tail=phase1.stderr_tail + "\n" + phase2.stderr_tail,
        started_at=phase1.started_at,
        duration_s=phase1.duration_s + phase2.duration_s,
        artifacts=[str(dotnet_out)],
        notes=phase1.notes + phase2.notes,
    )


def run_pyinstaller_unpack(target: Path, out_dir: Path) -> PhaseResult:
    """Run pyinstaller-unpacker: unpack + decompile."""
    pyinst_out = out_dir / "pyinstaller-unpacked"
    pyinst_out.mkdir(parents=True, exist_ok=True)

    unpack_script = REPO_ROOT / "pyinstaller-unpacker" / "scripts" / "unpack_pyinstaller.py"
    phase1 = make_phase("breach:unpack", "pyinstaller-unpacker",
                        [PYTHON, str(unpack_script), str(target), "--out", str(pyinst_out)])

    if phase1.returncode != 0:
        phase1.notes.append("Unpack failed — check PyInstaller format")
        return phase1

    decompile_script = REPO_ROOT / "pyinstaller-unpacker" / "scripts" / "decompile_pyc.py"
    phase2 = make_phase("breach:decompile", "pyinstaller-unpacker",
                        [PYTHON, str(decompile_script), str(pyinst_out), "--out", str(pyinst_out / "decompiled")])

    return PhaseResult(
        name="breach", skill="pyinstaller-unpacker",
        command=phase1.command + ["&&"] + phase2.command,
        returncode=phase2.returncode,
        stdout_tail=phase1.stdout_tail + "\n---\n" + phase2.stdout_tail,
        stderr_tail=phase1.stderr_tail + "\n" + phase2.stderr_tail,
        started_at=phase1.started_at,
        duration_s=phase1.duration_s + phase2.duration_s,
        artifacts=[str(pyinst_out)],
        notes=phase1.notes + phase2.notes,
    )


def run_rust_analyze(target: Path, out_dir: Path) -> PhaseResult:
    """Run rust-binary-analyzer on a Rust binary."""
    rust_out = out_dir / "rust-analysis"
    rust_out.mkdir(parents=True, exist_ok=True)
    script = REPO_ROOT / "rust-binary-analyzer" / "scripts" / "analyze_rust.py"
    phase = make_phase("breach:rust-analyze", "rust-binary-analyzer",
                       [PYTHON, str(script), str(target), "--out", str(rust_out)])
    phase.artifacts = [str(rust_out)]

    # Check if Tauri was detected → auto-chain tauri-unpacker
    info_json = rust_out / "rust_info.json"
    if info_json.exists():
        try:
            import json as _json
            info = _json.loads(info_json.read_text(encoding='utf-8'))
            if info.get('is_tauri'):
                phase.notes.append("Tauri detected — will auto-chain tauri-unpacker")
        except Exception:
            pass

    return phase


def run_tauri_unpack(target: Path, out_dir: Path) -> PhaseResult:
    """Unpack a Tauri app and analyse its frontend."""
    tauri_out = out_dir / "tauri-unpacked"
    tauri_out.mkdir(parents=True, exist_ok=True)

    unpack_script = REPO_ROOT / "tauri-unpacker" / "scripts" / "unpack_tauri.py"
    phase1 = make_phase("breach:tauri-unpack", "tauri-unpacker",
                        [PYTHON, str(unpack_script), str(target), "--out", str(tauri_out)])

    # Auto-analyse extracted assets
    assets_dir = tauri_out / "assets"
    if assets_dir.exists() and any(assets_dir.rglob("*")):
        analyze_script = REPO_ROOT / "tauri-unpacker" / "scripts" / "analyze_tauri.py"
        analysis_out = out_dir / "tauri-analysis"
        phase2 = make_phase("audit:tauri-analyze", "tauri-unpacker",
                            [PYTHON, str(analyze_script), str(tauri_out), "--out", str(analysis_out)])

        return PhaseResult(
            name="breach:tauri", skill="tauri-unpacker",
            command=phase1.command + ["&&"] + phase2.command,
            returncode=phase2.returncode,
            stdout_tail=phase1.stdout_tail + "\n---\n" + phase2.stdout_tail,
            stderr_tail=phase1.stderr_tail + "\n" + phase2.stderr_tail,
            started_at=phase1.started_at,
            duration_s=phase1.duration_s + phase2.duration_s,
            artifacts=[str(tauri_out), str(analysis_out)],
            notes=phase1.notes + phase2.notes,
        )

    return phase1


def run_java_decompile(target: Path, out_dir: Path) -> PhaseResult:
    """Decompile a Java JAR/WAR/APK/class file and analyse the source."""
    java_out = out_dir / "java-decompiled"
    java_out.mkdir(parents=True, exist_ok=True)

    # Step 1: Decompile
    decompile_script = REPO_ROOT / "java-decompiler" / "scripts" / "decompile_java.py"
    phase1 = make_phase("breach:java-decompile", "java-decompiler",
                        [PYTHON, str(decompile_script), str(target), "--out", str(java_out)])

    # Step 2: Analyse decompiled source
    src_dir = java_out / "src"
    if src_dir.exists() and any(src_dir.rglob("*.java")):
        analyze_script = REPO_ROOT / "java-decompiler" / "scripts" / "analyze_java.py"
        analysis_out = out_dir / "java-analysis"
        phase2 = make_phase("audit:java-analyze", "java-decompiler",
                            [PYTHON, str(analyze_script), str(src_dir), "--out", str(analysis_out)])

        return PhaseResult(
            name="breach:java", skill="java-decompiler",
            command=phase1.command + ["&&"] + phase2.command,
            returncode=phase2.returncode,
            stdout_tail=phase1.stdout_tail + "\n---\n" + phase2.stdout_tail,
            stderr_tail=phase1.stderr_tail + "\n" + phase2.stderr_tail,
            started_at=phase1.started_at,
            duration_s=phase1.duration_s + phase2.duration_s,
            artifacts=[str(java_out), str(analysis_out)],
            notes=phase1.notes + phase2.notes,
        )

    return phase1


def run_android_analyze(target: Path, out_dir: Path) -> PhaseResult:
    """Run android-apk-pentester static APK/XAPK/APKS analysis."""
    android_out = out_dir / "android-apk-analysis"
    android_out.mkdir(parents=True, exist_ok=True)
    script = REPO_ROOT / "android-apk-pentester" / "scripts" / "analyze_apk.py"
    phase = make_phase(
        "breach:android-static",
        "android-apk-pentester",
        [PYTHON, str(script), str(target), "--out", str(android_out)],
    )
    phase.artifacts = [str(android_out)]
    return phase


def run_network_analyze(target: Path, out_dir: Path, har_file: str | None = None) -> PhaseResult:
    """Run network-interceptor analysis on a HAR/JSON capture file."""
    net_out = out_dir / "network-analysis"
    net_out.mkdir(parents=True, exist_ok=True)

    traffic_file = har_file or str(target)
    analyze_script = REPO_ROOT / "network-interceptor" / "scripts" / "analyze_traffic.py"
    return make_phase("audit:network", "network-interceptor",
                      [PYTHON, str(analyze_script), traffic_file, "--out", str(net_out)])


def run_memory_scan(dump_file: str, out_dir: Path) -> PhaseResult:
    """Run memory-dumper scan on an existing dump file."""
    mem_out = out_dir / "memory-analysis"
    mem_out.mkdir(parents=True, exist_ok=True)

    scan_script = REPO_ROOT / "memory-dumper" / "scripts" / "scan_memory.py"
    return make_phase("audit:memory", "memory-dumper",
                      [PYTHON, str(scan_script), dump_file, "--out", str(mem_out)])


def run_frida_hook(target: str, template: str, out_dir: Path) -> PhaseResult:
    """Generate and run Frida hooks from a template."""
    frida_out = out_dir / "frida-results"
    frida_out.mkdir(parents=True, exist_ok=True)

    gen_script = REPO_ROOT / "frida-hooker" / "scripts" / "generate_hooks.py"
    hook_js = frida_out / f"{template}.js"
    phase1 = make_phase("unlock:generate", "frida-hooker",
                        [PYTHON, str(gen_script), "--template", template, "--out", str(hook_js)])

    if phase1.returncode != 0:
        return phase1

    run_script = REPO_ROOT / "frida-hooker" / "scripts" / "run_frida.py"
    phase2 = make_phase("unlock:frida", "frida-hooker",
                        [PYTHON, str(run_script), "--attach", target, "--script", str(hook_js),
                         "--timeout", "30", "--out", str(frida_out)])

    return PhaseResult(
        name="unlock", skill="frida-hooker",
        command=phase1.command + ["&&"] + phase2.command,
        returncode=phase2.returncode,
        stdout_tail=phase1.stdout_tail + "\n---\n" + phase2.stdout_tail,
        stderr_tail=phase1.stderr_tail + "\n" + phase2.stderr_tail,
        started_at=phase1.started_at,
        duration_s=phase1.duration_s + phase2.duration_s,
        artifacts=[str(hook_js), str(frida_out)],
        notes=phase1.notes + phase2.notes,
    )


def run_dotnet_patch(target: Path, out_dir: Path) -> PhaseResult:
    """Run dotnet-patcher: auto-patch license checks."""
    patch_out = out_dir / "dotnet-patched"
    patch_out.mkdir(parents=True, exist_ok=True)

    patch_script = REPO_ROOT / "dotnet-patcher" / "scripts" / "patch_dotnet.py"
    return make_phase("unlock:patch", "dotnet-patcher",
                      [PYTHON, str(patch_script), str(target), "--auto", "--out", str(patch_out)])


def run_dotnet_keygen(decompiled_dir: Path, out_dir: Path) -> PhaseResult:
    """Run dotnet-keygen: extract algo + generate keygen."""
    keygen_out = out_dir / "dotnet-keygen"
    keygen_out.mkdir(parents=True, exist_ok=True)

    extract_script = REPO_ROOT / "dotnet-keygen" / "scripts" / "extract_license_algo.py"
    info_json = keygen_out / "license_info.json"
    phase1 = make_phase("export:extract-algo", "dotnet-keygen",
                        [PYTHON, str(extract_script), str(decompiled_dir), "--out", str(info_json)])

    if phase1.returncode != 0:
        phase1.notes.append("License algorithm extraction failed")
        return phase1

    gen_script = REPO_ROOT / "dotnet-keygen" / "scripts" / "generate_keygen.py"
    phase2 = make_phase("export:keygen", "dotnet-keygen",
                        [PYTHON, str(gen_script), str(info_json), "--out", str(keygen_out / "keygen.py")])

    return PhaseResult(
        name="export", skill="dotnet-keygen",
        command=phase1.command + ["&&"] + phase2.command,
        returncode=phase2.returncode,
        stdout_tail=phase1.stdout_tail + "\n---\n" + phase2.stdout_tail,
        stderr_tail=phase1.stderr_tail + "\n" + phase2.stderr_tail,
        started_at=phase1.started_at,
        duration_s=phase1.duration_s + phase2.duration_s,
        artifacts=[str(info_json), str(keygen_out / "keygen.py")],
        notes=phase1.notes + phase2.notes,
    )


def run_find_patch_targets(source_dir: Path, out_dir: Path) -> PhaseResult:
    """Scan decompiled source for license check methods (works on any .cs source)."""
    script = REPO_ROOT / "dotnet-patcher" / "scripts" / "find_patch_targets.py"
    targets_json = out_dir / "patch_targets.json"
    return make_phase("audit:patch-targets", "dotnet-patcher",
                      [PYTHON, str(script), str(source_dir), "--out", str(targets_json), "--verbose"])


def run_audit_generic(source_dir: Path, out_dir: Path) -> PhaseResult:
    """Run dotnet analyze_dotnet.py on any decompiled source — its regex patterns
    work on JS/Python too (API keys, tokens, URLs, base64 blobs)."""
    script = REPO_ROOT / "dotnet-decompiler" / "scripts" / "analyze_dotnet.py"
    audit_out = out_dir / "audit-results"
    return make_phase("audit:secrets", "dotnet-decompiler",
                      [PYTHON, str(script), str(source_dir), "--out", str(audit_out)])


def run_frida_license_bypass(target_name: str, out_dir: Path) -> PhaseResult:
    """Auto-generate Frida license_bypass hooks for any target."""
    frida_out = out_dir / "frida-bypass"
    frida_out.mkdir(parents=True, exist_ok=True)

    gen_script = REPO_ROOT / "frida-hooker" / "scripts" / "generate_hooks.py"
    hook_js = frida_out / "license_bypass.js"
    phase = make_phase("unlock:frida-gen", "frida-hooker",
                       [PYTHON, str(gen_script), "--template", "license_bypass", "--out", str(hook_js)])

    phase.notes.append(f"Hook script ready: {hook_js}")
    phase.notes.append(f"Run: python frida-hooker/scripts/run_frida.py --attach \"{target_name}\" --script {hook_js}")
    phase.artifacts = [str(hook_js)]
    return phase


def run_generic_keygen(source_dir: Path, out_dir: Path) -> PhaseResult:
    """Extract license info and generate keygen from any decompiled source."""
    keygen_out = out_dir / "keygen"
    keygen_out.mkdir(parents=True, exist_ok=True)

    # Step 1: Try extract_license_algo (works on .cs but also picks up strings in .py/.js)
    extract_script = REPO_ROOT / "dotnet-keygen" / "scripts" / "extract_license_algo.py"
    info_json = keygen_out / "license_info.json"
    phase1 = make_phase("export:extract-algo", "dotnet-keygen",
                        [PYTHON, str(extract_script), str(source_dir), "--out", str(info_json)])

    if phase1.returncode != 0 or not info_json.exists():
        # Fallback: generate a serial-checksum keygen template
        gen_script = REPO_ROOT / "dotnet-keygen" / "scripts" / "generate_keygen.py"
        phase2 = make_phase("export:keygen-fallback", "dotnet-keygen",
                            [PYTHON, str(gen_script), "--template", "serial-checksum", "--out",
                             str(keygen_out / "keygen.py")])
        phase2.notes.append("Used fallback serial-checksum template (algo extraction failed)")
        return phase2

    # Step 2: Generate keygen from extracted info
    gen_script = REPO_ROOT / "dotnet-keygen" / "scripts" / "generate_keygen.py"
    phase2 = make_phase("export:keygen", "dotnet-keygen",
                        [PYTHON, str(gen_script), str(info_json), "--out", str(keygen_out / "keygen.py")])

    return PhaseResult(
        name="export", skill="dotnet-keygen",
        command=phase1.command + ["&&"] + phase2.command,
        returncode=phase2.returncode,
        stdout_tail=phase1.stdout_tail + "\n---\n" + phase2.stdout_tail,
        stderr_tail=phase1.stderr_tail + "\n" + phase2.stderr_tail,
        started_at=phase1.started_at,
        duration_s=phase1.duration_s + phase2.duration_s,
        artifacts=[str(info_json), str(keygen_out / "keygen.py")],
        notes=phase1.notes + phase2.notes,
    )


def find_recovered_source(out_dir: Path) -> Path | None:
    """Find the first directory with recovered/decompiled source code."""
    candidates = [
        out_dir / "dotnet-decompiled",
        out_dir / "java-decompiled" / "src",
        out_dir / "java-decompiled",
        out_dir / "electron-unpacked",
        out_dir / "tauri-unpacked" / "assets",
        out_dir / "tauri-unpacked",
        out_dir / "nuitka-reconstructed" / "source",
        out_dir / "nuitka-reconstructed",
        out_dir / "pyinstaller-unpacked" / "decompiled",
        out_dir / "pyinstaller-unpacked",
        out_dir / "recovered_code",
    ]
    for c in candidates:
        if c.exists() and any(c.rglob("*")):
            return c
    return None


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

    # Phase 1.5 — Mitigate (advisory for native targets)
    fp_dict = report.fingerprint if isinstance(report.fingerprint, dict) else {}
    is_native = bool(fp_dict.get("languages") or fp_dict.get("packers"))
    if is_native:
        report.phases.append(PhaseResult(
            name="mitigate",
            skill="(advisory)",
            command=[],
            returncode=0,
            stdout_tail=(
                "Native target — review before patching:\n"
                "  - anti-debugging-techniques/SKILL.md  (clear ptrace/PEB/timing/TLS checks)\n"
                "  - binary-protection-bypass/SKILL.md   (inventory ASLR/PIE/canary/RELRO)\n"
                "Use ScyllaHide (Win) or LD_PRELOAD shim (Linux) before binary-patcher.\n"
            ),
            stderr_tail="",
            started_at=datetime.now(timezone.utc).isoformat(),
            duration_s=0.0,
        ))

    # Phase 2 — Breach (auto-select)
    if is_url or (target_arg.endswith(".js.map")):
        report.phases.append(run_js_extract(target_arg, out_dir))
    elif target_path:
        skill = choose_breach_skill(target_path, report.fingerprint if isinstance(report.fingerprint, dict) else {})
        if skill == "electron-builder-unpacker":
            report.phases.append(run_electron_unpack(target_path, out_dir))
        elif skill == "nuitka-decryptor":
            report.phases.append(run_nuitka_extract(target_path, out_dir))
        elif skill == "ida-nuitka-reconstructor":
            report.phases.append(run_ida_nuitka_reconstruct(target_path, out_dir))
        elif skill == "dotnet-decompiler":
            report.phases.append(run_dotnet_decompile(target_path, out_dir))
        elif skill == "pyinstaller-unpacker":
            report.phases.append(run_pyinstaller_unpack(target_path, out_dir))
        elif skill == "tauri-unpacker":
            report.phases.append(run_rust_analyze(target_path, out_dir))
            report.phases.append(run_tauri_unpack(target_path, out_dir))
        elif skill == "rust-binary-analyzer":
            report.phases.append(run_rust_analyze(target_path, out_dir))
        elif skill == "java-decompiler":
            report.phases.append(run_java_decompile(target_path, out_dir))
        elif skill == "android-apk-pentester":
            report.phases.append(run_android_analyze(target_path, out_dir))
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

    # Phase 3 — Audit (auto for ALL target types)
    source_dir = find_recovered_source(out_dir)
    breach_skill = None
    if target_path:
        breach_skill = choose_breach_skill(target_path, report.fingerprint if isinstance(report.fingerprint, dict) else {})

    #   3a. Electron-specific analysis
    electron_unpacked = out_dir / "electron-unpacked"
    if electron_unpacked.exists():
        report.phases.append(run_electron_analyze(electron_unpacked, out_dir))

    #   3b. .NET patch target scan
    dotnet_decompiled = out_dir / "dotnet-decompiled"
    if dotnet_decompiled.exists():
        report.phases.append(run_find_patch_targets(dotnet_decompiled, out_dir))

    #   3c. Generic secret/license scan on any recovered source
    if source_dir and source_dir != dotnet_decompiled:
        # dotnet-decompiler already runs analyze_dotnet internally, skip double-scan
        report.phases.append(run_audit_generic(source_dir, out_dir))
    elif source_dir and source_dir == dotnet_decompiled:
        # Already audited inside run_dotnet_decompile, note it
        pass

    # Phase 4 — Unlock (fully automatic)
    if allow_unlock:
        target_name = target_path.name if target_path else target_arg
        unlocked = False

        #   4a. .NET → auto-patch IL bytecode
        if dotnet_decompiled.exists() and target_path and target_path.exists():
            report.phases.append(run_dotnet_patch(target_path, out_dir))
            unlocked = True

        #   4b. Frida license bypass hooks (universal — works on any target)
        report.phases.append(run_frida_license_bypass(target_name, out_dir))
        unlocked = True

        #   4c. Frida anti-debug bypass (if native target)
        if is_native:
            frida_out = out_dir / "frida-antidebug"
            frida_out.mkdir(parents=True, exist_ok=True)
            gen_script = REPO_ROOT / "frida-hooker" / "scripts" / "generate_hooks.py"
            hook_js = frida_out / "anti_debug_bypass.js"
            phase = make_phase("unlock:antidebug", "frida-hooker",
                               [PYTHON, str(gen_script), "--template", "anti_debug_bypass",
                                "--out", str(hook_js)])
            phase.artifacts = [str(hook_js)]
            report.phases.append(phase)

    # Phase 5 — Export (fully automatic keygen)
    if allow_export:
        exported = False

        #   5a. .NET → dedicated keygen pipeline
        if dotnet_decompiled.exists():
            report.phases.append(run_dotnet_keygen(dotnet_decompiled, out_dir))
            exported = True

        #   5b. Any other source → generic keygen (extract algo + template)
        if not exported and source_dir:
            report.phases.append(run_generic_keygen(source_dir, out_dir))
            exported = True

        #   5c. Fallback — generate serial-checksum template
        if not exported:
            gen_script = REPO_ROOT / "dotnet-keygen" / "scripts" / "generate_keygen.py"
            keygen_out = out_dir / "keygen"
            keygen_out.mkdir(parents=True, exist_ok=True)
            phase = make_phase("export:keygen-fallback", "dotnet-keygen",
                               [PYTHON, str(gen_script), "--template", "serial-checksum",
                                "--out", str(keygen_out / "keygen.py")])
            phase.notes.append("No source recovered — generated default serial-checksum keygen template")
            report.phases.append(phase)

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
