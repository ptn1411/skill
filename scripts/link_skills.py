#!/usr/bin/env python3
"""
link_skills.py — Junction every workspace skill into each config skills root.

Safety notes (a previous version deleted the whole workspace — do not regress):
  * NEVER call .resolve() on the destination path: resolving a path that is
    already a junction follows it back to the workspace, so a later delete would
    target the workspace itself. Build dest with plain path division.
  * NEVER use shutil.rmtree on the destination: rmtree FOLLOWS directory
    junctions and would delete the link target's contents (the workspace).
    Remove a junction with os.rmdir (unlinks the junction only).
  * Hard guard: refuse to remove anything whose real path is the workspace or
    lives inside it.
"""
import os
import subprocess
import sys
from pathlib import Path

WORKSPACE = Path("c:/Users/NAM/Code/skill").resolve()

# Link skills into every config root below.
CONFIG_ROOTS = [
    Path("C:/Users/NAM/.gemini/config/skills"),
    Path("C:/Users/NAM/.claude/skills"),
]

# List of skills to link from the workspace to the global config skills folder
skills_to_link = [
    # (source_in_workspace, target_in_config)
    (".", "authorized-artifact-auditor"), # The main/root skill (authorized-artifact-auditor)
    ("antigravity-kit/pentest-script-generator", "pentest-script-generator"), # Pentest script generator skill
    ("android-apk-pentester", "android-apk-pentester"),
    ("anti-debugging-techniques", "anti-debugging-techniques"),
    ("binary-identifier", "binary-identifier"),
    ("binary-patcher", "binary-patcher"),
    ("binary-protection-bypass", "binary-protection-bypass"),
    ("container-cloud-auditor", "container-cloud-auditor"),
    ("dotnet-decompiler", "dotnet-decompiler"),
    ("dotnet-keygen", "dotnet-keygen"),
    ("dotnet-patcher", "dotnet-patcher"),
    ("electron-app-analyzer", "electron-app-analyzer"),
    ("electron-builder-repacker", "electron-builder-repacker"),
    ("electron-builder-unpacker", "electron-builder-unpacker"),
    ("frida-hooker", "frida-hooker"),
    ("ida-nuitka-reconstructor", "ida-nuitka-reconstructor"),
    ("java-decompiler", "java-decompiler"),
    ("javascript-deobfuscator", "javascript-deobfuscator"),
    ("master-unlock", "master-unlock"),
    ("memory-dumper", "memory-dumper"),
    ("network-interceptor", "network-interceptor"),
    ("network-scanner", "network-scanner"),
    ("windows-log-hunter", "windows-log-hunter"),
    ("web-app-scanner", "web-app-scanner"),
    ("nuitka-decryptor", "nuitka-decryptor"),
    ("orchestrator-plugin-sdk", "orchestrator-plugin-sdk"),
    ("pyinstaller-unpacker", "pyinstaller-unpacker"),
    ("rust-binary-analyzer", "rust-binary-analyzer"),
    ("sbom-supply-chain-auditor", "sbom-supply-chain-auditor"),
    ("symbolic-execution-tools", "symbolic-execution-tools"),
    ("tauri-unpacker", "tauri-unpacker"),
    ("vm-and-bytecode-reverse", "vm-and-bytecode-reverse"),
    ("writerpro-pentest", "writerpro-pentest"),
]


def is_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction and isjunction(str(path)))


def _protects_workspace(dest_path: Path) -> bool:
    """True if dest's REAL location is the workspace or inside it — never delete that."""
    try:
        real = Path(os.path.realpath(str(dest_path)))
    except Exception:
        return False
    return real == WORKSPACE or WORKSPACE in real.parents


def remove_dest(dest_path: Path) -> None:
    """Remove an existing destination safely. Junctions are unlinked (never
    recursed into); real directories are removed with rmdir /s /q."""
    if is_junction(dest_path):
        # Unlink the junction ONLY. os.rmdir removes the reparse point without
        # touching the target's contents.
        try:
            os.rmdir(str(dest_path))
        except OSError:
            # rmdir (no /s) also removes a junction link only.
            subprocess.run(["cmd", "/c", "rmdir", "/q", str(dest_path)], check=True)
        return

    # Real directory/file. Guard against a resolved workspace path before /s delete.
    if _protects_workspace(dest_path):
        raise RuntimeError(f"refusing to recursively delete workspace-backed path: {dest_path}")
    subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", str(dest_path)], check=True)


def link_into(config_root: Path) -> bool:
    """Junction every listed skill into config_root. Returns True on any failure."""
    config_root = config_root.resolve()
    if not config_root.exists():
        print(f"[-] Config skills directory not found, skipping: {config_root}")
        return False

    print(f"[+] Syncing skills from {WORKSPACE} to {config_root}...\n")
    failed = False

    for src_rel, dest_name in skills_to_link:
        src_path = (WORKSPACE / src_rel).resolve()
        # IMPORTANT: do NOT .resolve() dest — that would follow an existing junction
        # back into the workspace and make a later delete target the workspace.
        dest_path = config_root / dest_name

        if not src_path.exists():
            print(f"[-] Source directory {src_rel} does not exist in workspace. Skipping.")
            continue

        print(f"[*] Processing '{dest_name}':")

        if dest_path.exists() or dest_path.is_symlink() or is_junction(dest_path):
            print(f"    - Removing existing: {dest_path}")
            try:
                remove_dest(dest_path)
            except Exception as ex:
                print(f"    [!] Error removing: {ex}")
                failed = True
                continue

        print(f"    - Creating junction: {src_path} -> {dest_path}")
        try:
            subprocess.run(["cmd", "/c", "mklink", "/J", str(dest_path), str(src_path)], check=True)
            print("    [+] Linked successfully.")
        except Exception as e:
            print(f"    [!] Junction creation failed: {e}")
            failed = True

    return failed


def main() -> int:
    if not any(root.exists() for root in CONFIG_ROOTS):
        print("[!] No config skills directory found: "
              + ", ".join(str(r) for r in CONFIG_ROOTS), file=sys.stderr)
        return 1

    failed = False
    for root in CONFIG_ROOTS:
        print(f"\n{'='*70}\n[ROOT] {root}\n{'='*70}")
        failed = link_into(root) or failed

    if failed:
        print("\n[!] Some links failed. Please check permissions or run from a standard cmd prompt.")
        return 1

    print("\n[+] All skills linked into every config root! Restart/refresh your Gemini and Claude sessions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
