#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
from pathlib import Path

WORKSPACE = Path("c:/Users/NAM/Code/skill").resolve()
CONFIG_SKILLS = Path("C:/Users/NAM/.gemini/config/skills").resolve()

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

def main() -> int:
    if not CONFIG_SKILLS.exists():
        print(f"[!] Global config skills directory not found: {CONFIG_SKILLS}", file=sys.stderr)
        return 1

    print(f"[+] Syncing skills from workspace {WORKSPACE} to {CONFIG_SKILLS}...\n")
    failed = False
    
    for src_rel, dest_name in skills_to_link:
        src_path = (WORKSPACE / src_rel).resolve()
        dest_path = (CONFIG_SKILLS / dest_name).resolve()
        
        if not src_path.exists():
            print(f"[-] Source directory {src_rel} does not exist in workspace. Skipping.")
            continue
            
        print(f"[*] Processing '{dest_name}':")
        
        # Safe deletion of existing files/folders
        if dest_path.exists() or dest_path.is_symlink():
            print(f"    - Removing existing: {dest_path}")
            try:
                # We use cmd /c rmdir /s /q which safely deletes junctions or regular dirs
                subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", str(dest_path)], check=True)
            except Exception as e:
                # Fallback to shutil if rmdir fails
                try:
                    if dest_path.is_file() or dest_path.is_symlink():
                        dest_path.unlink()
                    else:
                        shutil.rmtree(dest_path)
                except Exception as ex:
                    print(f"    [!] Error removing: {ex}")
                    failed = True
                    continue
                    
        # Create directory junction
        print(f"    - Creating junction: {src_path} -> {dest_path}")
        try:
            subprocess.run(["cmd", "/c", "mklink", "/J", str(dest_path), str(src_path)], check=True)
            print("    [+] Linked successfully.")
        except Exception as e:
            print(f"    [!] Junction creation failed: {e}")
            failed = True

    if failed:
        print("\n[!] Some links failed. Please check permissions or run from a standard cmd prompt.")
        return 1
        
    print("\n[+] All skills linked successfully! Please restart/refresh your Gemini session.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
