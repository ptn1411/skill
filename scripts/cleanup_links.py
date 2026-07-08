#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path

CONFIG_SKILLS = Path("C:/Users/NAM/.gemini/config/skills").resolve()

# List of sub-skills to remove from the global config skills folder
sub_skills_to_remove = [
    "android-apk-pentester",
    "anti-debugging-techniques",
    "binary-identifier",
    "binary-patcher",
    "binary-protection-bypass",
    "container-cloud-auditor",
    "dotnet-decompiler",
    "dotnet-keygen",
    "dotnet-patcher",
    "electron-app-analyzer",
    "electron-builder-repacker",
    "electron-builder-unpacker",
    "frida-hooker",
    "ida-nuitka-reconstructor",
    "java-decompiler",
    "javascript-deobfuscator",
    "master-unlock",
    "memory-dumper",
    "network-interceptor",
    "nuitka-decryptor",
    "orchestrator-plugin-sdk",
    "pyinstaller-unpacker",
    "rust-binary-analyzer",
    "sbom-supply-chain-auditor",
    "symbolic-execution-tools",
    "tauri-unpacker",
    "vm-and-bytecode-reverse",
    "writerpro-pentest",
]

def main() -> int:
    if not CONFIG_SKILLS.exists():
        print(f"[!] Config directory not found: {CONFIG_SKILLS}", file=sys.stderr)
        return 1

    print(f"[+] Removing individual sub-skill links from {CONFIG_SKILLS}...\n")
    
    for name in sub_skills_to_remove:
        path = CONFIG_SKILLS / name
        if path.exists() or path.is_symlink():
            print(f"[*] Removing link: {path}")
            try:
                # Use cmd /c rmdir to safely delete directory links/junctions without touching target files
                subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", str(path)], check=True)
                print("    [+] Removed successfully.")
            except Exception as e:
                print(f"    [!] Error removing: {e}")
                
    print("\n[+] Cleaned up individual sub-skills. Only the main skill ('pentest-script-generator') is kept.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
