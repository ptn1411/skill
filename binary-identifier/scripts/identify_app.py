#!/usr/bin/env python3
"""
identify_app.py — Binary Fingerprinting Tool.
Identifies programming language, compiler, and potential packers/encryption.
"""
import argparse
import re
import sys
from pathlib import Path

# Markers for languages and compilers
MARKERS = {
    'Python': [
        rb'python[23]\d?\.dll', rb'Py_Initialize', rb'_Py_NoneStruct', rb'Include/Python.h',
        rb'libpython', rb'__compiled__', rb'nuitka', rb'pyinstaller', rb'pkg_resources'
    ],
    'Go': [
        rb'runtime.go', rb'main.main', rb'go.itab.', rb'runtime.mallocgc', rb'Go build ID'
    ],
    'Rust': [
        rb'rustc', rb'std::', rb'core::', rb'alloc::', rb'__rust_alloc',
        rb'rust_begin_unwind', rb'rust_panic', rb'\.rs:\d+:\d+',
        rb'core::panicking', rb'core::result::Result',
    ],
    'C# / .NET': [
        rb'mscoree.dll', rb'_CorExeMain', rb'System.Reflection', rb'mscorlib', rb'CLR'
    ],
    'Java': [
        rb'Ljava/lang/Object;', rb'java.lang', rb'JNI_CreateJavaVM', rb'com.sun.'
    ],
    'C++ / Visual Studio': [
        rb'MSVCP', rb'VCRUNTIME', rb'Microsoft Visual C++', rb'std::string', rb'operator new'
    ],
    'Delphi / Lazarus': [
        rb'TObject', rb'TForm', rb'TApplication', rb'VCL.Forms', rb'LCL.Forms'
    ]
}

# Markers for packers and obfuscators
PACKERS = {
    'UPX': [rb'UPX0', rb'UPX1', rb'UPX2'],
    'Nuitka (Onefile)': [rb'KA\x00', rb'NUITKA_ONEFILE_BINARY'],
    'PyInstaller': [rb'_PYI', rb'pyi-runtime-tmp', rb'pyi-windows-manifest'],
    'VMProtect': [rb'.vmp0', rb'.vmp1', rb'VMProtect begin'],
    'Themida': [rb'.themida', rb'Themida_V3'],
    'VBox / Enigma': [rb'.enigma', rb'Boxed App'],
    'Fernet (Encryption Indicator)': [rb'cryptography.fernet', rb'[A-Za-z0-9_-]{43}='],
    'Tauri': [rb'tauri::app', rb'__TAURI__', rb'tauri_runtime', rb'wry::webview', rb'tao::window'],
}

def identify(filepath):
    p = Path(filepath)
    if not p.exists():
        print(f"[!] Error: {filepath} not found.")
        return

    print(f"[*] Analyzing Binary: {p.name} ({p.stat().st_size:,} bytes)")
    data = p.read_bytes()
    
    results = {
        'Language/Compiler': [],
        'Packer/Protection': [],
        'Misc/Indicators': []
    }

    # 1. Check Languages
    for lang, markers in MARKERS.items():
        found = False
        for m in markers:
            if re.search(m, data):
                found = True
                break
        if found:
            results['Language/Compiler'].append(lang)

    # 2. Check Packers
    for packer, markers in PACKERS.items():
        found = False
        for m in markers:
            if re.search(m, data):
                found = True
                break
        if found:
            results['Packer/Protection'].append(packer)

    # 3. Special case for Nuitka detection
    if b'nuitka' in data.lower():
        if 'Python' not in results['Language/Compiler']:
             results['Language/Compiler'].append('Python (Nuitka)')

    # 3b. Java archive / class file detection
    if data[:4] == b'\xca\xfe\xba\xbe':
        if 'Java' not in results['Language/Compiler']:
            results['Language/Compiler'].append('Java')
        results['Misc/Indicators'].append('Java class file (0xCAFEBABE)')
    elif data[:2] == b'PK':
        import zipfile, io
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()
                if 'classes.dex' in names or 'AndroidManifest.xml' in names:
                    if 'Java' not in results['Language/Compiler']:
                        results['Language/Compiler'].append('Java')
                    results['Packer/Protection'].append('Android APK')
                elif 'META-INF/MANIFEST.MF' in names and any(n.endswith('.class') for n in names):
                    if 'Java' not in results['Language/Compiler']:
                        results['Language/Compiler'].append('Java')
                    if any(n.startswith('WEB-INF/') for n in names):
                        results['Misc/Indicators'].append('Java WAR archive')
                    else:
                        results['Misc/Indicators'].append('Java JAR archive')
        except Exception:
            pass
    
    # 4. Output Report
    print("\n" + "=" * 40)
    print(" FINGERPRINT REPORT")
    print("=" * 40)
    
    for category, items in results.items():
        print(f"\n[{category}]")
        if not items:
            print("  - Unknown / None detected")
        for item in items:
            print(f"  [+] {item}")
    
    print("\n" + "=" * 40)
    
    # Recommendations
    if 'Python (Nuitka)' in results['Language/Compiler'] or 'Nuitka (Onefile)' in results['Packer/Protection']:
        print("Recommendation: Use 'nuitka-decryptor' or 'writerpro-pentest' skills.")
    elif 'UPX' in results['Packer/Protection']:
        print("Recommendation: Try 'upx -d <file>' to unpack before analysis.")
    elif 'C# / .NET' in results['Language/Compiler']:
        print("Recommendation: Use 'dotnet-decompiler' (ilspycmd + de4dot). Then 'dotnet-patcher' + 'dotnet-keygen'.")
    elif 'Tauri' in results['Packer/Protection']:
        print("Recommendation: Use 'tauri-unpacker' to extract web assets, then 'rust-binary-analyzer' for backend.")
    elif 'Rust' in results['Language/Compiler']:
        print("Recommendation: Use 'rust-binary-analyzer' for symbol/module map. Use IDA/Ghidra for code.")
    elif 'PyInstaller' in results['Packer/Protection']:
        print("Recommendation: Use 'pyinstaller-unpacker' to extract .pyc and decompile.")
    elif 'Java' in results['Language/Compiler']:
        if 'Android APK' in results['Packer/Protection']:
            print("Recommendation: Use 'java-decompiler' with JADX for APK decompilation.")
        else:
            print("Recommendation: Use 'java-decompiler' (CFR/Procyon/FernFlower) for decompilation.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python identify_app.py <binary_path>")
    else:
        identify(sys.argv[1])
