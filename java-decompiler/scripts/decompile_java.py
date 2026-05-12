#!/usr/bin/env python3
"""
decompile_java.py — Decompile Java applications (JAR/WAR/APK/class).

Extracts archives, detects obfuscators, and decompiles bytecode to .java
source using CFR → Procyon → FernFlower → javap fallback chain.

Usage:
    python decompile_java.py app.jar --out output/java-decompiled
    python decompile_java.py app.apk --out output/java-decompiled
    python decompile_java.py MyClass.class --out output/java-decompiled
    python decompile_java.py app.jar --out output --decompiler procyon
"""

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path


# --- Archive type detection ---------------------------------------------------

def detect_archive_type(filepath: Path) -> str:
    """Detect Java archive type from magic bytes and contents."""
    data = filepath.read_bytes()[:8]

    # Class file: 0xCAFEBABE
    if data[:4] == b'\xca\xfe\xba\xbe':
        return 'class'

    # ZIP-based (JAR/WAR/EAR/APK)
    if data[:2] == b'PK':
        try:
            with zipfile.ZipFile(filepath) as zf:
                names = zf.namelist()
                if 'classes.dex' in names or 'AndroidManifest.xml' in names:
                    return 'apk'
                if 'WEB-INF/web.xml' in names:
                    return 'war'
                if 'META-INF/application.xml' in names:
                    return 'ear'
                if any(n.endswith('.class') for n in names):
                    return 'jar'
                return 'jar'
        except zipfile.BadZipFile:
            pass

    return 'unknown'


# --- Archive extraction -------------------------------------------------------

def extract_jar(filepath: Path, out_dir: Path) -> dict:
    """Extract JAR/WAR/EAR and parse metadata."""
    extract_dir = out_dir / 'extracted'
    extract_dir.mkdir(parents=True, exist_ok=True)

    manifest = {}
    class_count = 0
    resource_files = []

    with zipfile.ZipFile(filepath) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            # Extract
            target = extract_dir / info.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, 'wb') as dst:
                dst.write(src.read())

            if info.filename.endswith('.class'):
                class_count += 1
            else:
                resource_files.append(info.filename)

        # Parse MANIFEST.MF
        if 'META-INF/MANIFEST.MF' in zf.namelist():
            mf_text = zf.read('META-INF/MANIFEST.MF').decode('utf-8', errors='replace')
            manifest = parse_manifest(mf_text)

    return {
        'extract_dir': str(extract_dir),
        'class_count': class_count,
        'resource_count': len(resource_files),
        'resources': resource_files[:50],
        'manifest': manifest,
    }


def parse_manifest(text: str) -> dict:
    """Parse MANIFEST.MF into a dict."""
    result = {}
    current_key = None
    for line in text.splitlines():
        if line.startswith(' ') and current_key:
            result[current_key] += line[1:]
        elif ':' in line:
            key, _, value = line.partition(':')
            current_key = key.strip()
            result[current_key] = value.strip()
    return result


# --- Obfuscator detection ----------------------------------------------------

OBFUSCATOR_SIGNATURES = {
    'ProGuard': {
        'class_patterns': [
            r'^[a-z]\.class$',
            r'^[a-z]{1,2}/[a-z]{1,2}\.class$',
        ],
        'file_markers': ['proguard.map', 'proguard-rules.pro', 'proguard.cfg'],
        'string_markers': [],
    },
    'Allatori': {
        'class_patterns': [],
        'file_markers': [],
        'string_markers': [b'Allatori', b'allatori', b'\x00ALLATORi\x00'],
    },
    'Zelix KlassMaster (ZKM)': {
        'class_patterns': [],
        'file_markers': [],
        'string_markers': [b'ZKM', b'Zelix', b'zKM'],
    },
    'Stringer': {
        'class_patterns': [],
        'file_markers': [],
        'string_markers': [b'Stringer Java Obfuscator', b'stringer.jar'],
    },
    'DashO': {
        'class_patterns': [],
        'file_markers': [],
        'string_markers': [b'DashO', b'PreEmptive'],
    },
    'yGuard': {
        'class_patterns': [],
        'file_markers': ['yguard.xml'],
        'string_markers': [b'yGuard', b'yworks'],
    },
    'ClassGuard': {
        'class_patterns': [],
        'file_markers': [],
        'string_markers': [b'ClassGuard', b'Semantic Designs'],
    },
    'JObfuscator': {
        'class_patterns': [],
        'file_markers': [],
        'string_markers': [b'JObfuscator', b'PELock'],
    },
}


def detect_obfuscator(extract_dir: Path, archive_data: bytes | None = None) -> dict:
    """Detect obfuscation in extracted Java classes."""
    detected = []

    # Collect class file names
    class_files = []
    for f in extract_dir.rglob('*.class'):
        rel = str(f.relative_to(extract_dir)).replace('\\', '/')
        class_files.append(rel)

    # Collect all bytes from class files for string scanning (sample first 50)
    sample_data = b''
    for f in sorted(extract_dir.rglob('*.class'))[:50]:
        sample_data += f.read_bytes()[:4096]

    if archive_data:
        sample_data += archive_data[:100000]

    for name, sigs in OBFUSCATOR_SIGNATURES.items():
        evidence = []

        # Class name patterns
        for pattern in sigs['class_patterns']:
            matches = [c for c in class_files if re.match(pattern, c.split('/')[-1])]
            if len(matches) > 5:
                evidence.append(f"class pattern: {len(matches)} matches")

        # File markers
        for marker in sigs['file_markers']:
            if any(marker in str(f) for f in extract_dir.rglob('*')):
                evidence.append(f"file: {marker}")

        # String markers
        for marker in sigs['string_markers']:
            if marker in sample_data:
                evidence.append(f"string: {marker.decode('ascii', errors='replace')}")

        if evidence:
            detected.append({
                'name': name,
                'evidence': evidence,
                'confidence': min(len(evidence) / 2.0, 1.0),
            })

    # Heuristic: check for single-letter package/class names (generic obfuscation)
    short_names = [c for c in class_files if re.match(r'^([a-z]/)*[a-z]\.class$', c)]
    ratio = len(short_names) / max(len(class_files), 1)
    if ratio > 0.3 and len(short_names) > 10:
        # Check if already attributed to ProGuard
        if not any(d['name'] == 'ProGuard' for d in detected):
            detected.append({
                'name': 'ProGuard (heuristic)',
                'evidence': [f"{len(short_names)}/{len(class_files)} short class names ({ratio:.0%})"],
                'confidence': min(ratio, 1.0),
            })

    # String encryption heuristic: many classes with decryption-looking patterns
    encrypted_string_classes = 0
    for f in sorted(extract_dir.rglob('*.class'))[:100]:
        data = f.read_bytes()
        # Common pattern: method that XORs/decodes byte arrays
        if b'\xb8' in data and (b'javax/crypto' in data or b'[B' in data):
            encrypted_string_classes += 1
    if encrypted_string_classes > 5:
        detected.append({
            'name': 'String Encryption (generic)',
            'evidence': [f"{encrypted_string_classes} classes with crypto/byte-array patterns"],
            'confidence': 0.6,
        })

    return {
        'obfuscated': bool(detected),
        'obfuscators': detected,
        'total_classes': len(class_files),
        'short_name_ratio': ratio if class_files else 0,
    }


# --- Decompiler wrappers -----------------------------------------------------

def find_decompiler(name: str) -> str | None:
    """Find a Java decompiler executable or JAR."""
    # Check common locations
    search_names = {
        'cfr': ['cfr.jar', 'cfr-*.jar', 'cfr_*.jar'],
        'procyon': ['procyon-decompiler.jar', 'procyon.jar', 'procyon-decompiler-*.jar'],
        'fernflower': ['fernflower.jar', 'intellij-fernflower.jar'],
        'jadx': ['jadx', 'jadx.bat', 'jadx.exe'],
        'javap': ['javap', 'javap.exe'],
    }

    if name == 'jadx':
        path = shutil.which('jadx')
        if path:
            return path
        # Check common install dirs
        for d in [Path.home() / 'jadx' / 'bin', Path('C:/tools/jadx/bin')]:
            exe = d / ('jadx.bat' if sys.platform == 'win32' else 'jadx')
            if exe.exists():
                return str(exe)
        return None

    if name == 'javap':
        return shutil.which('javap')

    java = shutil.which('java')
    if not java:
        return None

    # Search for JAR files
    search_dirs = [
        Path('.'),
        Path.home() / 'tools',
        Path.home() / '.local' / 'share' / 'java',
        Path('C:/tools'),
        Path('/opt'),
    ]

    # Also check CLASSPATH and common env vars
    for env in ['CFR_JAR', 'PROCYON_JAR', 'FERNFLOWER_JAR']:
        val = os.environ.get(env)
        if val and Path(val).exists():
            return val

    for d in search_dirs:
        if not d.exists():
            continue
        for pattern in search_names.get(name, []):
            for match in d.rglob(pattern):
                if match.is_file():
                    return str(match)

    return None


def decompile_with_cfr(jar_or_dir: Path, out_dir: Path, cfr_jar: str) -> tuple[int, str, str]:
    """Decompile using CFR."""
    src_dir = out_dir / 'src'
    src_dir.mkdir(parents=True, exist_ok=True)

    cmd = ['java', '-jar', cfr_jar, str(jar_or_dir), '--outputdir', str(src_dir)]

    if jar_or_dir.is_dir():
        # Decompile all .class files in directory
        cmd = ['java', '-jar', cfr_jar, '--outputdir', str(src_dir)]
        class_files = list(jar_or_dir.rglob('*.class'))
        if len(class_files) > 500:
            cmd.extend([str(jar_or_dir / '*.class')])
        else:
            cmd.extend([str(f) for f in class_files[:500]])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:]
    except subprocess.TimeoutExpired:
        return 1, '', 'CFR timed out (300s)'
    except FileNotFoundError:
        return 1, '', 'java not found'


def decompile_with_procyon(jar_or_dir: Path, out_dir: Path, procyon_jar: str) -> tuple[int, str, str]:
    """Decompile using Procyon."""
    src_dir = out_dir / 'src'
    src_dir.mkdir(parents=True, exist_ok=True)

    cmd = ['java', '-jar', procyon_jar, '-o', str(src_dir), str(jar_or_dir)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:]
    except subprocess.TimeoutExpired:
        return 1, '', 'Procyon timed out (300s)'
    except FileNotFoundError:
        return 1, '', 'java not found'


def decompile_with_fernflower(jar_or_dir: Path, out_dir: Path, ff_jar: str) -> tuple[int, str, str]:
    """Decompile using FernFlower."""
    src_dir = out_dir / 'src'
    src_dir.mkdir(parents=True, exist_ok=True)

    cmd = ['java', '-jar', ff_jar, str(jar_or_dir), str(src_dir)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        # FernFlower outputs a JAR of sources — extract it
        for f in src_dir.glob('*.jar'):
            try:
                with zipfile.ZipFile(f) as zf:
                    zf.extractall(src_dir)
                f.unlink()
            except zipfile.BadZipFile:
                pass
        return proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:]
    except subprocess.TimeoutExpired:
        return 1, '', 'FernFlower timed out (300s)'
    except FileNotFoundError:
        return 1, '', 'java not found'


def decompile_with_jadx(apk_path: Path, out_dir: Path, jadx_bin: str) -> tuple[int, str, str]:
    """Decompile APK using JADX."""
    src_dir = out_dir / 'src'
    src_dir.mkdir(parents=True, exist_ok=True)

    cmd = [jadx_bin, '-d', str(src_dir), '--no-res', str(apk_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:]
    except subprocess.TimeoutExpired:
        return 1, '', 'JADX timed out (600s)'
    except FileNotFoundError:
        return 1, '', 'jadx not found'


def decompile_with_javap(class_dir: Path, out_dir: Path) -> tuple[int, str, str]:
    """Fallback: bytecode listing with javap."""
    javap = shutil.which('javap')
    if not javap:
        return 1, '', 'javap not found (install JDK)'

    src_dir = out_dir / 'src'
    src_dir.mkdir(parents=True, exist_ok=True)

    output_lines = []
    class_files = list(class_dir.rglob('*.class'))[:200]

    for cf in class_files:
        try:
            proc = subprocess.run(
                [javap, '-c', '-p', str(cf)],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode == 0:
                # Save to .javap.txt
                rel = cf.relative_to(class_dir)
                dest = src_dir / str(rel).replace('.class', '.javap.txt')
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(proc.stdout, encoding='utf-8')
                output_lines.append(f"[+] {rel}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return 0, '\n'.join(output_lines[-50:]), f'javap fallback: {len(output_lines)} classes'


# --- APK handling -------------------------------------------------------------

def handle_apk(apk_path: Path, out_dir: Path, preferred: str | None) -> tuple[int, str, str]:
    """Handle Android APK decompilation."""
    # Try JADX first (best for APK)
    jadx = find_decompiler('jadx')
    if jadx and preferred in (None, 'jadx'):
        print("[*] Using JADX for APK decompilation...")
        return decompile_with_jadx(apk_path, out_dir, jadx)

    # Fallback: dex2jar + CFR
    dex2jar = shutil.which('d2j-dex2jar') or shutil.which('dex2jar') or shutil.which('d2j-dex2jar.bat')
    if dex2jar:
        print("[*] Converting DEX to JAR with dex2jar...")
        jar_out = out_dir / 'converted.jar'
        try:
            proc = subprocess.run(
                [dex2jar, str(apk_path), '-o', str(jar_out), '--force'],
                capture_output=True, text=True, timeout=120,
            )
            if proc.returncode == 0 and jar_out.exists():
                return decompile_jar(jar_out, out_dir, preferred)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # Fallback: extract classes.dex + manual processing
    print("[!] No APK decompiler found (install JADX or dex2jar)")
    extract_dir = out_dir / 'extracted'
    extract_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(apk_path) as zf:
        zf.extractall(extract_dir)
    return 1, f'Extracted APK to {extract_dir}', 'No decompiler — install jadx or dex2jar'


def decompile_jar(jar_path: Path, out_dir: Path, preferred: str | None) -> tuple[int, str, str]:
    """Try decompilers in priority order for JAR/class files."""
    decompilers = ['cfr', 'procyon', 'fernflower']
    if preferred:
        decompilers = [preferred] + [d for d in decompilers if d != preferred]

    for name in decompilers:
        tool = find_decompiler(name)
        if not tool:
            continue

        print(f"[*] Decompiling with {name}...")
        if name == 'cfr':
            rc, out, err = decompile_with_cfr(jar_path, out_dir, tool)
        elif name == 'procyon':
            rc, out, err = decompile_with_procyon(jar_path, out_dir, tool)
        elif name == 'fernflower':
            rc, out, err = decompile_with_fernflower(jar_path, out_dir, tool)
        else:
            continue

        if rc == 0:
            print(f"[+] Decompilation successful with {name}")
            return rc, f"[decompiler: {name}]\n{out}", err

        print(f"[-] {name} failed (rc={rc}), trying next...")

    # Final fallback: javap
    extract_dir = out_dir / 'extracted'
    if extract_dir.exists():
        print("[*] Falling back to javap bytecode listing...")
        return decompile_with_javap(extract_dir, out_dir)

    return 1, '', 'No Java decompiler found — install CFR, Procyon, or FernFlower'


# --- Main decompile -----------------------------------------------------------

def decompile(filepath: Path, out_dir: Path, preferred_decompiler: str | None = None) -> dict:
    """Full decompilation pipeline."""
    result = {
        'file': str(filepath),
        'type': 'unknown',
        'extraction': None,
        'obfuscation': None,
        'decompilation': {'success': False, 'decompiler': None},
        'stats': {},
    }

    # Detect type
    ftype = detect_archive_type(filepath)
    result['type'] = ftype
    print(f"[*] Detected type: {ftype}")

    out_dir.mkdir(parents=True, exist_ok=True)

    # Single class file
    if ftype == 'class':
        print(f"[*] Single class file: {filepath.name}")
        extract_dir = out_dir / 'extracted'
        extract_dir.mkdir(parents=True, exist_ok=True)
        dest = extract_dir / filepath.name
        shutil.copy2(filepath, dest)
        result['extraction'] = {'class_count': 1, 'extract_dir': str(extract_dir)}

        rc, stdout, stderr = decompile_jar(extract_dir, out_dir, preferred_decompiler)
        result['decompilation'] = {
            'success': rc == 0,
            'decompiler': preferred_decompiler or 'auto',
            'stdout_tail': stdout[-1000:],
            'stderr_tail': stderr[-500:],
        }

        return result

    # APK
    if ftype == 'apk':
        print(f"[*] Android APK: {filepath.name}")
        # Also extract for analysis
        extract_info = extract_jar(filepath, out_dir)
        result['extraction'] = extract_info
        result['extraction']['manifest'] = extract_info['manifest']

        rc, stdout, stderr = handle_apk(filepath, out_dir, preferred_decompiler)
        result['decompilation'] = {
            'success': rc == 0,
            'decompiler': preferred_decompiler or 'jadx',
            'stdout_tail': stdout[-1000:],
            'stderr_tail': stderr[-500:],
        }

        # Detect obfuscation
        extract_dir = Path(extract_info['extract_dir'])
        result['obfuscation'] = detect_obfuscator(extract_dir)

        return result

    # JAR/WAR/EAR
    if ftype in ('jar', 'war', 'ear'):
        print(f"[*] Extracting {ftype.upper()}: {filepath.name}")
        extract_info = extract_jar(filepath, out_dir)
        result['extraction'] = extract_info

        manifest = extract_info['manifest']
        if manifest:
            main_class = manifest.get('Main-Class')
            if main_class:
                print(f"[+] Main-Class: {main_class}")

        # Detect obfuscation
        extract_dir = Path(extract_info['extract_dir'])
        archive_data = filepath.read_bytes()[:200000]
        obf = detect_obfuscator(extract_dir, archive_data)
        result['obfuscation'] = obf
        if obf['obfuscated']:
            for o in obf['obfuscators']:
                print(f"[!] Obfuscator detected: {o['name']} ({', '.join(o['evidence'][:3])})")

        # Decompile
        rc, stdout, stderr = decompile_jar(filepath, out_dir, preferred_decompiler)
        result['decompilation'] = {
            'success': rc == 0,
            'decompiler': preferred_decompiler or 'auto',
            'stdout_tail': stdout[-1000:],
            'stderr_tail': stderr[-500:],
        }
    else:
        print(f"[!] Unknown file type — attempting JAR decompilation anyway")
        extract_info = extract_jar(filepath, out_dir)
        result['extraction'] = extract_info
        rc, stdout, stderr = decompile_jar(filepath, out_dir, preferred_decompiler)
        result['decompilation'] = {
            'success': rc == 0,
            'stdout_tail': stdout[-1000:],
            'stderr_tail': stderr[-500:],
        }

    # Count decompiled files
    src_dir = out_dir / 'src'
    if src_dir.exists():
        java_files = list(src_dir.rglob('*.java'))
        javap_files = list(src_dir.rglob('*.javap.txt'))
        result['stats'] = {
            'java_source_files': len(java_files),
            'javap_files': len(javap_files),
            'src_dir': str(src_dir),
        }
        print(f"[+] Decompiled: {len(java_files)} .java files" +
              (f", {len(javap_files)} bytecode listings" if javap_files else ""))

    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Decompile Java applications (JAR/WAR/APK/class)")
    ap.add_argument('target', help='JAR, WAR, APK, or class file')
    ap.add_argument('--out', required=True, help='Output directory')
    ap.add_argument('--decompiler', choices=['cfr', 'procyon', 'fernflower', 'jadx'],
                    help='Preferred decompiler (default: auto)')
    ap.add_argument('--no-extract', action='store_true', help='Skip archive extraction (decompile only)')
    args = ap.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"[!] Not found: {target}", file=sys.stderr)
        return 1

    out_dir = Path(args.out)
    result = decompile(target, out_dir, args.decompiler)

    # Save result
    json_path = out_dir / 'decompile_result.json'
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"\n[+] Result: {json_path}")

    # Summary
    print(f"\n{'=' * 50}")
    print(f"[+] Type: {result['type']}")
    print(f"[+] Decompiled: {'Yes' if result['decompilation']['success'] else 'No'}")
    if result['obfuscation'] and result['obfuscation']['obfuscated']:
        print(f"[!] Obfuscated: {', '.join(o['name'] for o in result['obfuscation']['obfuscators'])}")
    if result['stats']:
        print(f"[+] Source files: {result['stats'].get('java_source_files', 0)}")

    if not result['decompilation']['success']:
        print("\n[*] Install a decompiler:")
        print("    CFR:       download cfr.jar, set CFR_JAR env var")
        print("    Procyon:   download procyon-decompiler.jar, set PROCYON_JAR env var")
        print("    JADX:      pip install jadx  (best for APK)")
        return 1

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
