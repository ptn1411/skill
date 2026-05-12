---
name: pyinstaller-unpacker
description: "Fully automated PyInstaller extraction and decompilation pipeline. Extracts .pyc from onefile/onedir bundles, fixes headers, and batch-decompiles with pycdc/uncompyle6/decompile3 fallback chain."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# PyInstaller Unpacker & Decompiler

> Extract and decompile Python source from PyInstaller-bundled executables (.exe/.elf).

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

| Sibling skill | When |
|---|---|
| [binary-identifier](../binary-identifier/SKILL.md) | Upstream — confirms target is PyInstaller |
| [nuitka-decryptor](../nuitka-decryptor/SKILL.md) | If misidentified — Nuitka ≠ PyInstaller |
| [writerpro-pentest](../writerpro-pentest/SKILL.md) | Downstream — keygen from recovered source |
| [javascript-deobfuscator](../javascript-deobfuscator/SKILL.md) | If embedded Electron+PyInstaller hybrid |

---

## How PyInstaller Works

```
source.py → PyInstaller → CArchive → native bootloader + embedded .pyc/.pyz
                              ↓
              MEI magic marker at end of file: b'MEI\x0c\x0b\x0a\x0b\x0e'
              TOC (Table of Contents) lists all embedded files
              PYZ archive contains all imported modules as .pyc
```

**Two modes:**
- **Onefile**: Single .exe with temp extraction at runtime. Everything in CArchive.
- **Onedir**: Directory with main .exe + `_internal/` folder containing .pyc/.pyd/.dll.

**Key challenge**: PyInstaller **strips .pyc headers** (first 16 bytes: magic + flags + timestamp + size). Must restore before decompilation.

---

## Step 1 — Recon: Confirm PyInstaller

Look for these markers:
- `MEI` magic at end of file (8 bytes)
- Strings: `_MEIPASS`, `_MEI`, `pyi_rth_`, `pyiboot`
- Section names or overlay data past PE end

```bash
python scripts/unpack_pyinstaller.py --detect-only target.exe
```

```powershell
python scripts\unpack_pyinstaller.py --detect-only target.exe
```

---

## Step 2 — Extract .pyc Files

```bash
python scripts/unpack_pyinstaller.py target.exe --out unpacked/
```

```powershell
python scripts\unpack_pyinstaller.py target.exe --out unpacked\
```

What it does:
1. Detect PyInstaller variant (onefile/onedir) and Python version
2. If `pyinstxtractor-ng` available → use it (best compatibility)
3. Fallback → manual CArchive parsing (built-in, no deps)
4. Fix .pyc headers with correct magic number for detected Python version
5. Extract PYZ archive (all imported modules)
6. Write `manifest.json` listing all extracted files

---

## Step 3 — Decompile .pyc to .py

```bash
python scripts/decompile_pyc.py --pyc-dir unpacked/ --out decompiled/
```

```powershell
python scripts\decompile_pyc.py --pyc-dir unpacked\ --out decompiled\
```

**Fallback chain** (version-aware):

| Python version | Primary | Secondary | Last resort |
|---------------|---------|-----------|-------------|
| 3.9+ | pycdc | decompile3 | dis (bytecode) |
| 3.6–3.8 | uncompyle6 | pycdc | dis |
| 3.5 and below | uncompyle6 | — | dis |

---

## Step 4 — Verify & Analyze

```bash
head -50 decompiled/main.py
grep -rn "api_key\|secret\|password\|token\|license" decompiled/
```

---

## Workflow

```
1. DETECT    → unpack_pyinstaller.py --detect-only → confirm PyInstaller + version
2. EXTRACT   → unpack_pyinstaller.py → .pyc files + PYZ modules
3. DECOMPILE → decompile_pyc.py → .py source files
4. ANALYZE   → grep for secrets, license logic, endpoints
5. REPORT    → Present findings IN VIETNAMESE
```

---

## Final Report to User (always in Vietnamese)

```
📦 Giải nén PyInstaller hoàn tất:

  🔍 Loại          : PyInstaller <onefile|onedir>
  🐍 Python        : <VERSION>
  📁 Files trích xuất: <COUNT> files
  📝 Decompile      : <SUCCESS>/<TOTAL> files thành công

  🔑 Phát hiện đáng chú ý:
    - <secrets, license logic, endpoints>

  💾 Output: decompiled/

  ▶ Bước tiếp theo:
    grep -rn "api_key\|secret" decompiled/
```

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Assume all Python exes are PyInstaller | Run binary-identifier first — could be Nuitka, cx_Freeze, py2exe |
| Skip .pyc header fix | PyInstaller strips headers — decompilers fail without them |
| Use only one decompiler | Version-aware fallback chain catches more files |
| Ignore PYZ archive | It contains all imported modules — often more interesting than main script |
| Decompile without knowing Python version | Magic bytes differ per version — wrong header = wrong output |
