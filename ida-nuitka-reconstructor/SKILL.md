---
name: ida-nuitka-reconstructor
description: "Reconstruct Python source code from Nuitka-compiled binaries (.dll/.exe/.pyd) by extracting serialized constants from PE .rsrc/.rdata sections and using IDA Pro MCP for live decompilation. Use when the target is a Nuitka onefile/standalone binary with NO .encrypted files — the Python is compiled to C, not encrypted."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# IDA + Nuitka Source Reconstructor

> Reconstruct readable Python source from Nuitka-compiled native binaries by combining IDA Pro MCP live analysis with raw PE section constant extraction.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## When to Use This Skill

| Condition | Use this skill |
|-----------|---------------|
| Nuitka **onefile** `.exe` with embedded `.dll` | ✅ Yes |
| Nuitka **standalone** `.pyd` / `.dll` | ✅ Yes |
| Nuitka + XOR/Base64 `.encrypted` files | ❌ Use `nuitka-decryptor` instead |
| PyInstaller `.exe` | ❌ Use `pyinstxtractor` |
| Electron `.asar` | ❌ Use `electron-builder-unpacker` |

**Key difference from `nuitka-decryptor`**: This skill handles the case where Python is **compiled to C** (no encrypted .py files exist). The source must be **reconstructed** from serialized Nuitka constants, not decrypted.

---

## How Nuitka Onefile Works

```
source.py → Nuitka compiler → C code → MSVC/GCC → native .dll/.exe
                                          ↓
                              Python constants serialized into PE .rsrc section
                              (strings, function names, class names, imports, URLs, HTML, JS)
```

**Key insight**: Nuitka compiles Python logic to C, but all **string constants** (literals, attribute names, module names, format strings) are stored as serialized blobs in the PE `.rsrc` section (sometimes `.rdata`). These constants contain enough information to reconstruct ~80-95% of the original source.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                IDA Pro (binary loaded)           │
│  ┌───────────┐  ┌──────────┐  ┌──────────────┐  │
│  │ list_funcs│  │ decompile│  │   py_eval    │  │
│  └─────┬─────┘  └────┬─────┘  └──────┬───────┘  │
│        │              │               │          │
│        └──────────┬───┘───────────────┘          │
│                   │ MCP HTTP :13337              │
└───────────────────┼──────────────────────────────┘
                    │
         ┌──────────▼──────────┐
         │ ida_mcp_analyze.py  │  ← Step 1: Structure analysis
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────────┐
         │ extract_rsrc_strings.py │  ← Step 2: Raw PE .rsrc extraction
         └──────────┬──────────────┘
                    │
         ┌──────────▼────────────────────┐
         │ reconstruct_nuitka_source.py  │  ← Step 3: Source reconstruction
         └──────────┬────────────────────┘
                    │
              reconstructed/*.py
```

---

## Step 1 — IDA MCP Analysis (Live Binary)

**Prerequisite**: IDA Pro is open with the target binary loaded. IDA MCP server running at `http://127.0.0.1:13337/mcp`.

Run `scripts/ida_mcp_analyze.py`:

```bash
python scripts/ida_mcp_analyze.py --url http://127.0.0.1:13337/mcp --out ida_analysis.json
```

What it does:
1. **List exports** — finds entry points (`run_code`, `DllEntryPoint`, etc.)
2. **List functions** — catalogs all named functions with addresses
3. **Decompile key functions** — pseudo-C for entry points and interesting functions
4. **PE section mapping** via `py_eval` — finds `.rsrc` / `.rdata` offsets and sizes
5. **Check mapped memory** — confirms which sections IDA has loaded

**Known IDA limitations with Nuitka**:
- `survey_binary` **timeouts** on large binaries (>20MB) — script uses targeted queries instead
- `.rsrc` section is **NOT mapped** by IDA — string searches (`find`, `find_regex`) return empty
- IDA 9.x removed `ida_search.find_binary` — script uses `ida_bytes.bin_search` with `compiled_binpat_vec_t`

**When IDA MCP is not available** (IDA not open): Skip this step. Steps 2-3 work standalone.

---

## Step 2 — Extract Constants from PE .rsrc Section

Run `scripts/extract_rsrc_strings.py`:

```bash
# Basic extraction
python scripts/extract_rsrc_strings.py --binary target.dll --out extracted_strings.json

# With IDA analysis for cross-referencing
python scripts/extract_rsrc_strings.py --binary target.dll --ida-analysis ida_analysis.json --out extracted_strings.json

# Also check .rdata section
python scripts/extract_rsrc_strings.py --binary target.dll --sections rsrc,rdata --out extracted_strings.json
```

What it does:
1. Parse PE headers to locate `.rsrc` and `.rdata` sections
2. Read raw bytes from each section
3. Extract all UTF-8 printable strings (min length 4)
4. Categorize strings by type:
   - `imports` — module names (`tkinter`, `playwright`, `json`, etc.)
   - `functions` — function/method names (Nuitka prefixed with `u` or `a`)
   - `classes` — class names
   - `urls` — HTTP/HTTPS URLs and endpoints
   - `html_js` — embedded HTML/JavaScript code
   - `format_strings` — Python format strings and templates
   - `constants` — other string literals
5. Detect Nuitka serialization markers (`u`, `a`, `s`, `w` prefixes)
6. Output structured JSON for Step 3

**Nuitka serialization format** (see `references/nuitka_serialization_format.md`):
- `u` prefix → unicode string literal (e.g., `u\x0bhello world`)
- `a` prefix → attribute/identifier name (e.g., `a\x04self`)
- Length encoded as 1-4 bytes after prefix
- Strings appear in order of source code occurrence

---

## Step 3 — Reconstruct Python Source

Run `scripts/reconstruct_nuitka_source.py`:

```bash
# Auto-reconstruct from extracted strings
python scripts/reconstruct_nuitka_source.py \
  --strings extracted_strings.json \
  --out reconstructed/

# With IDA decompilation data for better structure
python scripts/reconstruct_nuitka_source.py \
  --strings extracted_strings.json \
  --ida-analysis ida_analysis.json \
  --out reconstructed/

# Interactive mode — shows candidates and asks for confirmation
python scripts/reconstruct_nuitka_source.py \
  --strings extracted_strings.json \
  --interactive \
  --out reconstructed/
```

What it does:
1. **Import recovery** — identifies `import X`, `from X import Y` from module name strings
2. **Class/function skeleton** — builds class and function definitions from attribute names
3. **String literal placement** — maps string constants to likely code locations
4. **URL/endpoint mapping** — reconstructs API call patterns
5. **GUI reconstruction** — detects tkinter/Qt patterns and rebuilds UI code
6. **JavaScript/HTML embedding** — preserves embedded code blocks
7. **Constants and config** — reconstructs module-level constants

**Reconstruction accuracy depends on**:
- Number and quality of string constants preserved by Nuitka
- Presence of format strings (reveal variable names and logic)
- HTML/JS templates (often contain complete code blocks)
- Error messages (reveal function flow and validation logic)

---

## Step 4 — Verify & Test

```bash
# Syntax check
python -m py_compile reconstructed/main.py

# Try to run (may need dependencies)
pip install playwright pyotp  # or whatever the target needs
python reconstructed/main.py

# Compare behavior with original
# Run original .exe and reconstructed .py side by side
```

---

## Workflow Summary

```
1. IDA MCP    → ida_mcp_analyze.py   → Structure: exports, functions, PE layout
2. PE EXTRACT → extract_rsrc_strings.py → All string constants from .rsrc/.rdata
3. RECONSTRUCT → reconstruct_nuitka_source.py → Python source files
4. VERIFY     → Run reconstructed code, compare with original
5. REPORT     → Present findings to user IN VIETNAMESE
```

---

## Integration with Other Skills

| When | Chain to |
|------|----------|
| Binary not yet identified | Run `binary-identifier` first |
| Found .encrypted files alongside .pyd | Switch to `nuitka-decryptor` |
| Found anti-debug in dispatcher | Use `anti-debugging-techniques` |
| Need to patch license check in reconstructed code | Use `binary-patcher` |
| Reconstructed code has obfuscated JS | Chain to `javascript-deobfuscator` |
| Need keygen from reconstructed license logic | Use `writerpro-pentest` |

---

## Final Report to User (always in Vietnamese)

```
🔬 Tái tạo source code Nuitka hoàn tất:

  📦 Binary phân tích : <FILENAME> (<SIZE>)
  🏗️ Kiến trúc       : Nuitka Onefile (Python <VER> → C → native)
  📊 PE Sections      : .text (<SIZE>), .rsrc (<SIZE>), .rdata (<SIZE>)

  🔍 IDA MCP Analysis:
    - Exports    : <COUNT> (run_code, DllEntryPoint, ...)
    - Functions  : <COUNT> identified
    - Decompiled : <COUNT> key functions

  📝 Constants Extracted:
    - Imports       : <COUNT> module names
    - Functions     : <COUNT> function/method names
    - Classes       : <COUNT> class names
    - URLs          : <COUNT> endpoints
    - HTML/JS       : <COUNT> embedded code blocks
    - String literals: <COUNT> constants

  ✅ Source Reconstructed:
    - Files    : <COUNT> .py files
    - Lines    : <COUNT> total lines
    - Accuracy : ~<PERCENT>% (estimated)

  💾 Output: reconstructed/

  ▶ Bước tiếp theo:
    - Kiểm tra code: python reconstructed/main.py
    - Tìm secrets: grep -rn "api_key\|secret\|token" reconstructed/
    - Keygen: sử dụng writerpro-pentest nếu cần
```

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Search strings via IDA find/find_regex on Nuitka binary | Read raw PE bytes — .rsrc is not mapped |
| Use `survey_binary` on large Nuitka DLLs | Use targeted `list_funcs` + `decompile` |
| Assume all Nuitka apps have .encrypted files | Many are compiled-only, no encryption layer |
| Try to decompile Nuitka C code back to Python | Extract constants and reconstruct — C decompilation gives Nuitka runtime, not original Python |
| Skip IDA when available | IDA provides function structure and xrefs that improve reconstruction accuracy |
| Present findings in English | Always deliver final summary in Vietnamese |
