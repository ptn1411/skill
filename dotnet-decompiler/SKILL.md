---
name: dotnet-decompiler
description: "Automated .NET/C# decompilation and security analysis. Uses ilspycmd for batch decompilation with manual IL fallback. Detects obfuscators (ConfuserEx, .NET Reactor, Babel) and scans for license logic, API keys, and protection patterns."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# .NET Decompiler & Analyzer

> Decompile .NET assemblies to C# source and analyze for license logic, secrets, and protection patterns.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

| Sibling skill | When |
|---|---|
| [binary-identifier](../binary-identifier/SKILL.md) | Upstream — confirms target is .NET |
| [binary-patcher](../binary-patcher/SKILL.md) | Downstream — patch license checks |
| [symbolic-execution-tools](../symbolic-execution-tools/SKILL.md) | Solve license constraints symbolically |
| [frida-hooker](../frida-hooker/SKILL.md) | Dynamic bypass via CLR hooking |

---

## How .NET Works

```
source.cs → C# compiler → IL bytecode (.dll/.exe with CLI header)
                              ↓
              Metadata tables (types, methods, fields, strings)
              IL method bodies (CIL instructions)
              Resources (embedded files, configs, Costura.Fody merged DLLs)
```

**.NET decompilation is high-fidelity** — IL bytecode retains most source structure (names, types, control flow). Obfuscators try to break this by renaming, encrypting strings, flattening control flow.

---

## Step 1 — Detect .NET and Obfuscator

```bash
python scripts/decompile_dotnet.py --detect-only target.exe
```

```powershell
python scripts\decompile_dotnet.py --detect-only target.exe
```

Checks: `mscoree.dll` import, CLI header, `BSJB` metadata signature, obfuscator markers.

---

## Step 2 — Decompile

```bash
python scripts/decompile_dotnet.py target.exe --out decompiled/
```

```powershell
python scripts\decompile_dotnet.py target.exe --out decompiled\
```

**Decompiler priority:**
1. `ilspycmd` (ILSpy CLI) — install: `dotnet tool install -g ilspycmd`
2. Manual IL metadata extraction (built-in, no deps)

---

## Step 3 — Analyze

```bash
python scripts/analyze_dotnet.py decompiled/ --out analysis/
```

Scans for:
- License validation (LicenseManager, TrialCheck, ExpiryDate, HWID)
- API keys and connection strings
- Obfuscation artifacts (unprintable names, delegate CF, resource decryptors)
- Costura.Fody merged assemblies

---

## Workflow

```
1. DETECT    → decompile_dotnet.py --detect-only → .NET version + obfuscator
2. DECOMPILE → decompile_dotnet.py → C# source
3. ANALYZE   → analyze_dotnet.py → license logic + secrets + protection map
4. REPORT    → Present findings IN VIETNAMESE
```

---

## Final Report to User (always in Vietnamese)

```
🔷 Decompile .NET hoàn tất:

  🏗️ Framework     : .NET <VERSION>
  🛡️ Obfuscator    : <DETECTED or None>
  📁 Files decompile: <COUNT> types
  🔑 License logic  : <FOUND/NOT FOUND>

  🔍 Phát hiện:
    - <license methods, API keys, protection patterns>

  💾 Output: decompiled/

  ▶ Bước tiếp theo:
    - binary-patcher: patch license check
    - frida-hooker: hook CLR methods runtime
```

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Assume all .NET apps are unprotected | Check for obfuscator first |
| Skip resource extraction | Costura.Fody hides DLLs as resources |
| Use only GUI tools (dnSpy) | ilspycmd automates batch decompilation |
| Ignore string encryption | ConfuserEx encrypts strings — look for decryptor methods |
| Present findings in English | Final summary in Vietnamese |
