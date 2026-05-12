---
name: dotnet-patcher
description: "Patch .NET assemblies to bypass license checks — IL bytecode patching, method replacement, strong name removal, anti-tamper NOP. Works on raw bytes without requiring dnlib/Mono.Cecil at runtime."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# .NET Patcher

> Patch .NET assemblies at the IL bytecode level to bypass license validation, remove anti-tamper, strip strong names, and force method returns.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

| Sibling skill | When |
|---|---|
| [dotnet-decompiler](../dotnet-decompiler/SKILL.md) | Decompile first to identify patch targets |
| [dotnet-keygen](../dotnet-keygen/SKILL.md) | Generate keygen instead of patching |
| [binary-patcher](../binary-patcher/SKILL.md) | For native (non-.NET) patches |
| [frida-hooker](../frida-hooker/SKILL.md) | Runtime bypass without file modification |

---

## Step 1 — Find Patch Targets

Analyze decompiled source to identify license check methods:

```bash
python scripts/find_patch_targets.py decompiled/ --out targets.json
```

```powershell
python scripts\find_patch_targets.py decompiled\ --out targets.json
```

This scans for:
- Methods returning `bool` with license-related names
- `if/else` blocks checking `IsRegistered`, `IsLicensed`, `CheckLicense`
- String comparisons against serial/key patterns
- DateTime comparisons (trial expiry)
- Network calls to license servers

---

## Step 2 — Apply Patches

### Auto-patch license checks (scan + patch)

```bash
python scripts/patch_dotnet.py target.exe --auto --out patched/target.exe
```

### Patch specific method (force return true)

```bash
python scripts/patch_dotnet.py target.exe --method "LicenseManager::IsValid" --force-true --out patched/
```

### Patch specific method (force return false — disable feature check)

```bash
python scripts/patch_dotnet.py target.exe --method "Security::IsTrialExpired" --force-false --out patched/
```

### Remove strong name

```bash
python scripts/patch_dotnet.py target.exe --remove-strong-name --out patched/
```

### NOP anti-tamper module constructor

```bash
python scripts/patch_dotnet.py target.exe --nop-cctor --out patched/
```

### Patch string comparison (make any key valid)

```bash
python scripts/patch_dotnet.py target.exe --patch-strcmp "ValidateKey" --out patched/
```

---

## Step 3 — Verify Patch

```bash
python scripts/patch_dotnet.py patched/target.exe --verify
```

Checks:
- Assembly still loads (valid metadata)
- Patched methods have correct IL
- Strong name removed if requested
- File size delta report

---

## Final Report (Vietnamese)

```
🔧 .NET patch hoàn tất:

  🎯 Target          : <FILENAME>
  📐 Methods patched  : <COUNT>
  🔓 License bypass   : <YES/NO>
  🔑 Strong name      : <REMOVED/INTACT>
  🛡️ Anti-tamper      : <NOPPED/INTACT>
  📦 Output size      : <SIZE> (delta: <+/- BYTES>)

  💾 Output: patched/
```

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Patch without decompiling first | Always analyze decompiled source to find exact targets |
| Modify random bytes blindly | Use IL-aware patching (opcode-level) |
| Forget to remove strong name | Remove SN or re-sign — runtime will reject tampered signed assemblies |
| Skip anti-tamper check | NOP `<Module>.cctor` if it contains integrity checks |
| Patch only one check | Scan for ALL license checks — apps often have multiple |
| Ignore Costura.Fody DLLs | Extract and patch embedded license DLLs too |
