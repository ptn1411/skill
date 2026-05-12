---
name: memory-dumper
description: "Dump process memory and scan for secrets, license keys, decryption keys, tokens, and crypto artifacts. Cross-platform: comsvcs.dll / MiniDumpWriteDump on Windows, /proc/mem on Linux."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Memory Dumper

> Dump running process memory and scan for embedded secrets — license keys, API tokens, crypto keys, decrypted strings that never touch disk.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

| Sibling skill | When |
|---|---|
| [frida-hooker](../frida-hooker/SKILL.md) | Hook crypto functions to capture keys at call time |
| [network-interceptor](../network-interceptor/SKILL.md) | Cross-reference memory tokens with network traffic |
| [electron-app-analyzer](../electron-app-analyzer/SKILL.md) | Find JS strings that match memory artifacts |
| [nuitka-decryptor](../nuitka-decryptor/SKILL.md) | Compare decrypted Nuitka blobs with memory dumps |

---

## Step 1 — Dump Process Memory

### Windows (comsvcs.dll — no extra tools needed)

```powershell
python scripts\dump_process.py --pid 1234 --out dumps\target.dmp
python scripts\dump_process.py --name "TargetApp.exe" --out dumps\target.dmp
```

### Windows (ProcDump — Sysinternals)

```powershell
python scripts\dump_process.py --pid 1234 --method procdump --out dumps\target.dmp
```

### Linux (/proc/mem)

```bash
python scripts/dump_process.py --pid 1234 --out dumps/target.dmp
python scripts/dump_process.py --name "target_app" --out dumps/target.dmp
```

Requires: elevated privileges (Administrator / root) for full memory access.

---

## Step 2 — Scan Memory Dump

```bash
python scripts/scan_memory.py dumps/target.dmp --out analysis/
```

```powershell
python scripts\scan_memory.py dumps\target.dmp --out analysis\
```

Detects:
- **License keys**: Common serial formats (XXXXX-XXXXX-...), base64 license blobs
- **API tokens**: Bearer tokens, JWT, API keys, OAuth tokens
- **Crypto keys**: AES/RSA key material, high-entropy blocks adjacent to crypto constants
- **URLs**: HTTP(S) endpoints, license server URLs
- **Strings**: UTF-8 and UTF-16 printable strings with context

Options:
- `--min-entropy 4.5` — Minimum Shannon entropy for key candidate blocks
- `--key-size 16,32` — Expected key sizes in bytes (AES-128, AES-256)
- `--cross-ref strings.txt` — Cross-reference with known strings from static analysis

---

## Step 3 — Cross-Reference with Static Analysis

Feed scan results back to other skills:

```bash
# Compare memory strings with Nuitka .rsrc constants
python scripts/scan_memory.py dumps/target.dmp --cross-ref nuitka_strings.txt --out xref/

# Compare with electron ASAR strings
python scripts/scan_memory.py dumps/target.dmp --cross-ref asar_strings.txt --out xref/
```

---

## Final Report (Vietnamese)

```
🧠 Phân tích memory dump hoàn tất:

  📦 Dump size        : <SIZE> MB
  🔤 Strings found    : <COUNT> (UTF-8: X, UTF-16: Y)
  🔑 License keys     : <COUNT>
  🎫 API tokens       : <COUNT>
  🔐 Crypto key cands : <COUNT>
  🌐 URLs found       : <COUNT>
  📊 Cross-ref matches: <COUNT>

  💾 Output: analysis/
```

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Dump without elevated privileges | Run as Administrator / root |
| Scan only UTF-8 strings | Always scan both UTF-8 and UTF-16LE |
| Ignore high-entropy blocks | Entropy analysis catches AES keys |
| Dump after app exits | Dump while app is running with license active |
| Skip cross-referencing | Compare memory strings with static analysis output |
| Use only one dump method | Try comsvcs.dll first, fallback to ProcDump or API |
