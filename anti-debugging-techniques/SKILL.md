---
name: anti-debugging-techniques
description: "Anti-debug detection and bypass for protected binaries. Activate before patching commercial apps that use ptrace/PEB/timing/exception checks on Linux or Windows."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Anti-Debugging Techniques

> **Upstream reference**: [yaklang/hack-skills/anti-debugging-techniques](https://github.com/yaklang/hack-skills/tree/main/skills/anti-debugging-techniques) — distilled from ctf-wiki + hacktricks. Use that page for full prose.
> **Language rule**: instructions in English; final user-facing summary in Vietnamese.

## 0. Authorization & routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2 (owner-attested target, granted technical authority).

**Run this skill before [binary-patcher](../binary-patcher/SKILL.md)** on any commercial-grade binary — patches misfire when anti-debug watchdogs are still live.

| Sibling skill | When |
|---|---|
| [binary-identifier](../binary-identifier/SKILL.md) | First — fingerprint protector (VMProtect/Themida ship known anti-debug stacks) |
| [binary-protection-bypass](../binary-protection-bypass/SKILL.md) | After — ASLR/PIE/canary still blocks patch even if debugger is hidden |
| [vm-and-bytecode-reverse](../vm-and-bytecode-reverse/SKILL.md) | When the check is implemented inside a custom VM dispatcher |
| [symbolic-execution-tools](../symbolic-execution-tools/SKILL.md) | Skip checks symbolically with angr instead of patching |

## 1. Detection-class → first-line bypass

| Class | Linux primary | Windows primary |
|---|---|---|
| API call | `LD_PRELOAD` shim returning 0 | Hook `IsDebuggerPresent` / `NtQueryInformationProcess` |
| Process flag | Filter `TracerPid` in `/proc/self/status` | Zero PEB `BeingDebugged` / `NtGlobalFlag` / heap flags |
| Timing | Frida hook on `clock_gettime` | Frida hook on `rdtsc` / `QueryPerformanceCounter` |
| Signal / exception | GDB `handle SIGTRAP nostop pass` | VEH handler or ScyllaHide |
| HW breakpoint | n/a | Hook `GetThreadContext` to clear DR0–DR3 |
| Multi-process watchdog | GDB `set follow-fork-mode child` | Attach to both processes |

## 2. Linux check signatures (grep-able)

```text
ptrace(           # PTRACE_TRACEME self-attach
fopen("/proc/self/status"      # TracerPid scan
fopen("/proc/self/maps"        # Frida/LD_PRELOAD scan
rdtsc                          # timing measurement
signal(SIGTRAP                 # signal-swallowed test
fork()                         # potential watchdog parent/child
```

## 3. Windows PEB + Nt* offsets (x64)

| Field | Location | Debugged | Clean |
|---|---|---|---|
| `BeingDebugged` | `PEB+0x02` | `1` | `0` |
| `NtGlobalFlag` | `PEB+0xBC` | `0x70` | `0` |
| `ProcessHeap.Flags` | `Heap+0x40` | `0x40000062` | `0x00000002` |
| `ProcessHeap.ForceFlags` | `Heap+0x44` | `0x40000060` | `0` |

`NtQueryInformationProcess` info-class IDs: `ProcessDebugPort=0x07`, `ProcessDebugObjectHandle=0x1E`, `ProcessDebugFlags=0x1F` (returns 0 when debugged — inverted).

## 4. Tooling matrix

| Tool | Platform | Use |
|---|---|---|
| ScyllaHide | Windows (x64dbg/IDA plugin) | One-click PEB/Nt*/timing patch |
| TitanHide | Windows kernel driver | Kernel-level hide for DR/heap checks |
| Frida | Cross-platform | Script hooks, timing spoof |
| LD_PRELOAD | Linux | ptrace/getenv/fopen replacement |
| GDB | Linux | `catch syscall`, conditional BP, register fixup |
| Qiling | Cross-platform | Full emulation — bypasses HW-level checks |

## 5. Functional bypass snippets

### Linux ptrace shim

```bash
# bash / WSL
cat > /tmp/ap.c <<'EOF'
long ptrace(int r, int p, void *a, void *d) { return 0; }
EOF
gcc -shared -fPIC -o /tmp/ap.so /tmp/ap.c
LD_PRELOAD=/tmp/ap.so ./target
```

### GDB catch-and-clear

```text
(gdb) catch syscall ptrace
(gdb) commands
> set $rax = 0
> continue
> end
```

### Frida cross-platform

```javascript
// Linux ptrace
Interceptor.replace(
  Module.getExportByName(null, 'ptrace'),
  new NativeCallback(() => 0, 'long', ['int', 'int', 'pointer', 'pointer'])
);
// Windows IsDebuggerPresent
Interceptor.replace(
  Module.getExportByName('kernel32.dll', 'IsDebuggerPresent'),
  new NativeCallback(() => 0, 'int', [])
);
```

### x64dbg + ScyllaHide (PowerShell launch)

```powershell
& 'C:\Tools\x64dbg\x64\x64dbg.exe' 'C:\Program Files\MyApp\target.exe'
# In GUI: Plugins → ScyllaHide → Options →
#   PEB BeingDebugged, NtGlobalFlag, HeapFlags
#   NtQueryInformationProcess (all classes)
#   NtSetInformationThread (HideFromDebugger)
#   GetTickCount, QueryPerformanceCounter
# → Apply → restart session
```

## 6. Bypass methodology

1. **Static scan** — grep the strings/imports above; map every check site.
2. **Classify** each hit into the table in §1.
3. **Apply layered bypass** — start with ScyllaHide (Win) or LD_PRELOAD shim (Linux); they cover ~80% of common checks.
4. **Handle TLS callbacks** before `main` runs (x64dbg "Break on TLS" / WinDbg `sxe ld`).
5. **Verify** — set BP on `ExitProcess`/`exit`/`_exit`; if hit unexpectedly, a check was missed → trace back.

## 7. Real-world protector defaults

| Protector | Stack | Recommended kit |
|---|---|---|
| VMProtect | PEB + timing + driver | TitanHide + ScyllaHide |
| Themida | PEB + SEH + timing | ScyllaHide + manual NOP |
| Enigma | IsDebuggerPresent + CRC | x64dbg + ScyllaHide |
| UPX (custom) | Usually none | Standard unpack |

## 8. Final report (Vietnamese)

```
🛡️ Bypass Anti-Debug hoàn tất:
  🔍 Phát hiện     : <DETECTION_TYPES>
  🛠️ Bypass        : <METHODS>
  🧰 Công cụ        : <ScyllaHide | Frida | LD_PRELOAD | GDB>
  ✅ Verify        : chạy không exit sớm dưới debugger

▶  Tiếp:
   binary-protection-bypass (nếu ASLR/PIE chặn patch)
   → binary-patcher (vá license check)
```
