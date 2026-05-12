---
name: vm-and-bytecode-reverse
description: "Reverse engineer custom virtual machines and proprietary bytecode (dispatcher loops, opcode tables, VM protectors, .pyc/CIL/JVM/Lua bytecode). Activate when the binary is a thin native shell around an interpreter."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# VM & Bytecode Reverse Engineering

> **Upstream reference**: [yaklang/hack-skills/vm-and-bytecode-reverse](https://github.com/yaklang/hack-skills/tree/main/skills/vm-and-bytecode-reverse) — facts/tables distilled from ctf-wiki.
> Final user-facing summary in Vietnamese.

## 0. Authorization & routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

| Sibling skill | When |
|---|---|
| [binary-identifier](../binary-identifier/SKILL.md) | First — confirm whether you are looking at native code or VM-driven |
| [anti-debugging-techniques](../anti-debugging-techniques/SKILL.md) | Many commercial VMs ship anti-debug inside the dispatcher |
| [symbolic-execution-tools](../symbolic-execution-tools/SKILL.md) | Symbolically run handlers to recover constraints |
| [nuitka-decryptor](../nuitka-decryptor/SKILL.md) | Specifically for Nuitka-compiled Python (XOR+B64 layer over .pyd) |
| [javascript-deobfuscator](../javascript-deobfuscator/SKILL.md) | Custom JS VMs (jsvmp, obfuscator.io) |

## 1. Recognition signatures (in IDA / Ghidra / Binary Ninja)

| Pattern in disassembly | Dispatcher style | First move |
|---|---|---|
| `while(1) { switch(byte[pc++]) { case 0: ... } }` | switch-based | Enumerate cases → opcode table |
| Indirect call via `[table + idx*8]` | table-based (jump table) | Dump the table, label handlers |
| Long if/else chain on `op` | if-chain | Same as switch |
| `push`/`pop` dominate, single operand stream | stack VM | Map push/pop/arith opcodes first |
| `reg[k] = …` arithmetic on a small array | register VM | Determine reg count + width |
| `pc = code[pc]; goto *handlers[op]` | threaded code | One handler per opcode, ends with goto-next |

Signature of a VM in any binary: a **tight loop** containing one fetch (`opcode = mem[pc++]`), one decode (table or switch), and one set of small handlers reading from and writing to the same context structure.

## 2. Reconstructing the ISA

| Step | Action |
|---|---|
| 1 | Locate the dispatcher loop — it dominates execution time, easy to spot in a profiler / coverage trace |
| 2 | Identify the **VM context**: bytecode pointer, PC, stack/regs, memory area. Often a single struct |
| 3 | Walk every case/handler. Annotate operand widths (`pc++` once = 1 byte operand, four times = 32-bit) |
| 4 | Build an opcode table: `{ opcode → mnemonic, operand_layout, semantics }` |
| 5 | Write a **disassembler** that consumes the bytecode blob and prints mnemonics |
| 6 | (Optional) Write a **lifter** that emits semantically equivalent C / Python / LLVM IR per handler |
| 7 | (Optional) Re-host: emulate the VM in Python so you can fuzz, brute, symbolize |

## 3. Disassembler skeleton (Python, stack-VM example)

```python
# Generic single-byte-opcode + variable operand
OPCODES = {
    0x00: ('nop',  0),
    0x01: ('push', 4),     # push imm32
    0x02: ('pop',  0),
    0x03: ('add',  0),
    0x04: ('sub',  0),
    0x05: ('jz',   2),     # short branch
    0x06: ('call', 2),
    0xFF: ('halt', 0),
}

def disasm(blob: bytes, base: int = 0) -> list[str]:
    pc, out = 0, []
    while pc < len(blob):
        op = blob[pc]
        mnem, oplen = OPCODES.get(op, (f'db {op:#04x}', 0))
        operand = int.from_bytes(blob[pc+1:pc+1+oplen], 'little') if oplen else None
        out.append(f'{base+pc:08x}: {mnem}' + (f' {operand:#x}' if operand is not None else ''))
        pc += 1 + oplen
    return out
```

## 4. Common interpreter targets and their tooling

| Target | Format | Decompiler / disassembler | Notes |
|---|---|---|---|
| CPython | `.pyc` | `decompile3`, `uncompyle6` (≤3.8), `pycdc` (3.9+) | Magic header bytes encode version |
| PyInstaller | bundled `.pyc` | `pyinstxtractor` then `decompile3`/`pycdc` | `struct.tuple` header strip |
| Nuitka | native `.pyd`/`.exe` | none direct — use [nuitka-decryptor](../nuitka-decryptor/SKILL.md) for XOR-encrypted variants | Compiled to C, not classical bytecode |
| .NET | PE/CIL | `dnSpyEx`, `ilspy`, `dotPeek` | Strong decompilation; watch for `ConfuserEx` |
| JVM | `.class`/`.jar` | `cfr`, `procyon`, `jadx-cli` | Strings often obfuscated, control flow flattened |
| Android Dex | `classes.dex` | `jadx`, `apktool` | Smali for surgical patches |
| Lua 5.x | `.luac` | `luadec`, `unluac` | Header magic `\x1bLua` |
| WASM | `.wasm` | `wabt` (`wasm2wat`), `wasm-decompile` | Stack-VM with structured control flow |
| V8 snapshot | `.bin`/`.jsc` | `V8 ssa decompiler` (limited) | Largely opaque; usually reverse via tracing |
| EVM (Ethereum) | bytecode hex | `panoramix`, `heimdall-rs`, `ethervm.io` | Stack VM, 256-bit words |
| Custom CTF VM | proprietary | write your own (§3) | Most common |

## 5. VM protectors (commercial)

| Protector | What it does | Approach |
|---|---|---|
| **VMProtect** | Lifts hot blocks into a stack VM with randomized handler set per build | Match handler patterns across builds; `VMPDump` / `vmp-decompiler` recover handlers; trace with Intel PIN |
| **Themida** | Several VM "engines"; mixes with code mutation and anti-debug | Tools fragile per-version; usually trace + handler clustering |
| **Code Virtualizer** | Older Oreans VM | Similar approach to Themida |
| **VMware ThinApp / IonCube / SourceGuardian** | Domain-specific VMs around PHP/Python | Look for vendor-specific decoders first |

Heuristic: VM protectors push lots of context onto the stack at function entry (vctx), then the rest of the function is one giant unrolled dispatcher. Handler **count** is the fingerprint — collect 20-30 handlers and cluster by operand-pattern to map them to the abstract VM ISA.

## 6. Maze / interpreter-style CTF tricks

- 2D grid + step opcodes → extract the grid, run BFS/DFS for the shortest legal path.
- "Brainfuck-like" tape VMs: the input is the program; build a meta-disassembler around the tape opcodes.
- Crackme that hashes input through a VM: re-implement the VM in Python, then either brute-force per-byte if state is byte-local, or feed it to angr (see [symbolic-execution-tools](../symbolic-execution-tools/SKILL.md)).

## 7. Methodology

1. Confirm it really is a VM (single loop dominates, opcode-shaped switch/table).
2. Extract the **bytecode blob** (often a `.rodata` array, sometimes encrypted — decrypt first).
3. Walk every handler; build the opcode dictionary.
4. Implement a disassembler; sanity-check by disassembling a known block.
5. (If needed) implement an emulator for fuzzing/symbolic execution.
6. Hand off the recovered semantics to [binary-patcher](../binary-patcher/SKILL.md) (patch handler) or [symbolic-execution-tools](../symbolic-execution-tools/SKILL.md) (solve constraints).

## 8. Final report (Vietnamese)

```
🧠 VM/Bytecode RE hoàn tất:
  🏛️ Kiến trúc VM   : <stack | register | threaded | maze>
  📜 Số opcode     : <COUNT>
  📚 Bảng opcode   : opcodes.json (mnemonic, operand_layout, semantics)
  🛠️ Disassembler  : disasm.py — verify trên block test
  🧪 Emulator      : (tùy chọn) emu.py
  ▶ Tiếp           : symbolic-execution-tools (giải input) hoặc binary-patcher (vá handler)
```
