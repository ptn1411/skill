---
name: symbolic-execution-tools
description: "Symbolic execution and constraint solving with angr, Z3, Unicorn, and Qiling. Activate when license logic, crackmes, or VM input puzzles need automated path exploration and input synthesis."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Symbolic Execution Tools

> **Upstream reference**: [yaklang/hack-skills/symbolic-execution-tools](https://github.com/yaklang/hack-skills/tree/main/skills/symbolic-execution-tools).
> Final user-facing summary in Vietnamese.

## 0. Authorization & routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

| Sibling skill | When |
|---|---|
| [anti-debugging-techniques](../anti-debugging-techniques/SKILL.md) | Symbolically skip debugger checks instead of patching |
| [vm-and-bytecode-reverse](../vm-and-bytecode-reverse/SKILL.md) | Solve constraints inside a recovered VM ISA |
| [binary-protection-bypass](../binary-protection-bypass/SKILL.md) | Auto-discover leak primitives or compute ROP chains |
| [binary-patcher](../binary-patcher/SKILL.md) | Apply patches once correct branch / input is known |
| [writerpro-pentest](../writerpro-pentest/SKILL.md) | When license logic is amenable to constraint solving (e.g., HWID-derived check) |

## 1. Tool selection

| Use case | Pick | Reason |
|---|---|---|
| Pure equation / SAT-style problem | Z3 | Direct constraint solver, no binary needed |
| Single binary, modest path count | angr | Manages states + constraints; great `find=`/`avoid=` UX |
| High-speed CPU emulation, no symbolics | Unicorn | μs/instr, ideal for unpacking and tracing |
| Custom VM with native handlers | angr (control) + Unicorn (handler emu) | Combine path exploration with raw speed |
| OS / syscall / firmware aware | Qiling | Full-system emu with OS personalities |
| Industrial-scale concolic on real targets | Triton, KLEE | Dynamic taint + concolic; mature solvers |

## 2. angr — minimum viable script (crackme template)

```python
# pip install angr claripy
import angr, claripy

proj = angr.Project('./crackme', auto_load_libs=False)

# Symbolic input — 32 printable bytes
flag_len = 32
flag = claripy.BVS('flag', 8 * flag_len)

state = proj.factory.entry_state(
    args=['./crackme'],
    stdin=flag,
)
# Constrain to printable ASCII
for i in range(flag_len):
    b = flag.get_byte(i)
    state.solver.add(b >= 0x20, b <= 0x7e)

simgr = proj.factory.simgr(state)
simgr.explore(
    find=lambda s: b'Correct' in s.posix.dumps(1),     # stdout sentinel
    avoid=lambda s: b'Wrong'  in s.posix.dumps(1),
)
if simgr.found:
    sol = simgr.found[0].solver.eval(flag, cast_to=bytes)
    print('flag =', sol)
else:
    print('no solution')
```

## 3. State factories — when to use which

| Factory | Starts at | Good for |
|---|---|---|
| `entry_state()` | binary entry | Most CTF crackmes |
| `full_init_state()` | with libc init | When constructors matter |
| `blank_state(addr=…)` | arbitrary address | Skip unwanted setup; reach a check directly |
| `call_state(addr, *args)` | function with concrete args | Per-function analysis, e.g. just the validator |

## 4. Hooking & SimProcedures

```python
# Replace strcmp with a fast SimProcedure
import angr
proj.hook_symbol('strcmp', angr.SIM_PROCEDURES['libc']['strcmp']())

# Custom hook — return value forced to 0
@proj.hook(0x401234, length=5)        # length must equal patched insn bytes
def force_ok(state):
    state.regs.eax = 0
```

Use this to:
- skip anti-debug calls (`ptrace`, `IsDebuggerPresent`)
- model `scanf`, `printf`, `malloc` cleanly
- short-circuit slow / opaque loops

## 5. Path-explosion taming

| Symptom | Lever |
|---|---|
| Memory blowup at branchy loops | `simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=10))` |
| Stuck in libc functions | Hook them with SimProcedures (§4) |
| Too many parallel states | `LengthLimiter(max_length=2000)` or `DFS()` |
| Unhelpful states linger | `explore(num_find=1)`, then drop the rest |
| Mass irrelevant branches | Build a CFG, restrict simgr to addresses on the path to target |
| Each step very slow | Switch to Unicorn-engine backend: `state.options.add(angr.options.UNICORN)` |

## 6. Z3 — direct constraint examples

```python
# pip install z3-solver
from z3 import *

# Toy: find 8-byte input where xor(in, key) == out
key = bytes.fromhex('aabbccdd' * 2)
out = bytes.fromhex('11223344' * 2)

s = Solver()
inp = [BitVec(f'b{i}', 8) for i in range(8)]
for i in range(8):
    s.add(inp[i] ^ key[i] == out[i])
print(s.check(), [s.model()[b].as_long() for b in inp] if s.check() == sat else '-')
```

Use Z3 when the binary is already reduced to a system of equations (after VM lifting, or after a manual transcription of a small validator).

## 7. Unicorn for fast handler emulation

```python
# pip install unicorn capstone
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
mu = Uc(UC_ARCH_X86, UC_MODE_64)

CODE_BASE = 0x400000
mu.mem_map(CODE_BASE, 0x10000)
mu.mem_write(CODE_BASE, open('handler.bin','rb').read())

mu.reg_write(UC_X86_REG_RDI, 0x41424344)    # arg1
mu.emu_start(CODE_BASE, CODE_BASE + 0x80)
print(hex(mu.reg_read(UC_X86_REG_RAX)))
```

Pair with [vm-and-bytecode-reverse](../vm-and-bytecode-reverse/SKILL.md): each handler is a small native blob → emulate with Unicorn, drive PC manually.

## 8. Qiling — when you need syscall/OS awareness

```python
# pip install qiling
from qiling import Qiling
ql = Qiling(['./linux_x86_64_target'], rootfs='./rootfs/x8664_linux')
ql.os.set_api('ptrace', lambda *a, **k: 0)   # hide debugger
ql.run()
```

Good for malware/firmware where OS calls matter and you don't want to keep porting symbolic stubs.

## 9. Methodology

1. Identify the target check function (string ref to "Wrong"/"Correct"; license error message; etc.).
2. Decide where to start: `entry_state` is safest; `call_state(check_func, …)` when you trust the rest.
3. Symbolize only what needs to be: keep concretes for everything else.
4. Stub expensive externals; cap loops; pin to relevant addresses.
5. `explore(find=, avoid=)`; verify the recovered input on the real binary.
6. Hand off the discovered branch / value to [binary-patcher](../binary-patcher/SKILL.md) for permanent patch, or to [writerpro-pentest](../writerpro-pentest/SKILL.md) for keygen synthesis.

## 10. Anti-patterns

| ❌ | ✅ |
|---|---|
| Run `simgr.explore()` with no bounds | Always set `find=` and `avoid=`, plus loop/length limiters |
| Symbolize the whole address space | Only the bytes that drive the decision |
| Trust default libc model on every call | Hook `scanf`/`printf`/`malloc` with SimProcedures |
| Re-run from `entry_state` for each tweak | Cache `proj`/CFG; reuse `blank_state(addr=…)` |

## 11. Final report (Vietnamese)

```
🧮 Symbolic execution hoàn tất:
  🛠️ Công cụ      : <angr | Z3 | Unicorn | Qiling | combo>
  🎯 Hàm mục tiêu : <addr / symbol>
  🔣 Input solved : <bytes hoặc số>
  ⏱️ Thời gian    : <s>
  📂 Script       : solve.py

▶  Tiếp:
   binary-patcher (vá vĩnh viễn) hoặc writerpro-pentest (sinh keygen từ ràng buộc).
```
