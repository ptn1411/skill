# Memory Forensics — Reference

## Dump Techniques

| Method | Platform | Privileges | Notes |
|--------|----------|-----------|-------|
| `comsvcs.dll` MiniDump | Windows | Admin | Built-in, no extra tools. `rundll32 comsvcs.dll, MiniDump <PID> <file> full` |
| `MiniDumpWriteDump` API | Windows | Admin | Direct Win32 API via ctypes. Most reliable. |
| ProcDump (Sysinternals) | Windows | Admin | `-ma` for full dump. Handles anti-debug better. |
| `/proc/<pid>/mem` | Linux | root | Read mapped regions from `/proc/<pid>/maps` |
| `gcore` | Linux | root | GDB core dump: `gcore -o dump <pid>` |
| `process_vm_readv` | Linux | root/ptrace | Syscall for reading remote process memory |

## Key Patterns in Memory

| Pattern | Regex / Signature | Context |
|---------|-------------------|---------|
| Serial key | `[A-Z0-9]{5}(-[A-Z0-9]{5}){3,}` | License activation |
| JWT | `eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+` | API auth |
| Bearer token | `Bearer [A-Za-z0-9\-._~+/]+=*` | HTTP auth header |
| AWS key | `AKIA[A-Z0-9]{16}` | AWS access key ID |
| Private key header | `-----BEGIN (RSA |EC )?PRIVATE KEY-----` | PEM-encoded key |
| AES S-box start | `63 7c 77 7b f2 6b 6f c5` | AES implementation |
| SHA-256 H0 | `6a 09 e6 67` (LE: `67 e6 09 6a`) | SHA-256 init vector |
| RSA public exp | `01 00 01` (65537) | RSA key structure |

## Entropy Analysis

| Entropy (bits/byte) | Interpretation |
|---------------------|----------------|
| 0.0 – 1.0 | Null/repeated bytes |
| 1.0 – 3.5 | Text (ASCII, UTF-8) |
| 3.5 – 5.0 | Structured data, code |
| 5.0 – 7.0 | Compressed data |
| 7.0 – 7.5 | Likely encrypted / crypto key |
| 7.5 – 8.0 | Random / strong encryption |

## Windows Memory Layout

| Region | Typical Address | Contains |
|--------|----------------|----------|
| Stack | `0x00000000'xxxxx000` | Local variables, return addresses |
| Heap | varies | Dynamic allocations — strings, objects |
| .data section | image base + offset | Global/static variables |
| .rdata section | image base + offset | Read-only strings, vtables |
| PEB/TEB | `0x7FFE0000` region | Process/thread environment blocks |

## Anti-Dump Countermeasures

| Technique | Description | Bypass |
|-----------|-------------|--------|
| `NtQueryInformationProcess` | Detects debugger/dump tool | Hook to return clean values |
| Header erasure | PE header zeroed at runtime | Dump before erasure or reconstruct |
| Guard pages | `PAGE_GUARD` on key regions | Suspend threads before dump |
| Encrypted heap | License data XORed in memory | Hook decrypt function, dump after |
| Timing checks | Detect paused execution | Use hardware breakpoints instead |

## Common Locations for Secrets

| Application Type | Where to Look |
|-----------------|---------------|
| Electron apps | V8 heap — search for JS string objects |
| .NET apps | CLR heap — managed string objects (UTF-16) |
| Python (Nuitka/PyInstaller) | PyObject allocations, interned strings |
| Native C/C++ | Stack frames near license check functions, .data/.bss |
| Java | JVM heap — String pool, char arrays |
