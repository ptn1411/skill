# Nuitka Constant Serialization Format — Reference

## Overview

Nuitka compiles Python source to C, but all Python **string constants** are serialized
into a binary blob stored in the PE `.rsrc` section (Windows) or an ELF section (Linux).
This includes: string literals, attribute names, module names, format strings, HTML/JS
templates, error messages, and more.

Understanding this format is key to reconstructing source code from compiled Nuitka binaries.

---

## PE Section Layout (Windows)

| Section | Contents | IDA Maps? |
|---------|----------|-----------|
| `.text` | Compiled C code (Nuitka runtime + translated Python) | Yes |
| `.rdata` | Read-only data, some Nuitka constants | Yes |
| `.data` | Mutable globals | Yes |
| `.rsrc` | **Main Nuitka constant blob** — all Python string constants | **NO** |

**Critical**: IDA Pro does NOT map `.rsrc` by default. All string searches via IDA
(`find`, `find_regex`, `find_bytes`) will return empty. Must read raw PE bytes.

---

## Serialization Prefix Bytes

Observed from analysis of Nuitka 1.x / 2.x compiled binaries:

| Prefix | Meaning | Format | Example |
|--------|---------|--------|---------|
| `u` (0x75) | Unicode string literal | `u` + length + UTF-8 bytes | `u\x0bhello world` |
| `a` (0x61) | Attribute/identifier name | `a` + length + ASCII bytes | `a\x04self` |
| `s` (0x73) | String reference (backreference) | `s` + index | refers to earlier string |
| `w` (0x77) | Variable reference | `w` + index | refers to a variable |
| `i` (0x69) | Integer constant | `i` + encoded int | small int |
| `f` (0x66) | Float constant | `f` + 8 bytes (IEEE 754) | |
| `n` (0x6E) | None | single byte | |
| `T` (0x54) | True | single byte | |
| `F` (0x46) | False | single byte | |
| `t` (0x74) | Tuple | `t` + count + elements | |
| `l` (0x6C) | List | `l` + count + elements | |
| `d` (0x64) | Dict | `d` + count + key/value pairs | |
| `b` (0x62) | Bytes literal | `b` + length + raw bytes | |

---

## Length Encoding

String lengths use a variable-length encoding:

```
If byte < 0x80:
    length = byte                        (0-127)
Else:
    length = ((byte & 0x7F) << 8) | next_byte   (128-32767)
```

For very long strings (>32767), a 4-byte encoding may be used:
```
If first two bytes both have high bit set:
    length = 4-byte big-endian integer
```

---

## String Order

Strings in the `.rsrc` blob appear roughly in **source code order**:
1. Module-level imports and constants first
2. Class definitions and method names
3. Function bodies in definition order
4. Nested function/lambda strings
5. Module `__main__` block last

This ordering is useful for reconstruction — strings near each other in the blob
likely belong to the same function or class.

---

## Nuitka Identifier Patterns

Nuitka mangles some names with prefixes:

| Pattern | Meaning |
|---------|---------|
| `$module_<name>` | Module-level code for `<name>.py` |
| `$function_<name>` | Function named `<name>` |
| `$class_<name>` | Class named `<name>` |
| `$generator_<name>` | Generator function |
| `$coroutine_<name>` | Async coroutine |
| `$lambda_<n>` | Lambda expression #n |
| `$comprehension_<n>` | List/dict/set comprehension #n |

---

## Detection Heuristics

### Confirming a binary is Nuitka-compiled

Look for these strings in `.rdata` or `.rsrc`:

```
__compiled__
__nuitka_version__
Nuitka
onefile_path
__compiled_constant_
```

### Identifying Python version

Look for strings matching: `cp3XX-win_amd64`, `cp3XX-win32`, `python3XX.dll`

Common: `cp310` (3.10), `cp311` (3.11), `cp312` (3.12)

---

## Extraction Strategy

### Method 1: Nuitka-aware parsing (preferred)
```python
# Walk the blob looking for u/a prefixes
i = 0
while i < len(blob):
    if blob[i] == ord('u') or blob[i] == ord('a'):
        length = blob[i+1]
        if length >= 0x80:
            length = ((length & 0x7F) << 8) | blob[i+2]
            i += 1
        string = blob[i+2:i+2+length].decode('utf-8')
        yield string
        i += 2 + length
    else:
        i += 1
```

### Method 2: Raw string regex (fallback)
```python
import re
# Find all printable ASCII sequences >= 4 chars
for m in re.finditer(rb'[\x20-\x7e]{4,}', blob):
    yield m.group().decode('ascii')
```

### Method 3: PowerShell one-liner (quick & dirty)
```powershell
$bytes = [IO.File]::ReadAllBytes("target.dll")
$rsrc_off = 0x131D000  # from PE header
$text = [Text.Encoding]::UTF8.GetString($bytes[$rsrc_off..($bytes.Length-1)])
$text -split '\x00+' | Where-Object { $_.Length -ge 4 } | Set-Content strings.txt
```

---

## Known Variations

| Nuitka Version | Notes |
|----------------|-------|
| 1.x | Simpler serialization, fewer prefix types |
| 2.x | Added more optimized constant storage |
| Onefile mode | Constants in the unpacked DLL, not the .exe wrapper |
| Standalone mode | Constants directly in the .pyd/.dll |
| Encrypted mode | XOR/Fernet layer on top — use `nuitka-decryptor` first |

---

## Cross-Reference with IDA MCP

When IDA Pro is available, use `py_eval` to find exact section offsets:

```python
# Via ida_mcp_analyze.py
import idautils, idc, ida_segment

for seg_ea in idautils.Segments():
    name = idc.get_segm_name(seg_ea)
    seg = ida_segment.getseg(seg_ea)
    print(f"{name}: VA={hex(seg.start_ea)} size={seg.size()}")
```

Then compare IDA's mapped segments with PE section table to identify unmapped regions.
