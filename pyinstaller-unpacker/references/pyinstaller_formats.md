# PyInstaller Archive Formats — Reference

## CArchive Structure (Onefile)

```
┌──────────────────────┐
│   Native bootloader  │  PE/ELF executable
├──────────────────────┤
│   Embedded files     │  zlib-compressed entries
│   (TOC entries)      │
├──────────────────────┤
│   Cookie (24-88 B)   │  Archive metadata
├──────────────────────┤
│   MEI Magic (8 B)    │  b'MEI\x0c\x0b\x0a\x0b\x0e'
└──────────────────────┘
```

## Cookie Format

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | magic | MEI magic bytes |
| 8 | 4 | pkg_len | Total package length |
| 12 | 4 | toc_offset | TOC offset from archive start |
| 16 | 4 | toc_len | TOC length in bytes |
| 20 | 4 | py_ver | Python version (e.g., 310 = 3.10) |

## TOC Entry Format

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | entry_len |
| 4 | 1 | compress_type |
| 5 | 4 | data_len |
| 9 | 4 | uncomp_len |
| 13 | 1 | compress_flag (0=raw, 1=zlib) |
| 14 | 1 | typecode |
| 18 | var | name (null-terminated) |

## Typecodes

| Code | Char | Meaning |
|------|------|---------|
| 115 | s | SCRIPT (entry point .pyc) |
| 109 | m | PYMODULE (.pyc) |
| 77 | M | PYPACKAGE (__init__.pyc) |
| 98 | b | BINARY (.dll/.so/.pyd) |
| 122 | z | PYZ (archive of all imports) |
| 90 | Z | ZIPFILE |
| 120 | x | DATA |
| 100 | d | DEPENDENCY |
| 110 | n | SPLASH |

## .pyc Magic Numbers

| Python | Magic (hex) | Magic (bytes) |
|--------|------------|---------------|
| 3.6 | 0x0D33 | `\x33\x0D\x0D\x0A` |
| 3.7 | 0x0D42 | `\x42\x0D\x0D\x0A` |
| 3.8 | 0x0D55 | `\x55\x0D\x0D\x0A` |
| 3.9 | 0x0D61 | `\x61\x0D\x0D\x0A` |
| 3.10 | 0x0D6F | `\x6F\x0D\x0D\x0A` |
| 3.11 | 0x0DA7 | `\xA7\x0D\x0D\x0A` |
| 3.12 | 0x0DCB | `\xCB\x0D\x0D\x0A` |
| 3.13 | 0x0DF7 | `\xF7\x0D\x0D\x0A` |

## .pyc Header (Python 3.7+)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | magic number |
| 4 | 4 | bit field (flags) |
| 8 | 4 | timestamp or hash |
| 12 | 4 | source size |
| 16+ | var | marshalled code object |

**PyInstaller strips this 16-byte header.** Must restore before decompilation.

## PYZ Archive

The PYZ entry contains a zipfile-like archive of all imported .pyc modules.
Structure: marshal'd dict mapping `module_name → (typecode, compressed_data)`

To extract: `marshal.loads(pyz_data[4:])` (skip 4-byte PYZ magic).

## Onedir Layout

```
app_name/
├── app_name.exe          # Bootloader
├── _internal/
│   ├── python3XX.dll     # Python runtime
│   ├── base_library.zip  # Stdlib .pyc modules
│   ├── *.pyc             # App modules
│   ├── *.pyd             # Native extensions
│   └── *.dll             # Dependencies
```
