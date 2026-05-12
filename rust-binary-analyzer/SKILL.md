---
name: rust-binary-analyzer
description: "Analyze Rust native binaries — demangle symbols, extract panic paths to reconstruct module map, detect frameworks (Tauri/Actix/Rocket/Axum), locate license validation logic."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Rust Binary Analyzer

## Purpose

Rust compiles to native code with no bytecode/IL to decompile, but leaves rich
metadata in the binary: mangled symbol names, panic strings with source paths,
and framework-specific signatures.  This skill extracts and organises that
metadata to give the reverse engineer a high-level map of the application
*before* opening IDA or Ghidra.

## Workflow

```
┌────────────┐     ┌──────────────┐     ┌───────────────────┐
│ target.exe │────▶│ analyze_rust │────▶│ rust_analysis.json │
└────────────┘     └──────────────┘     └───────────────────┘
                         │
                         ├─ Demangle symbols (_RN… / _ZN…)
                         ├─ Extract panic paths → module tree
                         ├─ Detect framework (Tauri, Actix, …)
                         ├─ Find license-related functions
                         └─ Identify linked crates
```

## Usage

```bash
python rust-binary-analyzer/scripts/analyze_rust.py target.exe --out output/rust-analysis
python rust-binary-analyzer/scripts/analyze_rust.py target.exe --json output/rust_info.json
```

## Outputs

| File | Content |
|------|---------|
| `rust_info.json` | Full analysis: symbols, panic paths, framework, license targets |
| `demangled_symbols.txt` | All demangled Rust symbols |
| `module_tree.txt` | Reconstructed source module hierarchy |
| `license_targets.txt` | Functions likely related to licensing |

## When to use

- `binary-identifier` reports **Rust** language
- Target contains `.rs:` panic strings or `_RN`/`_ZN` mangled symbols
- Tauri desktop app (chains into `tauri-unpacker`)

## Anti-patterns

| Mistake | Fix |
|---------|-----|
| Trying to decompile Rust to source | Rust → native; use IDA/Ghidra for code, this skill for metadata |
| Ignoring panic strings | Panic paths reveal the full source tree — always extract first |
| Skipping symbol demangling | Mangled names are unreadable; demangling reveals crate::module::function |
| Missing Tauri frontend | If framework=Tauri, chain `tauri-unpacker` to get the JS/HTML |
