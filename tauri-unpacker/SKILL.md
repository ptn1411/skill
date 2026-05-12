---
name: tauri-unpacker
description: "Unpack Tauri desktop apps — extract embedded web assets (HTML/JS/CSS), Tauri config, IPC command map, and frontend license logic."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Tauri App Unpacker

## Purpose

Tauri apps embed a web frontend (HTML/JS/CSS) inside a native Rust binary.
The frontend often contains the license UI, API calls, and business logic
accessible without disassembly.  This skill extracts those embedded assets
and analyses the Tauri-specific IPC layer.

## Workflow

```
┌────────────────┐     ┌──────────────┐     ┌─────────────────────┐
│ tauri-app.exe  │────▶│ unpack_tauri │────▶│ tauri-unpacked/     │
└────────────────┘     └──────────────┘     │  ├─ assets/         │
                                            │  │  ├─ index.html   │
                                            │  │  ├─ main.js      │
                                            │  │  └─ style.css    │
                                            │  └─ tauri_config.json│
                                            └─────────────────────┘
                              │
                              ▼
                       ┌───────────────┐     ┌───────────────────┐
                       │ analyze_tauri │────▶│ tauri_analysis.json│
                       └───────────────┘     └───────────────────┘
```

## Usage

```bash
# Extract assets
python tauri-unpacker/scripts/unpack_tauri.py app.exe --out output/tauri-unpacked

# Analyze extracted frontend
python tauri-unpacker/scripts/analyze_tauri.py output/tauri-unpacked --out output/tauri-analysis

# Full pipeline
python tauri-unpacker/scripts/unpack_tauri.py app.exe --out output/tauri-unpacked && \
python tauri-unpacker/scripts/analyze_tauri.py output/tauri-unpacked --out output/tauri-analysis
```

## Outputs

| File | Content |
|------|---------|
| `assets/` | Extracted HTML, JS, CSS, images |
| `tauri_config.json` | Embedded Tauri configuration |
| `tauri_analysis.json` | IPC commands, event listeners, API endpoints, license logic |

## When to use

- `binary-identifier` or `rust-binary-analyzer` reports **Tauri** framework
- Target directory contains a Tauri app bundle
- `.exe` with embedded web assets (HTML/JS/CSS in binary data)

## Chain targets

After extraction, chain:
- `javascript-deobfuscator` → deobfuscate extracted JS
- `electron-app-analyzer` → reuse secret/endpoint scanning (works on any JS)

## Anti-patterns

| Mistake | Fix |
|---------|-----|
| Only analysing the Rust backend | Frontend JS often has license UI, API keys, validation |
| Skipping brotli decompression | Tauri compresses assets with brotli — must decompress |
| Ignoring IPC commands | `invoke()` calls reveal backend API surface |
| Missing Tauri config | Config has CSP, allowed APIs, window settings — security-relevant |
