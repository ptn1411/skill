---
name: java-decompiler
description: "Decompile Java applications (JAR/WAR/APK/class) — extract archives, detect obfuscators, decompile bytecode to source, analyse license logic and secrets."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Java Decompiler

## Purpose

Java bytecode (.class) retains nearly all source-level information, making
decompilation highly effective.  This skill extracts, decompiles, and analyses
Java applications across all packaging formats: JAR, WAR, EAR, APK, and raw
class files.

## Workflow

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────────┐
│ target.jar / .apk│────▶│ decompile_java   │────▶│ java-decompiled/     │
└──────────────────┘     └──────────────────┘     │  ├─ src/             │
                                │                  │  ├─ manifest.json    │
                                │                  │  └─ obfuscation.json │
                                ▼                  └──────────────────────┘
                         ┌──────────────────┐     ┌──────────────────────┐
                         │  analyze_java    │────▶│ java_analysis.json   │
                         └──────────────────┘     └──────────────────────┘
```

## Usage

```bash
# Decompile a JAR
python java-decompiler/scripts/decompile_java.py app.jar --out output/java-decompiled

# Decompile an Android APK
python java-decompiler/scripts/decompile_java.py app.apk --out output/java-decompiled

# Decompile with specific tool
python java-decompiler/scripts/decompile_java.py app.jar --out output/java-decompiled --decompiler cfr

# Analyse decompiled source
python java-decompiler/scripts/analyze_java.py output/java-decompiled --out output/java-analysis
```

## Decompiler Priority

| Tool | Best for | Install |
|------|----------|---------|
| **CFR** | General JAR/class (best output quality) | Download cfr.jar |
| **Procyon** | Complex generics, lambdas | Download procyon-decompiler.jar |
| **FernFlower** | IntelliJ-style output | Download fernflower.jar |
| **JADX** | Android APK (dex → java directly) | `pip install jadx` or download |
| **javap** | Fallback bytecode listing | Included with JDK |

## Outputs

| File | Content |
|------|---------|
| `src/` | Decompiled .java source files |
| `manifest.json` | Parsed MANIFEST.MF + entry points |
| `obfuscation.json` | Detected obfuscator + evidence |
| `java_analysis.json` | License logic, secrets, endpoints, dependencies |

## When to use

- `binary-identifier` reports **Java** language
- Target is a `.jar`, `.war`, `.ear`, `.apk`, or `.class` file
- Target contains `META-INF/MANIFEST.MF` or `classes.dex`

## Anti-patterns

| Mistake | Fix |
|---------|-----|
| Using only one decompiler | CFR fails on some patterns → fallback to Procyon/FernFlower |
| Ignoring MANIFEST.MF | Contains Main-Class, classpath, version — always parse |
| Skipping obfuscator detection | Deobfuscate first (string decryption) for readable output |
| Treating APK as JAR | APK uses DEX bytecode — needs dex2jar or JADX, not cfr directly |
| Missing inner classes | Inner classes are separate .class files — decompile the whole JAR |
