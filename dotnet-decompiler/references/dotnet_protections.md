# .NET Protections & Obfuscators — Reference

## Detection Signatures

| Obfuscator | Detection Strings | Artifacts |
|-----------|-------------------|-----------|
| **ConfuserEx** | `ConfuserEx`, `Confuser.Core` | Unicode-renamed symbols, anti-tamper module in `<Module>.cctor`, string encryption via `Delegate.Invoke` |
| **.NET Reactor** | `.NET Reactor`, `Eziriz` | Native stub wrapping encrypted assembly, `_ProtectedModule` type |
| **Babel** | `Babel.Net`, `BabelObfuscator` | Metadata stream encryption, resource encryption |
| **SmartAssembly** | `SmartAssembly`, `{z2}` | String encoding tables, tamper detection, memory patching protection |
| **Dotfuscator** | `Dotfuscator`, `PreEmptive` | Renaming only (CE edition), shelf-life + tamper (Pro) |
| **Eazfuscator** | `Eazfuscator` | Virtualized IL (converts to custom VM bytecode), string encryption |
| **Crypto Obfuscator** | `CryptoObfuscator`, `LogicalTech` | Resource encryption, anti-debug, string encryption |

## Common Bypass Techniques

| Protection | Bypass |
|-----------|--------|
| String encryption | Find decryptor method → call it, or hook at runtime |
| Control flow | De4dot or manual deobfuscation |
| Anti-tamper | Patch `<Module>.cctor` to NOP anti-tamper init |
| Anti-debug | Patch `Debugger.IsAttached` check, hook `IsDebuggerPresent` |
| Resource encryption | Dump resources at runtime after decryption |
| Assembly packing | Run exe, dump decrypted assembly from memory |

## Tools

| Tool | Purpose |
|------|---------|
| **ilspycmd** | CLI decompiler: `dotnet tool install -g ilspycmd` |
| **dnSpyEx** | GUI decompiler + debugger (fork of original dnSpy) |
| **de4dot** | .NET deobfuscator (handles ConfuserEx, .NET Reactor, etc.) |
| **dotPeek** | JetBrains free decompiler |
| **AsmResolver** | .NET metadata library for programmatic analysis |

## .NET PE Detection

```
1. Check MZ header
2. Read e_lfanew → PE signature
3. Check Import Table for mscoree.dll
4. Or check Data Directory [14] (CLI header RVA > 0)
5. Find BSJB signature in metadata
6. Read metadata version string (e.g., "v4.0.30319")
```
