---
name: frida-hooker
description: "Generate and inject Frida hooks for dynamic instrumentation — license bypass, SSL pinning bypass, function tracing, crypto interception, anti-debug bypass. Supports attach and spawn modes."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Frida Hooker

> Dynamic instrumentation via Frida — hook functions at runtime to bypass protections, trace execution, intercept crypto operations, and capture license validation logic.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

| Sibling skill | When |
|---|---|
| [memory-dumper](../memory-dumper/SKILL.md) | Dump memory after hooks capture decrypted data |
| [network-interceptor](../network-interceptor/SKILL.md) | Bypass SSL pinning before traffic capture |
| [ida-nuitka-reconstructor](../ida-nuitka-reconstructor/SKILL.md) | Get function addresses from IDA for targeted hooks |
| [binary-identifier](../binary-identifier/SKILL.md) | Identify target framework before choosing hook template |

---

## Step 1 — Generate Hooks

### From template (common scenarios)

```bash
python scripts/generate_hooks.py --template license_bypass --out hooks/bypass.js
python scripts/generate_hooks.py --template ssl_pinning_bypass --out hooks/ssl.js
python scripts/generate_hooks.py --template function_tracer --target-module "app.dll" --out hooks/trace.js
python scripts/generate_hooks.py --template crypto_intercept --out hooks/crypto.js
python scripts/generate_hooks.py --template anti_debug_bypass --out hooks/antidebug.js
```

### From IDA export (targeted hooks)

```bash
python scripts/generate_hooks.py --ida-export ida_functions.json --filter "license,validate,check" --out hooks/targeted.js
```

### Custom address hook

```bash
python scripts/generate_hooks.py --address 0x140001234 --module "target.exe" --out hooks/custom.js
```

---

## Step 2 — Inject and Run

### Attach to running process

```bash
python scripts/run_frida.py --attach "TargetApp.exe" --script hooks/bypass.js --out results/
```

### Spawn with hooks

```bash
python scripts/run_frida.py --spawn "C:\path\to\target.exe" --script hooks/bypass.js --out results/
```

### Multiple scripts

```bash
python scripts/run_frida.py --attach "TargetApp.exe" --script hooks/ssl.js hooks/trace.js --out results/
```

Requires: `pip install frida-tools`

---

## Available Templates

| Template | File | Purpose |
|----------|------|---------|
| `license_bypass` | `templates/license_bypass.js` | Hook license check functions, force return true |
| `ssl_pinning_bypass` | `templates/ssl_pinning_bypass.js` | Bypass SSL cert pinning (Android + Desktop) |
| `function_tracer` | `templates/function_tracer.js` | Trace function calls with args and return values |
| `crypto_intercept` | `templates/crypto_intercept.js` | Intercept AES/RSA operations, log keys and plaintext |
| `anti_debug_bypass` | `templates/anti_debug_bypass.js` | Bypass IsDebuggerPresent, NtQueryInformationProcess, etc. |

---

## Final Report (Vietnamese)

```
🎣 Frida hooking hoàn tất:

  🎯 Target           : <PROCESS_NAME> (PID: <PID>)
  📜 Scripts injected  : <COUNT>
  🪝 Hooks active      : <COUNT>
  📊 Events captured   : <COUNT>
  🔑 Secrets found     : <COUNT>

  💾 Output: results/
```

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Hook without knowing the target framework | Run binary-identifier first |
| Use generic hooks on obfuscated code | Get addresses from IDA or runtime enumeration |
| Ignore anti-Frida checks | Apply anti-debug bypass template first |
| Hook too many functions at once | Start with targeted hooks, expand gradually |
| Forget to handle exceptions in hooks | Always wrap hook body in try/catch |
| Spawn without `--pause` when needed | Use spawn+resume for early hooks |
