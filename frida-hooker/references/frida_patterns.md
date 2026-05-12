# Frida Patterns — Reference

## Hook Targets by Application Type

| App Type | Key Functions to Hook | Why |
|----------|----------------------|-----|
| **Native (C/C++)** | License check functions, `strcmp`, `memcmp`, crypto APIs | Direct validation logic |
| **.NET** | `Assembly.Load`, JIT compile callbacks, `String.Compare` | Managed code interception |
| **Electron** | `eval`, `require`, `fs.readFileSync`, IPC handlers | JS runtime access |
| **Python (Nuitka)** | `PyObject_Call`, `PyUnicode_FromString`, import hooks | CPython API level |
| **PyInstaller** | `marshal.loads`, `importlib._bootstrap` | Module loading |
| **Java** | `ClassLoader.loadClass`, `Method.invoke` | Reflection-based bypass |

## Frida Attach Modes

| Mode | Command | Use Case |
|------|---------|----------|
| Attach by name | `frida -n "app.exe" -l script.js` | Running process |
| Attach by PID | `frida -p 1234 -l script.js` | Specific instance |
| Spawn | `frida -f "C:\app.exe" -l script.js` | Hook from start |
| Spawn + pause | `frida -f "C:\app.exe" -l script.js --pause` | Manual resume after hooks |

## Common Interceptor Patterns

### Replace return value
```javascript
Interceptor.attach(target, {
    onLeave(retval) {
        retval.replace(ptr(1)); // Force true
    }
});
```

### Modify argument
```javascript
Interceptor.attach(target, {
    onEnter(args) {
        args[0] = ptr(0); // Change first arg
    }
});
```

### Read string argument
```javascript
Interceptor.attach(target, {
    onEnter(args) {
        console.log(args[0].readUtf8String());   // UTF-8
        console.log(args[0].readUtf16String());  // UTF-16 (Windows)
    }
});
```

### Replace function entirely
```javascript
Interceptor.replace(target, new NativeCallback(function(arg0, arg1) {
    console.log('Called with: ' + arg0 + ', ' + arg1);
    return 1; // Always return success
}, 'int', ['pointer', 'pointer']));
```

### Enumerate and filter exports
```javascript
const mod = Process.findModuleByName('target.dll');
mod.enumerateExports().filter(e =>
    e.type === 'function' && /license/i.test(e.name)
).forEach(e => {
    Interceptor.attach(e.address, { ... });
});
```

## Anti-Frida Countermeasures

| Check | How It Works | Bypass |
|-------|-------------|--------|
| Module enumeration | Scan loaded modules for `frida-agent` | Rename agent or hook `EnumProcessModules` |
| Thread scanning | Look for Frida's GUM threads | Hook `NtQuerySystemInformation` |
| Port scanning | Check for Frida server on 27042 | Use `--listen` on non-default port |
| Inline hook detection | Scan function prologues for `jmp` patches | Use `Stalker` instead of `Interceptor` |
| Symbol resolution | Call `dlsym` for Frida symbols | Hook `dlsym` to hide Frida exports |
| Timing checks | Measure hook overhead | Minimize hook logic, cache results |
| Integrity checks | Hash code sections at runtime | Hook the hash comparison |

## Stalker (Code Tracing)

For apps with anti-hook detection, use Stalker instead of Interceptor:

```javascript
const tid = Process.getCurrentThreadId();
Stalker.follow(tid, {
    events: { call: true, ret: true },
    onCallSummary(summary) {
        for (const [addr, count] of Object.entries(summary)) {
            const sym = DebugSymbol.fromAddress(ptr(addr));
            if (sym.name) console.log(sym.name + ': ' + count + ' calls');
        }
    }
});
```

## Memory Scanning

```javascript
// Find a specific byte pattern in memory
const pattern = '48 89 5C 24 ?? 48 89 74 24 ?? 57';
Process.enumerateRanges('r--').forEach(range => {
    Memory.scan(range.base, range.size, pattern, {
        onMatch(address, size) {
            console.log('[FOUND] ' + address);
        },
        onComplete() {}
    });
});
```

## Key Frida APIs

| API | Purpose |
|-----|---------|
| `Interceptor.attach()` | Hook function entry/exit |
| `Interceptor.replace()` | Replace function entirely |
| `Stalker.follow()` | Trace code execution (no patching) |
| `Memory.scan()` | Search memory for byte patterns |
| `Module.findExportByName()` | Resolve export address |
| `Process.enumerateModules()` | List loaded modules |
| `Process.enumerateRanges()` | List memory regions |
| `DebugSymbol.fromAddress()` | Resolve address to symbol |
| `NativeFunction()` | Call native function from JS |
| `NativeCallback()` | Create native callback from JS |
