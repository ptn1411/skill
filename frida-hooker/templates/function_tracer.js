'use strict';

// Function Tracer — Trace function calls with arguments and return values.
// Configure TARGET_MODULE to trace a specific module's exports.

const TARGET = 'TARGET_MODULE'; // Replaced by generate_hooks.py --target-module
const MAX_DEPTH = 3;
const MAX_STR_LEN = 200;

console.log('[*] Function tracer loading for: ' + TARGET);

let traceDepth = 0;
let callCount = 0;

function indent() {
    return '  '.repeat(traceDepth);
}

function readArgSafe(arg) {
    if (arg.isNull()) return 'NULL';

    // Try as UTF-8 string
    try {
        const s = arg.readUtf8String();
        if (s && s.length > 0 && s.length < 1000) {
            return '"' + s.substring(0, MAX_STR_LEN) + '"';
        }
    } catch (e) {}

    // Try as UTF-16 string (Windows)
    try {
        const s = arg.readUtf16String();
        if (s && s.length > 0 && s.length < 1000) {
            return 'L"' + s.substring(0, MAX_STR_LEN) + '"';
        }
    } catch (e) {}

    // Try as pointer to readable memory
    try {
        const bytes = arg.readByteArray(16);
        if (bytes) {
            const arr = new Uint8Array(bytes);
            const hex = Array.from(arr).map(b => ('0' + b.toString(16)).slice(-2)).join(' ');
            return arg + ' [' + hex + ']';
        }
    } catch (e) {}

    return arg.toString();
}

function traceExport(mod, exp) {
    try {
        Interceptor.attach(exp.address, {
            onEnter(args) {
                if (traceDepth >= MAX_DEPTH) return;
                traceDepth++;
                callCount++;

                const argStr = [];
                for (let i = 0; i < 4; i++) {
                    try {
                        argStr.push('a' + i + '=' + readArgSafe(args[i]));
                    } catch (e) {
                        argStr.push('a' + i + '=?');
                    }
                }

                console.log(indent() + '[CALL #' + callCount + '] ' + exp.name + '(' + argStr.join(', ') + ')');
                this.entryDepth = traceDepth;
            },
            onLeave(retval) {
                if (this.entryDepth === undefined) return;
                console.log(indent() + '[RET] ' + exp.name + ' => ' + readArgSafe(retval));
                traceDepth = this.entryDepth - 1;
            }
        });
        return true;
    } catch (e) {
        return false;
    }
}

// Find and trace the target module
const targetMod = Process.findModuleByName(TARGET);
if (!targetMod) {
    console.log('[!] Module not found: ' + TARGET);
    console.log('[*] Available modules:');
    Process.enumerateModules().slice(0, 20).forEach(function(m) {
        console.log('    ' + m.name + ' @ ' + m.base);
    });
} else {
    console.log('[*] Found: ' + targetMod.name + ' @ ' + targetMod.base + ' (' + targetMod.size + ' bytes)');

    const exports = targetMod.enumerateExports();
    let hooked = 0;

    for (const exp of exports) {
        if (exp.type !== 'function') continue;
        if (traceExport(targetMod, exp)) {
            hooked++;
        }
    }

    console.log('[+] Tracing ' + hooked + ' / ' + exports.length + ' exports from ' + TARGET);
}

// Also trace any dynamically resolved functions
// CUSTOM_ADDRESSES

console.log('[+] Function tracer ready. Waiting for calls...');
