'use strict';

// License Bypass — Hook common license validation functions and force true returns.
// Works on: native (Win32 API), .NET, Electron, Python-based apps.

console.log('[*] License bypass hooks loading...');

// --- Windows API hooks ---

const modules = Process.enumerateModules();
console.log('[*] Loaded modules: ' + modules.length);

// Hook common license-related exports by name pattern
const licensePatterns = [
    /license/i, /validate/i, /activate/i, /isregistered/i,
    /check_?license/i, /verify_?key/i, /is_?trial/i, /is_?expired/i,
    /is_?valid/i, /check_?subscription/i, /get_?license_?status/i,
];

let hookCount = 0;

for (const mod of modules) {
    try {
        const exports = mod.enumerateExports();
        for (const exp of exports) {
            if (exp.type !== 'function') continue;
            for (const pat of licensePatterns) {
                if (pat.test(exp.name)) {
                    try {
                        Interceptor.attach(exp.address, {
                            onEnter(args) {
                                console.log('[LICENSE] Called: ' + exp.name + ' @ ' + mod.name);
                            },
                            onLeave(retval) {
                                console.log('[LICENSE] ' + exp.name + ' original return: ' + retval);
                                retval.replace(ptr(1));
                                console.log('[LICENSE] ' + exp.name + ' patched return: 1 (true)');
                            }
                        });
                        hookCount++;
                        console.log('[+] Hooked: ' + mod.name + '!' + exp.name);
                    } catch (e) {
                        // Skip unhookable exports
                    }
                    break;
                }
            }
        }
    } catch (e) {
        // Module enumeration may fail for some system modules
    }
}

// --- .NET CLR hooks (if applicable) ---
try {
    const clr = Process.findModuleByName('clrjit.dll') || Process.findModuleByName('coreclr.dll');
    if (clr) {
        console.log('[*] .NET runtime detected, scanning for managed license methods...');
        // Hook at JIT level would require more complex instrumentation
        // For now, log detection for manual follow-up
    }
} catch (e) {}

// --- Registry check bypass (Windows) ---
try {
    const RegQueryValueExW = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
    if (RegQueryValueExW) {
        Interceptor.attach(RegQueryValueExW, {
            onEnter(args) {
                try {
                    const valueName = args[1].readUtf16String();
                    if (valueName && /license|serial|key|registered|trial/i.test(valueName)) {
                        console.log('[REG] RegQueryValueExW: ' + valueName);
                        this.isLicense = true;
                    }
                } catch (e) {}
            },
            onLeave(retval) {
                if (this.isLicense) {
                    console.log('[REG] License registry query returned: ' + retval);
                }
            }
        });
        hookCount++;
    }
} catch (e) {}

// --- Time/date check bypass ---
try {
    const GetSystemTime = Module.findExportByName('kernel32.dll', 'GetSystemTime');
    const GetLocalTime = Module.findExportByName('kernel32.dll', 'GetLocalTime');

    // Log time checks (may be used for trial expiry)
    if (GetSystemTime) {
        Interceptor.attach(GetSystemTime, {
            onEnter(args) {
                this.buf = args[0];
            },
            onLeave(retval) {
                // Log but don't modify — uncomment to freeze time
                // const year = this.buf.readU16();
                // console.log('[TIME] GetSystemTime year: ' + year);
            }
        });
    }
} catch (e) {}

console.log('[+] License bypass: ' + hookCount + ' hooks installed');

// CUSTOM_ADDRESSES
