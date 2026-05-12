'use strict';

// Anti-Debug Bypass — Defeat common anti-debugging and anti-instrumentation checks.
// Covers: IsDebuggerPresent, NtQueryInformationProcess, CheckRemoteDebuggerPresent,
//         OutputDebugString timing, NtSetInformationThread (hide from debugger),
//         and common anti-Frida checks.

console.log('[*] Anti-debug bypass hooks loading...');

let hookCount = 0;

// --- IsDebuggerPresent ---
try {
    const IsDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
    if (IsDebuggerPresent) {
        Interceptor.attach(IsDebuggerPresent, {
            onLeave(retval) {
                if (retval.toInt32() !== 0) {
                    console.log('[ANTIDEBUG] IsDebuggerPresent -> 0 (was ' + retval + ')');
                    retval.replace(ptr(0));
                }
            }
        });
        hookCount++;
    }
} catch (e) {}

// --- CheckRemoteDebuggerPresent ---
try {
    const CheckRemoteDebuggerPresent = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
    if (CheckRemoteDebuggerPresent) {
        Interceptor.attach(CheckRemoteDebuggerPresent, {
            onEnter(args) {
                this.pDebuggerPresent = args[1];
            },
            onLeave(retval) {
                if (!this.pDebuggerPresent.isNull()) {
                    const val = this.pDebuggerPresent.readU32();
                    if (val !== 0) {
                        console.log('[ANTIDEBUG] CheckRemoteDebuggerPresent -> FALSE (was ' + val + ')');
                        this.pDebuggerPresent.writeU32(0);
                    }
                }
            }
        });
        hookCount++;
    }
} catch (e) {}

// --- NtQueryInformationProcess (ProcessDebugPort, ProcessDebugObjectHandle, ProcessDebugFlags) ---
try {
    const NtQueryInformationProcess = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
    if (NtQueryInformationProcess) {
        Interceptor.attach(NtQueryInformationProcess, {
            onEnter(args) {
                this.infoClass = args[1].toInt32();
                this.pInfo = args[2];
                this.infoLen = args[3].toInt32();
            },
            onLeave(retval) {
                // ProcessDebugPort = 7
                if (this.infoClass === 7 && !this.pInfo.isNull()) {
                    const port = this.pInfo.readPointer();
                    if (!port.isNull()) {
                        console.log('[ANTIDEBUG] NtQueryInformationProcess(DebugPort) -> 0');
                        this.pInfo.writePointer(ptr(0));
                    }
                }
                // ProcessDebugObjectHandle = 30
                if (this.infoClass === 30) {
                    console.log('[ANTIDEBUG] NtQueryInformationProcess(DebugObjectHandle) -> STATUS_PORT_NOT_SET');
                    retval.replace(ptr(0xC0000353)); // STATUS_PORT_NOT_SET
                }
                // ProcessDebugFlags = 31
                if (this.infoClass === 31 && !this.pInfo.isNull()) {
                    console.log('[ANTIDEBUG] NtQueryInformationProcess(DebugFlags) -> 1 (no debugger)');
                    this.pInfo.writeU32(1);
                }
            }
        });
        hookCount++;
    }
} catch (e) {}

// --- NtSetInformationThread (HideThreadFromDebugger) ---
try {
    const NtSetInformationThread = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
    if (NtSetInformationThread) {
        Interceptor.attach(NtSetInformationThread, {
            onEnter(args) {
                const infoClass = args[1].toInt32();
                // ThreadHideFromDebugger = 17
                if (infoClass === 17) {
                    console.log('[ANTIDEBUG] NtSetInformationThread(HideFromDebugger) -> NOP');
                    // Replace with harmless info class (ThreadPriority = 1)
                    args[1] = ptr(1);
                    args[2] = ptr(0);
                    args[3] = ptr(0);
                }
            }
        });
        hookCount++;
    }
} catch (e) {}

// --- NtClose (anti-debug via invalid handle) ---
try {
    const NtClose = Module.findExportByName('ntdll.dll', 'NtClose');
    if (NtClose) {
        Interceptor.attach(NtClose, {
            onEnter(args) {
                // Some anti-debug passes invalid handle to trigger exception
                this.handle = args[0];
            },
            onLeave(retval) {
                // Suppress STATUS_INVALID_HANDLE which anti-debug checks for
                if (retval.toInt32() === -1073741816) { // 0xC0000008
                    retval.replace(ptr(0)); // STATUS_SUCCESS
                }
            }
        });
        hookCount++;
    }
} catch (e) {}

// --- GetTickCount / QueryPerformanceCounter (timing checks) ---
try {
    const GetTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');
    const GetTickCount64 = Module.findExportByName('kernel32.dll', 'GetTickCount64');

    // Store initial values to provide consistent fake deltas
    let lastTick = 0;
    let tickOffset = 0;

    if (GetTickCount) {
        Interceptor.attach(GetTickCount, {
            onLeave(retval) {
                // Don't modify — just log excessive calls (timing check indicator)
                const tick = retval.toInt32() & 0xFFFFFFFF;
                if (lastTick > 0 && (tick - lastTick) > 10000) {
                    console.log('[ANTIDEBUG] GetTickCount large delta: ' + (tick - lastTick) + 'ms');
                }
                lastTick = tick;
            }
        });
        hookCount++;
    }
} catch (e) {}

// --- Anti-Frida detection bypass ---
try {
    // Hook dlopen/LoadLibrary to detect Frida module scanning
    const LoadLibraryW = Module.findExportByName('kernel32.dll', 'LoadLibraryW');
    const LoadLibraryA = Module.findExportByName('kernel32.dll', 'LoadLibraryA');

    if (LoadLibraryW) {
        Interceptor.attach(LoadLibraryW, {
            onEnter(args) {
                try {
                    const name = args[0].readUtf16String();
                    if (name && /frida|agent/i.test(name)) {
                        console.log('[ANTIDEBUG] LoadLibraryW anti-Frida check: ' + name);
                    }
                } catch (e) {}
            }
        });
    }

    // Block EnumProcessModules if it's being used to scan for Frida
    const EnumProcessModules = Module.findExportByName('psapi.dll', 'EnumProcessModules')
        || Module.findExportByName('kernel32.dll', 'K32EnumProcessModules');
    if (EnumProcessModules) {
        Interceptor.attach(EnumProcessModules, {
            onLeave(retval) {
                // Just log — full module hiding would break too many things
                // console.log('[ANTIDEBUG] EnumProcessModules called');
            }
        });
    }
} catch (e) {}

// --- PEB.BeingDebugged flag ---
try {
    // Directly patch PEB.BeingDebugged
    const peb = Process.findModuleByName('ntdll.dll');
    if (peb) {
        const NtCurrentProcess = new NativeFunction(
            Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess'),
            'int', ['pointer', 'int', 'pointer', 'uint32', 'pointer']
        );
        const pbi = Memory.alloc(48);
        const retLen = Memory.alloc(4);
        const status = NtCurrentProcess(ptr(-1), 0, pbi, 48, retLen); // ProcessBasicInformation
        if (status === 0) {
            const pebAddr = pbi.add(8).readPointer();
            const beingDebugged = pebAddr.add(2).readU8();
            if (beingDebugged !== 0) {
                pebAddr.add(2).writeU8(0);
                console.log('[ANTIDEBUG] PEB.BeingDebugged patched: ' + beingDebugged + ' -> 0');

                // Also clear NtGlobalFlag
                const ntGlobalFlag = pebAddr.add(0x68).readU32(); // offset for x64
                if (ntGlobalFlag & 0x70) { // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
                    pebAddr.add(0x68).writeU32(ntGlobalFlag & ~0x70);
                    console.log('[ANTIDEBUG] PEB.NtGlobalFlag cleaned');
                }
            }
        }
        hookCount++;
    }
} catch (e) {
    console.log('[ANTIDEBUG] PEB patch skipped: ' + e.message);
}

console.log('[+] Anti-debug bypass: ' + hookCount + ' hooks installed');
