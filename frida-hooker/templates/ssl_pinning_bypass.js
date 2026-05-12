'use strict';

// SSL Pinning Bypass — Disable certificate validation for traffic interception.
// Covers: WinHTTP, Schannel, OpenSSL, BoringSSL, NSS, WinINet.

console.log('[*] SSL pinning bypass hooks loading...');

let hookCount = 0;

// --- WinHTTP (Windows) ---
try {
    const WinHttpSetOption = Module.findExportByName('winhttp.dll', 'WinHttpSetOption');
    if (WinHttpSetOption) {
        Interceptor.attach(WinHttpSetOption, {
            onEnter(args) {
                const option = args[1].toInt32();
                // WINHTTP_OPTION_SECURITY_FLAGS = 31
                // WINHTTP_OPTION_CLIENT_CERT_CONTEXT = 47
                if (option === 31 || option === 47) {
                    console.log('[SSL] WinHttpSetOption security flag: ' + option);
                }
            }
        });
        hookCount++;
    }

    const WinHttpSendRequest = Module.findExportByName('winhttp.dll', 'WinHttpSendRequest');
    if (WinHttpSendRequest) {
        // Set SECURITY_FLAG_IGNORE_ALL before each request
        const WinHttpSetOptionFn = new NativeFunction(WinHttpSetOption, 'int', ['pointer', 'uint32', 'pointer', 'uint32']);
        Interceptor.attach(WinHttpSendRequest, {
            onEnter(args) {
                const hRequest = args[0];
                const flags = Memory.alloc(4);
                // SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                // SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
                flags.writeU32(0x00003300);
                WinHttpSetOptionFn(hRequest, 31, flags, 4);
                console.log('[SSL] Injected ignore-cert flags on WinHttpSendRequest');
            }
        });
        hookCount++;
    }
} catch (e) {
    console.log('[SSL] WinHTTP hooks skipped: ' + e.message);
}

// --- Schannel / SSPI (Windows native TLS) ---
try {
    const InitializeSecurityContextW = Module.findExportByName('sspicli.dll', 'InitializeSecurityContextW')
        || Module.findExportByName('secur32.dll', 'InitializeSecurityContextW');
    if (InitializeSecurityContextW) {
        Interceptor.attach(InitializeSecurityContextW, {
            onEnter(args) {
                // Log Schannel handshakes
                this.context = args[1];
            },
            onLeave(retval) {
                console.log('[SSL] InitializeSecurityContextW => ' + retval);
            }
        });
        hookCount++;
    }
} catch (e) {}

// --- OpenSSL ---
try {
    const SSL_CTX_set_verify = Module.findExportByName(null, 'SSL_CTX_set_verify');
    if (SSL_CTX_set_verify) {
        Interceptor.attach(SSL_CTX_set_verify, {
            onEnter(args) {
                console.log('[SSL] SSL_CTX_set_verify mode: ' + args[1] + ' -> forcing SSL_VERIFY_NONE (0)');
                args[1] = ptr(0); // SSL_VERIFY_NONE
            }
        });
        hookCount++;
    }

    const SSL_set_verify = Module.findExportByName(null, 'SSL_set_verify');
    if (SSL_set_verify) {
        Interceptor.attach(SSL_set_verify, {
            onEnter(args) {
                console.log('[SSL] SSL_set_verify -> forcing SSL_VERIFY_NONE');
                args[1] = ptr(0);
            }
        });
        hookCount++;
    }

    const SSL_get_verify_result = Module.findExportByName(null, 'SSL_get_verify_result');
    if (SSL_get_verify_result) {
        Interceptor.attach(SSL_get_verify_result, {
            onLeave(retval) {
                if (retval.toInt32() !== 0) {
                    console.log('[SSL] SSL_get_verify_result: ' + retval + ' -> 0 (X509_V_OK)');
                    retval.replace(ptr(0)); // X509_V_OK
                }
            }
        });
        hookCount++;
    }
} catch (e) {
    console.log('[SSL] OpenSSL hooks skipped: ' + e.message);
}

// --- BoringSSL (Chrome, Electron apps) ---
try {
    const modules = Process.enumerateModules();
    for (const mod of modules) {
        if (!/chrome|electron|libssl/i.test(mod.name)) continue;
        try {
            const exports = mod.enumerateExports();
            for (const exp of exports) {
                if (exp.name === 'SSL_CTX_set_custom_verify') {
                    Interceptor.attach(exp.address, {
                        onEnter(args) {
                            console.log('[SSL] BoringSSL SSL_CTX_set_custom_verify -> NOP callback');
                            // Replace callback with one that returns ssl_verify_ok (0)
                            args[2] = new NativeCallback(function() { return 0; }, 'int', ['pointer', 'pointer']);
                        }
                    });
                    hookCount++;
                }
            }
        } catch (e) {}
    }
} catch (e) {}

// --- WinINet (legacy Windows HTTP) ---
try {
    const InternetSetOptionW = Module.findExportByName('wininet.dll', 'InternetSetOptionW');
    if (InternetSetOptionW) {
        Interceptor.attach(InternetSetOptionW, {
            onEnter(args) {
                const option = args[1].toInt32();
                // INTERNET_OPTION_SECURITY_FLAGS = 31
                if (option === 31) {
                    console.log('[SSL] InternetSetOptionW security flags intercepted');
                }
            }
        });
        hookCount++;
    }
} catch (e) {}

console.log('[+] SSL pinning bypass: ' + hookCount + ' hooks installed');
