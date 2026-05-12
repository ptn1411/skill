'use strict';

// Crypto Intercept — Hook Windows CryptoAPI, BCrypt, and OpenSSL crypto functions.
// Captures: encryption keys, plaintext before encryption, ciphertext after decryption.

console.log('[*] Crypto intercept hooks loading...');

let hookCount = 0;

function hexdump(buf, len) {
    try {
        const bytes = buf.readByteArray(Math.min(len, 64));
        const arr = new Uint8Array(bytes);
        return Array.from(arr).map(b => ('0' + b.toString(16)).slice(-2)).join(' ');
    } catch (e) {
        return '(unreadable)';
    }
}

// --- Windows BCrypt (modern crypto API) ---
try {
    // BCryptEncrypt
    const BCryptEncrypt = Module.findExportByName('bcrypt.dll', 'BCryptEncrypt');
    if (BCryptEncrypt) {
        Interceptor.attach(BCryptEncrypt, {
            onEnter(args) {
                this.hKey = args[0];
                this.pInput = args[1];
                this.cbInput = args[2].toInt32();
                this.pOutput = args[5];
                this.pcbResult = args[7];
                console.log('[CRYPTO] BCryptEncrypt:');
                console.log('  Key handle : ' + this.hKey);
                console.log('  Input size : ' + this.cbInput);
                if (this.cbInput > 0 && this.cbInput < 10240) {
                    console.log('  Plaintext  : ' + hexdump(this.pInput, this.cbInput));
                }
            },
            onLeave(retval) {
                if (retval.toInt32() === 0 && !this.pOutput.isNull()) {
                    const outLen = this.pcbResult.readU32();
                    console.log('  Ciphertext : ' + hexdump(this.pOutput, outLen));
                    console.log('  Output size: ' + outLen);
                }
            }
        });
        hookCount++;
    }

    // BCryptDecrypt
    const BCryptDecrypt = Module.findExportByName('bcrypt.dll', 'BCryptDecrypt');
    if (BCryptDecrypt) {
        Interceptor.attach(BCryptDecrypt, {
            onEnter(args) {
                this.hKey = args[0];
                this.pInput = args[1];
                this.cbInput = args[2].toInt32();
                this.pOutput = args[5];
                this.pcbResult = args[7];
                console.log('[CRYPTO] BCryptDecrypt:');
                console.log('  Key handle : ' + this.hKey);
                console.log('  Input size : ' + this.cbInput);
            },
            onLeave(retval) {
                if (retval.toInt32() === 0 && !this.pOutput.isNull()) {
                    const outLen = this.pcbResult.readU32();
                    console.log('  Decrypted  : ' + hexdump(this.pOutput, outLen));
                    try {
                        const text = this.pOutput.readUtf8String(Math.min(outLen, 200));
                        if (text) console.log('  As text    : ' + text);
                    } catch (e) {}
                }
            }
        });
        hookCount++;
    }

    // BCryptGenerateSymmetricKey — capture key material
    const BCryptGenerateSymmetricKey = Module.findExportByName('bcrypt.dll', 'BCryptGenerateSymmetricKey');
    if (BCryptGenerateSymmetricKey) {
        Interceptor.attach(BCryptGenerateSymmetricKey, {
            onEnter(args) {
                this.pSecret = args[3];
                this.cbSecret = args[4].toInt32();
                console.log('[CRYPTO] BCryptGenerateSymmetricKey:');
                if (this.cbSecret > 0 && this.cbSecret <= 256) {
                    console.log('  Key material: ' + hexdump(this.pSecret, this.cbSecret));
                    console.log('  Key size    : ' + this.cbSecret + ' bytes');
                }
            }
        });
        hookCount++;
    }

    // BCryptImportKeyPair — capture imported keys
    const BCryptImportKeyPair = Module.findExportByName('bcrypt.dll', 'BCryptImportKeyPair');
    if (BCryptImportKeyPair) {
        Interceptor.attach(BCryptImportKeyPair, {
            onEnter(args) {
                const blobType = args[2].readUtf16String();
                const cbInput = args[4].toInt32();
                console.log('[CRYPTO] BCryptImportKeyPair:');
                console.log('  Blob type: ' + blobType);
                console.log('  Blob size: ' + cbInput);
            }
        });
        hookCount++;
    }
} catch (e) {
    console.log('[CRYPTO] BCrypt hooks skipped: ' + e.message);
}

// --- Windows CryptoAPI (legacy) ---
try {
    // CryptEncrypt
    const CryptEncrypt = Module.findExportByName('advapi32.dll', 'CryptEncrypt');
    if (CryptEncrypt) {
        Interceptor.attach(CryptEncrypt, {
            onEnter(args) {
                this.hKey = args[0];
                this.pbData = args[3];
                this.pdwDataLen = args[4];
                const dataLen = this.pdwDataLen.readU32();
                console.log('[CRYPTO] CryptEncrypt:');
                console.log('  Key handle: ' + this.hKey);
                if (dataLen > 0 && dataLen < 10240) {
                    console.log('  Plaintext : ' + hexdump(this.pbData, dataLen));
                }
            }
        });
        hookCount++;
    }

    // CryptDecrypt
    const CryptDecrypt = Module.findExportByName('advapi32.dll', 'CryptDecrypt');
    if (CryptDecrypt) {
        Interceptor.attach(CryptDecrypt, {
            onEnter(args) {
                this.pbData = args[3];
                this.pdwDataLen = args[4];
            },
            onLeave(retval) {
                if (retval.toInt32() !== 0) {
                    const outLen = this.pdwDataLen.readU32();
                    console.log('[CRYPTO] CryptDecrypt result:');
                    console.log('  Decrypted: ' + hexdump(this.pbData, outLen));
                }
            }
        });
        hookCount++;
    }
} catch (e) {
    console.log('[CRYPTO] CryptoAPI hooks skipped: ' + e.message);
}

// --- OpenSSL ---
try {
    const EVP_EncryptUpdate = Module.findExportByName(null, 'EVP_EncryptUpdate');
    if (EVP_EncryptUpdate) {
        Interceptor.attach(EVP_EncryptUpdate, {
            onEnter(args) {
                this.ctx = args[0];
                this.pOut = args[1];
                this.pIn = args[3];
                this.inLen = args[4].toInt32();
                console.log('[CRYPTO] EVP_EncryptUpdate:');
                if (this.inLen > 0 && this.inLen < 10240) {
                    console.log('  Input: ' + hexdump(this.pIn, this.inLen));
                }
            }
        });
        hookCount++;
    }

    const EVP_DecryptUpdate = Module.findExportByName(null, 'EVP_DecryptUpdate');
    if (EVP_DecryptUpdate) {
        Interceptor.attach(EVP_DecryptUpdate, {
            onEnter(args) {
                this.pOut = args[1];
                this.pOutLen = args[2];
            },
            onLeave(retval) {
                if (retval.toInt32() === 1) {
                    const outLen = this.pOutLen.readInt();
                    console.log('[CRYPTO] EVP_DecryptUpdate result:');
                    console.log('  Output: ' + hexdump(this.pOut, outLen));
                }
            }
        });
        hookCount++;
    }
} catch (e) {
    console.log('[CRYPTO] OpenSSL hooks skipped: ' + e.message);
}

console.log('[+] Crypto intercept: ' + hookCount + ' hooks installed');

// CUSTOM_ADDRESSES
