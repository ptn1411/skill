# Nuitka App Encryption Patterns — Reference

Quick reference for identifying and attacking common Nuitka app encryption schemes.

---

## Pattern 1 — XOR + Base64 (VideoAIStudio style)

**Identification signals:**
- `.encrypted` files contain only base64 text (A-Za-z0-9+/=)
- `MANIFEST.txt` lists Python module paths
- `config_loader.pyd` or similar in the binary tree
- Strings like `BT_DEV_`, `_SECURE`, `_2025_` in binary analysis

**Key location:** Nuitka marshalled constants in `.rdata` or `.rsrc` PE section

**Attack:**
```python
import base64
KEY = b'BT_DEV_2025_SECURE'
def decrypt(b64_text):
    data = base64.b64decode(b64_text)
    kr = (KEY * (len(data)//len(KEY)+1))[:len(data)]
    return bytes(a^b for a,b in zip(data,kr)).decode()
```

**Known-plaintext:** JSON config files always start with `{` — XOR with first encrypted byte to get key byte 0.

---

## Pattern 2 — Fernet (AES-128-CBC + HMAC-SHA256)

**Identification signals:**
- Encrypted blobs start with `gAAAAA` (base64url Fernet token)
- `cryptography` in requirements.txt
- `Fernet` string in binary

**Key location:** Often hardcoded as base64url string in `.rdata`, or derived from a password via PBKDF2

**Attack:**
```python
from cryptography.fernet import Fernet
# Key is a base64url-encoded 32-byte value
f = Fernet(b'<key_from_binary>')
plaintext = f.decrypt(b'gAAAAA...')
```

---

## Pattern 3 — AES-256-GCM

**Identification signals:**
- 16/32-byte blobs in binary (high entropy)
- `pycryptodome` or `PyNaCl` in requirements.txt
- `AES`, `GCM`, `nonce`, `tag` strings in binary

**Key extraction:**
- Look for 32-byte sequences in `.rdata` flanked by null bytes
- May be derived from machine-specific info (hostname, MAC, disk serial)

---

## Pattern 4 — PyArmor obfuscation

**Identification signals:**
- `pytransform.pyd` or `pytransform_protection` in the app
- `__armor_enter__` / `__armor_exit__` in disassembly
- `pyarmor` string in binary strings output

**Attack:** PyArmor has known deobfuscation tools (pyarmor-tool, unpyarmor).
Look for the `armor_key` in `.rdata`.

---

## PE Section Quick Reference

| Section | What to look for |
|---------|-----------------|
| `.rdata` | Read-only data: string constants, key material, Nuitka constants blob |
| `.rsrc` | Windows resources: marshalled Python constants (Nuitka stores here) |
| `.data` | Mutable data: runtime state, less useful for static analysis |
| `.text` | Code: XOR loops, decrypt function patterns |

---

## Key Size Heuristics

| Key length | Likely type |
|-----------|-------------|
| 16 bytes | AES-128, or short ASCII key |
| 18–24 bytes | Short ASCII passphrase (e.g. `BT_DEV_2025_SECURE` = 18) |
| 32 bytes | AES-256, or Fernet key (32 bytes b64url) |
| 44 chars (base64) | Fernet key |
| 64 chars (hex) | SHA-256 key hash |

---

## Binary String Grep Cheatsheet

```bash
# Strings tool equivalent in Python
python analyze_binary.py --pyd config_loader.pyd --out strings.txt

# Search output for key patterns
grep -i "key\|secret\|token\|encrypt\|dev_" strings.txt

# Look for exactly 16-32 alphanum chars (likely keys)
grep -Eo '[A-Za-z0-9_]{16,32}' strings.txt | sort -u
```

---

## Known Keys (reference only)

| App | Key | Algorithm |
|-----|-----|-----------|
| VideoAIStudio v2.1.5 | `BT_DEV_2025_SECURE` | XOR + Base64 |

---

## Evidence Saving After Successful Decrypt

Always save:
1. `key_final.txt` — confirmed key value
2. `decrypt_test.txt` — first 500 chars of decrypted config
3. `key_extraction.txt` — full PE analysis log
4. `decrypted_sources/` — full source tree
