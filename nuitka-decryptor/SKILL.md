---
name: nuitka-decryptor
description: Reverse engineer and decrypt Nuitka-compiled Python applications. Extracts encryption keys from PE binaries (.pyd), analyzes binary constants, and bulk-decrypts XOR+Base64 encrypted source files. Use when given a compiled Python app with .encrypted source files, .pyd Nuitka modules, or asked to reverse engineer / decrypt app source code.
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Nuitka Decryptor Skill

> Reverse engineer Nuitka-compiled Python apps: extract keys from PE binaries, decrypt XOR+Base64 source files.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## How Nuitka App Encryption Works

Nuitka compiles Python → C → `.exe` / `.pyd` (Windows DLL). Some apps add a custom encryption layer:

```
Source .py  →  encrypt(XOR + Base64, key)  →  .encrypted files
              key embedded in Nuitka constants (.rdata / .rsrc section of .pyd)
```

**Standard pattern** (confirmed on VideoAIStudio v2.1.5):

| Property | Value |
|----------|-------|
| Algorithm | XOR with repeating key |
| Encoding | Base64 (standard) |
| Key location | Nuitka marshalled constants in `.rdata` / `.rsrc` PE section |
| Key format | ASCII string (e.g. `BT_DEV_2025_SECURE`) |
| Formula | `plaintext = XOR(base64_decode(ciphertext), repeating_key)` |

---

## Step 1 — Reconnaissance: Map the target

Before running any script, identify:

```
target_app/
├── app/
│   ├── encrypted_sources/
│   │   ├── MANIFEST.txt        ← list of all source files
│   │   └── *.encrypted         ← encrypted Python source
│   └── repo/updater/
│       ├── config_loader.pyd   ← KEY IS HERE (Nuitka constants)
│       └── update_agent.pyd    ← secondary binary
├── *.encrypted                 ← encrypted config files
└── decrypted_sources/          ← output directory
```

**Trigger keywords** that suggest this pattern:
- `.encrypted` files alongside a `.pyd` or `.exe`
- `MANIFEST.txt` listing Python module paths
- `base64` + XOR combo in network traffic or strings analysis
- Nuitka strings (`__compiled__`, `nuitka`, `cp312-win_amd64`) in binary

---

## Step 2 — Binary Analysis

Run `scripts/analyze_binary.py` to surface key candidates:

```bash
python scripts/analyze_binary.py \
  --pyd path/to/config_loader.pyd \
  --out binary_analysis.txt
```

What it finds:
- Printable strings containing `key`, `secret`, `encrypt`, `decrypt`, `token`, `cipher`
- 16/32-byte high-entropy byte sequences (potential AES keys)
- Base64-like strings (20–100 chars)
- Nuitka function name patterns (`load_encrypted`, `get_key`, `xor`, `b64decode`)
- Long ASCII strings > 32 chars (embedded key candidates)

**Key discovery heuristic** — if you see a string like:
```
BT_DEV_2025_SECURE    ← 18-char ASCII key
BT_Automation_Tiktok  ← variant
```
→ This is almost certainly the XOR key. Proceed to Step 3.

---

## Step 3 — Key Extraction via PE Resource

Run `scripts/extract_key.py` to pull marshalled constants from the PE `.rsrc` / `.rdata` section:

```bash
python scripts/extract_key.py \
  --pyd path/to/config_loader.pyd \
  --config path/to/update_config.json.encrypted \
  --out key_extraction.txt
```

**Known-plaintext attack on config file:**

If `config.encrypted[0]` XOR `{` = key[0]:
```python
key[0] = config_enc[0] ^ ord('{')   # JSON always starts with {
key[1] = config_enc[1] ^ ord('\n')  # formatted JSON has newline
key[2] = config_enc[2] ^ ord(' ')   # indented with spaces
# Continue to recover full key byte-by-byte
```

**PE resource parsing approach:**
1. Read PE header → find `.rsrc` section offset
2. Attempt `marshal.loads()` on resource chunks
3. Search `.rdata` for key-sized (16/32B) high-entropy sequences

---

## Step 4 — Decrypt All Sources

Once key is confirmed, run `scripts/decrypt_all.py`:

```bash
# Decrypt all files listed in MANIFEST.txt
python scripts/decrypt_all.py \
  --key "BT_DEV_2025_SECURE" \
  --encrypted-dir path/to/app/encrypted_sources \
  --output-dir path/to/decrypted_sources \
  --manifest path/to/app/encrypted_sources/MANIFEST.txt

# Decrypt a single .encrypted file
python scripts/decrypt_all.py \
  --key "BT_DEV_2025_SECURE" \
  --single path/to/file.encrypted \
  --output-dir ./out

# Decrypt a config file
python scripts/decrypt_all.py \
  --key "BT_DEV_2025_SECURE" \
  --single update_config.json.encrypted \
  --output-dir ./out
```

**Decrypt formula** (pure stdlib, no deps):
```python
import base64
def xor_decrypt(payload_b64: str, key: bytes) -> str:
    decoded = base64.b64decode(payload_b64)
    kr = (key * (len(decoded) // len(key) + 1))[:len(decoded)]
    return bytes(a ^ b for a, b in zip(decoded, kr)).decode('utf-8')
```

---

## Step 5 — Verify & Analyze

After decryption, verify output:

```bash
# Check a sample file looks like valid Python
head -50 decrypted_sources/main.py
head -50 decrypted_sources/core/config.py

# Search for hardcoded secrets in decrypted source
grep -rn "api_key\|secret\|password\|token\|LICENSE" decrypted_sources/
grep -rn "http\|https" decrypted_sources/ | grep -v "\.pyc"
```

**What to look for in decrypted source:**
- License validation logic (bypass candidates)
- API keys / tokens embedded in code
- Encryption keys for other data stores
- Backend endpoints not visible from network traffic
- Authentication bypass opportunities

- Authentication bypass opportunities

---

## Step 7 — Keygen Development Support

If asked to create a keygen or extract license validation logic, use `scripts/extract_keygen_data.py`:

```bash
python scripts/extract_keygen_data.py \
  --pyd path/to/main_app.pyd \
  --out keygen_info.txt
```

**Keygen targets:**
- **HWID Retrieval**: Identification of system-specific IDs (MachineGuid, MAC address, Disk Serial) used to bind licenses.
- **Hashing Constants**: Detection of MD5/SHA256 initialization constants, which indicate the hashing algorithm used for license generation.
- **Secret Salts**: High-entropy strings near license-related keywords often act as salts for hashing.
- **License Logic**: Strings like `trial`, `expired`, `activation_code` help locate the validation routines.

---

## Step 8 — Key Confirmation Test

Before bulk decryption, always verify the key on a known-structure file:

```python
# Quick sanity check
result = xor_decrypt(open('update_config.json.encrypted').read().strip(), key)
assert result.strip().startswith('{'), f"Wrong key! Got: {result[:20]}"
import json; json.loads(result)  # must parse as valid JSON
print("Key confirmed:", key)
```

---

## File Naming Convention

| Output | Filename |
|--------|----------|
| Binary analysis | `binary_analysis.txt` |
| Key extraction log | `key_extraction.txt` |
| Confirmed key | `key_final.txt` |
| Decrypt test | `decrypt_test.txt` |
| Decrypted sources | `decrypted_sources/<original_path>.py` |

---

## Workflow

```
1. RECON    → Identify .pyd files, .encrypted files, MANIFEST.txt
2. ANALYZE  → Run analyze_binary.py → find key candidates
3. EXTRACT  → Run extract_key.py → confirm key via known-plaintext
4. DECRYPT  → Run decrypt_all.py → bulk decrypt all source files
5. KEYGEN   → Run extract_keygen_data.py → extract HWID/hash data for keygen
6. VERIFY   → Sample check + grep for secrets/hardcoded values
7. REPORT   → Present findings to user IN VIETNAMESE
```

---

## Final Report to User (always in Vietnamese)

```
✅ Giải mã hoàn tất:

  🔑 Key tìm được  : <KEY_VALUE>
  📦 Thuật toán    : XOR + Base64
  📁 File giải mã  : N / TOTAL file thành công
  💾 Output        : decrypted_sources/

  🔍 Phát hiện đáng chú ý:
    - <danh sách secrets, endpoints, license logic>
    - <Thông tin Keygen: HWID pattern, hash constants, secret salts>

▶  Bước tiếp theo:
   grep -rn "api_key\|secret" decrypted_sources/
```

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Hardcode target paths in scripts | Use `--pyd`, `--encrypted-dir` args |
| Guess the key without verification | Always confirm on known-structure file first |
| Skip binary analysis | `analyze_binary.py` often reveals key directly in strings |
| Decrypt without checking MANIFEST | Some files may be absent — track success/fail counts |
| Use only one section (.rsrc) | Check both `.rsrc` and `.rdata` for marshal blobs |
| Present findings in English | Always deliver final summary in Vietnamese |
