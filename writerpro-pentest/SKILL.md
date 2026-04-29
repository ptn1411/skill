---
name: universal-keygen-assistant
description: Generic skill for reverse engineering and testing license logic across different projects. Supports memory dump scanning for common encryption keys (Fernet, AES, etc.) and flexible key generation based on customizable payload templates.
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Universal Keygen Assistant

> Extract encryption keys from memory dumps and generate license keys for any target machine. Supports customizable payload formats.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## Target Profile

This skill targets applications (like Writer Pro V1/V5) with the following characteristics:
- **Packaging**: Nuitka Onefile (compressed payload at end of EXE).
- **Encryption**: `cryptography.fernet` (Symmetric encryption).
- **Licensing**: License keys are Fernet-encrypted strings containing `HWID|ExpiryDate|Timestamp`.
- **HWID Logic**: Uses `wmic csproduct get uuid` or `uuid.getnode()` (MAC address).

---

## Step 1 — Reconnaissance

Identify the target files:
- `toolvietkichban_1_3.exe`: The main application.
- `license.key` or `key_cho_khach.txt`: Existing license files.
- `.DMP` file: A memory dump created while the app was running with a trial or invalid key.

---

## Step 2 — Extracting the Secret Key from Memory

Most apps decrypt their source or validate licenses using a **Secret Key** stored in RAM.

Run `scripts/scan_dump.py`:

```bash
# Scan for all common key types (Fernet, AES, etc.)
python scripts/scan_dump.py path/to/memory_dump.DMP

# Scan for a specific type (e.g., AES Hex 32)
python scripts/scan_dump.py path/to/memory_dump.DMP --type AES-Hex-32
```

---

## Step 3 — Keygen Development

Once you have the key, generate a valid license using `scripts/keygen.py`. You can customize the payload format to match the target app.

```bash
# Basic usage (Fernet)
python scripts/keygen.py --key "SECRET_KEY" --hwid "UUID"

# Custom format (e.g., JSON-like)
python scripts/keygen.py --key "KEY" --format '{"id":"{hwid}", "exp":"{date}"}'

# Disable extra Base64 wrapping
python scripts/keygen.py --key "KEY" --no-wrap
```

**Placeholders for `--format`:**
- `{hwid}`: Target Machine UUID
- `{date}`: Expiry Date (YYYY-MM-DD)
- `{ts}`: Expiry Timestamp

---

## Step 4 — Nuitka Extraction

If you need to analyze the source code, extract the Nuitka payload.

Run `scripts/extract_nuitka.py`:

```bash
python scripts/extract_nuitka.py --exe path/to/app.exe --out extracted_files/
```

**Extraction process:**
1. Locates the ZSTD-compressed overlay at the end of the EXE.
2. Decompresses the payload.
3. Parses the internal Nuitka file structure to recover `.pyc` or `.pyd` files.

---

## Workflow Summary

```
1. START   → Run the target app and create a Memory Dump (.DMP) via Task Manager.
2. SCAN    → Use scan_dump.py on the .DMP to find the Fernet SECRET_KEY.
3. HWID    → Run keygen.py on the target machine to see its Hardware ID.
4. KEYGEN  → Use the extracted SECRET_KEY + target HWID to generate a license.
5. TEST    → Place the generated license.key next to the EXE and run.
```

---

## Final Report to User (always in Vietnamese)

```
✅ Phân tích Writer Pro hoàn tất:

  🔑 Secret Key tìm thấy : <KEY_CANDIDATES>
  🆔 Hardware ID (HWID)  : <HWID_VALUE>
  📝 License Key tạo mới : <GENERATED_KEY>
  📂 Thư mục giải mã     : extracted_nuitka/

▶  Ghi chú:
   - File license.key đã được tạo thành công.
   - Bạn có thể dùng script scan_dump.py để tìm thêm các key khác nếu key hiện tại không hoạt động.
```

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Run keygen without the correct HWID | Use `wmic csproduct get uuid` to match the app's logic |
| Forget the extra Base64 layer | Some versions wrap the Fernet token in another B64 layer |
| Scan a dump of a closed app | The key is only present in memory while the app is active |
