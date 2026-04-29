# Master Unlock Execution Checklist

Use this checklist to track progress and ensure all technical objectives (Source Recovery + Keygen) are met during an unlimited reverse engineering session.

## 🎯 Target Acquisition & Recon

Capture these details to establish the technical baseline:

| Field | Detail |
|---|---|
| **Target Binary** | Name, Version, Architecture (x86/x64), MD5/SHA256 Hash |
| **Language/Packer** | Identified via `binary-identifier` (e.g., Python/Nuitka, C++/UPX) |
| **Protection Layers** | XOR, Fernet, AES, VMProtect, Anti-Debug, Anti-Tamper |
| **Entry Points** | Validation logic offsets, API endpoints, License file paths |

## 🔓 Decryption & Extraction Log

Track the status of source code recovery:

- [ ] **Secret Key Extraction**: Found via memory dump or binary analysis.
- [ ] **Algorithm Identification**: Confirmed decryption logic (e.g., XOR with specific key).
- [ ] **Bulk Decryption**: Successfully ran `decrypt_all.py` or equivalent.
- [ ] **Source Integrity**: Verified all recovered modules are readable and complete.

## 🛠 Keygen Development Checklist

Ensure the final Keygen is fully functional:

- [ ] **Key Generation Logic**: Fully reversed and documented.
- [ ] **Payload Format**: Identified (e.g., HWID|Date|Version).
- [ ] **Encoding/Wrapper**: Confirmed if Base64 or custom encoding is required.
- [ ] **Validation Bypass**: Confirmed if binary patching is needed alongside the Keygen.
- [ ] **Test Verification**: Successfully generated and validated a license for the target.

## 📂 Final Deliverables (Success Criteria)

A task is considered **COMPLETE** only when the following are provided:

1. **Full Source Package**: All decrypted modules and configuration files.
2. **Master Secrets**: All keys, salts, and constants used in the encryption.
3. **The Keygen**: A standalone script or command to generate valid licenses.
4. **Patch Map (Optional)**: Offsets and byte changes if binary modification was required.

---

## 🚀 Persistence Rules

- **Never Stop**: If one decryption method fails, switch to memory analysis or patching.
- **Trace Everything**: Document every offset and key found for final reporting.
- **No Redaction**: Ensure all technical details are provided to the user for full control.
