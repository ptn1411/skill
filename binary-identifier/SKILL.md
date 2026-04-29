---
name: binary-identifier
description: Fingerprint binary executables to identify programming languages, compilers, packers, and obfuscators. Uses signature scanning (PE sections, strings, function names) to determine the technology stack.
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Binary Identifier Skill

> Analyze any executable (.exe, .pyd, .dll) to determine how it was built and protected. Essential for choosing the right reverse engineering strategy.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## Capabilities

This skill can detect:
- **Languages**: Python (Nuitka/PyInstaller), Go, Rust, C#, C++, Java, Delphi.
- **Packers**: UPX, VMProtect, Themida, Enigma.
- **Encryption**: Indicators of Fernet, AES, or custom XOR layers.

---

## Step 1 — Quick Identification

Run `scripts/identify_app.py`:

```bash
python scripts/identify_app.py path/to/target.exe
```

**What it looks for:**
- **PE Sections**: Names like `.vmp0` (VMProtect), `UPX0` (UPX), `.rdata` (Nuitka constants).
- **Strings**: Magic constants like `Py_Initialize`, `go.itab.`, `rustc`.
- **Imports**: DLLs like `mscoree.dll` (.NET), `python3.dll`.

---

## Step 2 — Analysis Strategy Selection

Based on the identification results:

| Result | Strategy |
|--------|----------|
| **Python (Nuitka)** | Use `nuitka-decryptor` or `writerpro-pentest`. |
| **Python (PyInstaller)** | Use `pyinstxtractor` to recover source. |
| **C# / .NET** | Use `dnSpy` for near-perfect source code recovery. |
| **UPX** | Run `upx -d file.exe` to unpack. |
| **Go / Rust** | Use specialized IDA/Ghidra plugins for symbol recovery. |

---

## Final Report to User (always in Vietnamese)

```
🔍 Kết quả định danh ứng dụng:

  🌐 Ngôn ngữ/Trình biên dịch : <LANGUAGE>
  🛡️ Packer/Bảo mật           : <PACKER_TYPE>
  🔑 Dấu hiệu mã hóa          : <ENCRYPTION_HINTS>

▶  Khuyến nghị:
   - <Dựa trên kết quả, hãy sử dụng skill tương ứng hoặc công cụ phù hợp>
```

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Start decrypting without identifying the language | Different languages use different encryption libraries |
| Assume all Python apps use Nuitka | PyInstaller is equally common and requires different tools |
| Skip the identification step | Identifying a packer like UPX saves hours of reverse engineering |
