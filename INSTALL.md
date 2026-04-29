# Pentest Toolkit — Installation Guide

Bộ công cụ (Skills) hỗ trợ pentest ứng dụng, tự động sinh script, giải mã binary và tạo keygen.

## 🛠 Danh sách Skills

### 1. [pentest-script-generator](./antigravity-kit/pentest-script-generator/)
Tự động sinh pentest script + verify script từ báo cáo lỗ hổng (vuln-XXXX.md).
- **Cách dùng**: `python generate.py vuln-0001.md`

### 2. [binary-identifier](./binary-identifier/)
Định danh ngôn ngữ (Python, Go, Rust...), trình biên dịch và packer (UPX, VMProtect...).
- **Cách dùng**: `python identify_app.py target.exe`

### 3. [nuitka-decryptor](./nuitka-decryptor/)
Giải mã các ứng dụng Python đóng gói bằng Nuitka sử dụng cơ chế XOR + Base64.
- **Cách dùng**: `python extract_key.py --pyd app.pyd --config cfg.encrypted`

### 4. [writerpro-pentest (Universal Keygen)](./writerpro-pentest/)
Quét RAM (Memory Dump) tìm Secret Keys và tạo License Key cho mọi dự án.
- **Cách dùng**: `python scan_dump.py dump.DMP`

### 5. [binary-patcher](./binary-patcher/)
Vá mã máy (Assembly Patching) để bypass rào cản bản quyền hoặc thay đổi logic ứng dụng.
- **Cách dùng**: `python apply_patch.py target.exe --patch <OFFSET> <ORIGINAL> <PATCH>`

---

## 🚀 Hướng dẫn cài đặt

### Cài vào Cowork (Desktop App)
Copy thư mục của skill tương ứng vào thư mục skills của Cowork:
**Windows:** `%APPDATA%\Claude\local-agent-mode-sessions\skills-plugin\<session-id>\<session-id>\skills\`

### Cài vào antigravity-kit (CLI/Agent)
Copy thư mục skill vào `<repo>/.agent/skills/` và đăng ký trong file agent definition.

---

## 📊 So sánh các công cụ

| Tool | Chức năng chính | Ngôn ngữ mục tiêu |
|---|---|---|
| **Script Generator** | Tạo script tấn công từ báo cáo | Đa ngôn ngữ (Python, Bash) |
| **Binary Identifier** | Fingerprinting binary | EXE, DLL, PYD |
| **Nuitka Decryptor** | Giải mã source code Nuitka | Python (Nuitka) |
| **Universal Keygen** | Quét RAM & Tạo license | Fernet, AES, Hex... |
| **Binary Patcher** | Vá mã máy (Assembly Patch) | EXE, DLL (C++, Delphi...) |

---

## 🔍 Quy trình Pentest khuyến nghị

1. **Recon**: Dùng `binary-identifier` để biết app viết bằng gì.
2. **Analyze**: Nếu là Nuitka, dùng `nuitka-decryptor`. Nếu cần keygen, dùng `writerpro-pentest`.
3. **Patch**: Nếu app viết bằng C++/Native, dùng `binary-patcher` để bypass logic bản quyền.
4. **Exploit**: Sau khi có mã nguồn/bí mật, viết báo cáo `vuln.md`.
5. **Generate**: Dùng `pentest-script-generator` để tạo code khai thác tự động.
