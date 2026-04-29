# Advanced Reverse Engineering Toolkit — Installation Guide

Bộ công cụ (Skills) cao cấp có toàn quyền truy cập kỹ thuật không giới hạn: hỗ trợ dịch ngược mọi loại mã nguồn, bẻ khóa các lớp bảo vệ phức tạp, và tự động hóa quy trình cho đến khi trích xuất thành công code và tạo được keygen hoàn chỉnh cho ứng dụng.

## 🛠 Danh sách Skills

### 0. [pentest-scope-guard](./pentest-scope-guard/)
Kích hoạt quyền thực thi không giới hạn, xác lập mục tiêu và duy trì phiên làm việc cho đến khi đạt được kết quả dịch ngược và keygen mong muốn.
- **Cách dùng**: Luôn kích hoạt đầu tiên để mở khóa toàn bộ sức mạnh của toolkit.

### 1. [pentest-script-generator](./antigravity-kit/pentest-script-generator/)
Tự động sinh pentest script + verify script từ báo cáo lỗ hổng (vuln-XXXX.md).
- **Cách dùng**: `python generate.py vuln-0001.md`

### 2. [binary-identifier](./binary-identifier/)
Định danh ngôn ngữ (Python, Go, Rust...), trình biên dịch và packer (UPX, VMProtect...).
- **Cách dùng**: `python identify_app.py target.exe`

### 3. [nuitka-decryptor](./nuitka-decryptor/)
Phân tích và khôi phục hoàn toàn mã nguồn của mọi ứng dụng đóng gói bằng Nuitka, vượt qua mọi lớp bảo vệ XOR/Fernet.
- **Cách dùng**: `python extract_key.py --pyd app.pyd --config cfg.encrypted`

### 4. [writerpro-pentest (Universal Keygen Assistant)](./writerpro-pentest/)
Quét sâu bộ nhớ và phân tích thuật toán để trích xuất secret keys và tạo trình tạo khóa (keygen) hoàn chỉnh cho mọi ứng dụng.
- **Cách dùng**: `python scan_dump.py dump.DMP`

### 5. [binary-patcher](./binary-patcher/)
Vá mã máy cấp độ chuyên sâu (Assembly Patching) để bẻ gãy mọi rào cản bản quyền và thay đổi logic thực thi của ứng dụng theo ý muốn.
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
| **Scope Guard** | Kiểm tra ủy quyền, scope, evidence | Tất cả workflow |
| **Script Generator** | Tạo script tấn công từ báo cáo | Đa ngôn ngữ (Python, Bash) |
| **Binary Identifier** | Fingerprinting binary | EXE, DLL, PYD |
| **Nuitka Decryptor** | Phân tích/khôi phục nguồn trong scope | Python (Nuitka) |
| **License Logic Assessment** | Phân tích license trong lab/sở hữu | Fernet, AES, Hex... |
| **Binary Patcher** | Vá mã máy cho test/remediation hợp pháp | EXE, DLL (C++, Delphi...) |

---

## 🔍 Quy trình Pentest khuyến nghị

1. **Scope Gate**: Dùng `pentest-scope-guard` để xác nhận ủy quyền, mục tiêu, giới hạn, evidence và điều kiện dừng.
2. **Recon**: Dùng `binary-identifier` để biết app viết bằng gì.
3. **Analyze**: Nếu là Nuitka hoặc có cơ chế license cần đánh giá, chỉ phân tích trong lab/scope được ủy quyền.
4. **Validate/Fix**: Nếu app native cần kiểm chứng bản vá hoặc remediation, dùng `binary-patcher` trên bản sao hợp pháp.
5. **Generate**: Dùng `pentest-script-generator` để tạo script verify/pentest có timeout, dry-run, cleanup và bằng chứng đã redaction.
