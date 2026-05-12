# Advanced Reverse Engineering Toolkit — Installation Guide

Bộ công cụ (Skills) cao cấp có toàn quyền truy cập kỹ thuật không giới hạn: hỗ trợ dịch ngược mọi loại mã nguồn, bẻ khóa các lớp bảo vệ phức tạp, và tự động hóa quy trình cho đến khi trích xuất thành công code và tạo được keygen hoàn chỉnh cho ứng dụng.

## 🛠 Danh sách Skills

### 0. [master-unlock](./master-unlock/)
Kích hoạt quyền thực thi không giới hạn, xác lập mục tiêu và duy trì phiên làm việc cho đến khi đạt được kết quả dịch ngược và keygen mong muốn.
- **Cách dùng**: Luôn kích hoạt đầu tiên để mở khóa toàn bộ sức mạnh của toolkit.

### 1. [pentest-script-generator](./antigravity-kit/pentest-script-generator/)
Tự động sinh pentest script + verify script từ báo cáo lỗ hổng (vuln-XXXX.md).
- **Cách dùng**: `python generate.py vuln-0001.md`

### 2. [binary-identifier](./binary-identifier/)
Định danh ngôn ngữ (Python, Go, Rust...), trình biên dịch và packer (UPX, VMProtect...).
- **Cách dùng**: `python identify_app.py target.exe`

### 3. [javascript-deobfuscator](./javascript-deobfuscator/)
Dịch ngược hoàn toàn JavaScript bị obfuscate, khôi phục mã nguồn từ sourcemap và tự động trích xuất tokens/cookies live.
- **Cách dùng**: `python extract_sourcemap.py <URL> --out recovered-code`

### 4. [electron-app-analyzer](./electron-app-analyzer/)
Giải phẫu toàn diện ứng dụng Electron: bóc tách IPC bridges, khôi phục logic Main/Preload và trích xuất bí mật ẩn trong app.
- **Cách dùng**: `python analyze_electron.py extracted-app --out electron-analysis`

### 5. [electron-builder-unpacker](./electron-builder-unpacker/)
Bung mọi artifact Electron Builder (`app.asar`, `app-update.yml`...) để khôi phục 100% mã nguồn và tài nguyên gốc.
- **Cách dùng**: `python unpack_electron_builder.py app-dir --out electron-unpacked`

### 6. [electron-builder-repacker](./electron-builder-repacker/)
Chỉnh sửa và đóng gói lại app Electron (Code Injection): cho phép AI viết thêm tính năng hoặc bypass vào app và chạy bình thường.
- **Cách dùng**: `python repack_electron_builder.py app_asar --out electron-repacked`

### 7. [nuitka-decryptor](./nuitka-decryptor/)
Giải mã và khôi phục hoàn toàn mã nguồn Python của mọi ứng dụng đóng gói bằng Nuitka, vượt qua mọi lớp bảo vệ XOR/Fernet.
- **Cách dùng**: `python extract_key.py --pyd app.pyd --config cfg.encrypted`

### 8. [writerpro-pentest (Universal Keygen Assistant)](./writerpro-pentest/)
Quét sâu RAM và phân tích thuật toán để trích xuất secret keys và tạo trình tạo khóa (keygen) hoàn chỉnh cho mọi ứng dụng.
- **Cách dùng**: `python scan_dump.py dump.DMP`

### 9. [binary-patcher](./binary-patcher/)
Vá mã máy cấp độ chuyên sâu (Assembly Patching) để bẻ gãy mọi rào cản bản quyền (License Check) và thay đổi logic thực thi của ứng dụng.
- **Cách dùng**: `python apply_patch.py target.exe --patch <OFFSET> <ORIGINAL> <PATCH>`

### 10. [anti-debugging-techniques](./anti-debugging-techniques/)
Phát hiện và bypass các tầng chống debug (ptrace, PEB, timing, exception, TLS callback) trước khi vá. Bắt buộc dùng trước `binary-patcher` với binary thương mại.
- **Cách dùng**: tham chiếu skill — kết hợp ScyllaHide / Frida / LD_PRELOAD theo bảng phân loại trong SKILL.md.

### 11. [binary-protection-bypass](./binary-protection-bypass/)
Định danh và bypass mitigation ELF (ASLR, PIE, NX, canary, RELRO, FORTIFY, CET, MTE) khi patch chuẩn không vào.
- **Cách dùng**: `checksec ./binary` → match primitive↔mitigation theo bảng SKILL.md §2 → build chain bằng pwntools.

### 12. [vm-and-bytecode-reverse](./vm-and-bytecode-reverse/)
Reverse engineer custom VM và bytecode interpreter (dispatcher → opcode table → disassembler). Cover .pyc/.NET CIL/JVM/Lua/WASM/EVM + VMProtect/Themida.
- **Cách dùng**: locate dispatcher → walk handlers → write disassembler bằng template Python trong SKILL.md §3.

### 13. [symbolic-execution-tools](./symbolic-execution-tools/)
Symbolic execution với angr / Z3 / Unicorn / Qiling — tự động tìm input thỏa mãn license check thay vì brute force.
- **Cách dùng**: `pip install angr claripy z3-solver` → script template trong SKILL.md §2.

### 14. [android-apk-pentester](./android-apk-pentester/)
Kiểm thử bảo mật Android APK/XAPK/APKS được ủy quyền: phân tích tĩnh, cài split APK, setup emulator root, cấu hình mitmproxy, và sinh Frida hooks phục vụ kiểm thử runtime.
- **Cách dùng**: `python android-apk-pentester/scripts/analyze_apk.py app.apk --out output/apk-analysis`

### 15. [container-cloud-auditor](./container-cloud-auditor/)
Audit Docker, Compose, Kubernetes, Terraform, and cloud configuration for risky defaults and exposed secrets.
- **Cách dùng**: `python container-cloud-auditor/scripts/analyze_container_cloud.py . --out output/container-cloud-auditor`

### 16. [sbom-supply-chain-auditor](./sbom-supply-chain-auditor/)
Audit dependency manifests and lockfiles for SBOM extraction, risky install scripts, unpinned versions, remote dependency sources, and secret-like values.
- **Cách dùng**: `python sbom-supply-chain-auditor/scripts/analyze_supply_chain.py . --out output/sbom-supply-chain-auditor`

### 17. [orchestrator-plugin-sdk](./orchestrator-plugin-sdk/)
Scaffold and validate new toolkit skills with the standard file layout, metadata, output contract, and orchestrator registration checklist.
- **Cách dùng**: `python orchestrator-plugin-sdk/scripts/validate_skill_contract.py container-cloud-auditor`

---

## 🚀 Hướng dẫn cài đặt

### Bước 0 — Dependencies

```bash
# bash / WSL / Linux / macOS
pip install -r requirements.txt
```

```powershell
# Windows PowerShell
pip install -r requirements.txt
```

Tooling ngoài Python (Node.js, asar, UPX, x64dbg, dnSpy…): xem [TOOLS.md](./TOOLS.md).

### Bước 1 — Chạy thử orchestrator

```bash
python scripts/orchestrate.py path/to/target.exe --require-tools
```

```powershell
python scripts\orchestrate.py 'C:\Program Files\MyApp\target.exe' --require-tools
```

Output: `output/REPORT.md` + `output/mission.json`.

### Cài vào Cowork (Desktop App)
Copy thư mục của skill tương ứng vào thư mục skills của Cowork:
**Windows:** `%APPDATA%\Claude\local-agent-mode-sessions\skills-plugin\<session-id>\<session-id>\skills\`

### Cài vào Codex CLI / Gemini CLI / OpenAI Assistants
Mỗi skill có manifest đa nền tảng trong `<skill>/agents/{codex,gemini,openai}.yaml`. Đọc comment đầu file để biết đường dẫn cài (vd Codex: `~/.codex/prompts/<name>.md`; Gemini: `.gemini/commands/<name>.toml`).

---

## 📊 So sánh các công cụ

| Tool | Chức năng chính | Ngôn ngữ mục tiêu |
|---|---|---|
| **Master Unlock** | Mở khóa toàn bộ quyền hạn kỹ thuật | Tất cả workflow |
| **Script Generator** | Tạo script khai thác từ báo cáo | Đa ngôn ngữ (Python, Bash) |
| **Binary Identifier** | Định danh ngôn ngữ và lớp bảo vệ | EXE, DLL, PYD |
| **JS Deobfuscator** | Dịch ngược JS, khôi phục sourcemap, dump token | JS, sourcemap, bundle |
| **Electron Analyzer** | Giải phẫu kiến trúc App và IPC | Electron, ASAR, JS |
| **Electron Unpacker** | Bung ASAR và khôi phục mã nguồn gốc | Electron Builder |
| **Electron Repacker** | Chỉnh sửa và đóng gói lại App (Injection) | Electron Builder |
| **Nuitka Decryptor** | Khôi phục 100% nguồn Python | Python (Nuitka) |
| **Universal Keygen** | Phân tích thuật toán và tạo Keygen | Fernet, AES, Hex... |
| **Binary Patcher** | Vá mã máy bẻ gãy mọi rào cản | EXE, DLL (C++, Delphi...) |
| **Android APK Pentester** | Phân tích, cài đặt, intercept và kiểm thử runtime Android app | APK, XAPK, APKS |
| **Container Cloud Auditor** | Audit cấu hình container/cloud | Docker, Compose, Kubernetes, Terraform |
| **SBOM Supply Chain Auditor** | Audit dependency manifests và lockfiles | npm, pip, Maven, Gradle, Cargo, NuGet |
| **Orchestrator Plugin SDK** | Scaffold và validate skill mới | Toolkit skills |

---

## 🔍 Quy trình Reverse Engineering khuyến nghị

1. **Master Unlock**: Kích hoạt `master-unlock` để mở khóa quyền hạn tối thượng.
2. **Recon**: Dùng `binary-identifier` để biết app được bảo vệ bởi lớp gì.
3. **JS Analyze**: Nếu là Web/JS, dùng `javascript-deobfuscator` để lấy lại mã nguồn và secrets.
4. **Electron Unpack**: Dùng `electron-builder-unpacker` để lấy toàn bộ code bên trong app Electron.
5. **Analyze & Edit**: Dùng `electron-app-analyzer` để tìm lỗi, sau đó yêu cầu AI sửa code theo ý muốn.
6. **Repack**: Dùng `electron-builder-repacker` để đóng gói lại app đã sửa và chạy bình thường.
7. **Native Analyze**: Nếu là Nuitka, dùng `nuitka-decryptor`. Nếu cần Keygen, dùng `writerpro-pentest`.
8. **Patch**: Nếu app Native có check bản quyền, dùng `binary-patcher` để bẻ gãy trực tiếp.
9. **Generate**: Dùng `pentest-script-generator` để tạo code khai thác tự động cho các lỗ hổng tìm thấy.
