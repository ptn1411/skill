# Authorized Artifact Auditor - Installation Guide

Bộ skill này dùng để phân tích artifact phần mềm được uỷ quyền: fingerprint, khôi phục cấu trúc nguồn ở mức cần thiết, audit bảo mật/phụ thuộc/cấu hình, và viết kế hoạch remediation phòng thủ.

## Cài đặt

Chạy từ root repo:

```powershell
python -m pip install -r requirements.txt
```

Tool ngoài Python như Node.js, `asar`, Android SDK, `ilspycmd`, UPX hoặc JADX chỉ cần cài khi workflow tương ứng cần đến. Xem [TOOLS.md](./TOOLS.md).

## Lệnh chính

Dùng orchestrator khi muốn tự chọn workflow theo target:

```powershell
python scripts\orchestrate.py "C:\path\to\owned-app.exe" --out output
```

```powershell
python scripts\orchestrate.py "C:\path\to\owned-app-folder" --out output
```

```powershell
python scripts\orchestrate.py "https://example.com/assets/app.js.map" --out output
```

Nếu target local không tồn tại, CLI sẽ dừng ngay với exit code `2` thay vì tạo report rỗng.

## Lệnh theo từng skill

Các ví dụ dưới đây chạy từ root repo, nên luôn dùng đường dẫn đầy đủ tới script:

| Skill | Mục đích | Lệnh |
|---|---|---|
| `binary-identifier` | Nhận diện ngôn ngữ, compiler, packager | `python binary-identifier\scripts\identify_app.py target.exe` |
| `electron-builder-unpacker` | Bung app Electron/ASAR để audit offline | `python electron-builder-unpacker\scripts\unpack_electron_builder.py app-dir --out output\electron-unpacked` |
| `electron-app-analyzer` | Audit Electron main/preload/renderer/IPC | `python electron-app-analyzer\scripts\analyze_electron.py extracted-app --out output\electron-analysis` |
| `javascript-deobfuscator` | Khôi phục cấu trúc từ sourcemap được uỷ quyền | `python javascript-deobfuscator\scripts\extract_sourcemap.py "https://example.com/app.js.map" output\recovered-code` |
| `nuitka-decryptor` | Inventory Nuitka `.pyd` phục vụ phân tích phòng thủ | `python nuitka-decryptor\scripts\analyze_binary.py --pyd app.pyd --out output\nuitka-analysis.txt` |
| `android-apk-pentester` | Static audit APK/XAPK nội bộ | `python android-apk-pentester\scripts\analyze_apk.py app.apk --out output\apk-analysis` |
| `container-cloud-auditor` | Audit Docker/Kubernetes/Terraform/cloud config | `python container-cloud-auditor\scripts\analyze_container_cloud.py . --out output\container-cloud` |
| `sbom-supply-chain-auditor` | Audit manifests/lockfiles phụ thuộc | `python sbom-supply-chain-auditor\scripts\analyze_supply_chain.py . --out output\sbom` |
| `searching-exploit-db` | Tra CVE, EDB-ID hoặc sản phẩm trong Exploit-DB | `python searching-exploit-db\scripts\search_exploit_db.py --cve CVE-2021-44228` |
| `vulnerability-lookup` | Tra cứu đa nguồn CVE, CISA KEV, EPSS, NVD và GitHub PoC | `python vulnerability-lookup\scripts\lookup_vuln.py --cve CVE-2024-6387` |
| `orchestrator-plugin-sdk` | Validate contract của skill mới | `python orchestrator-plugin-sdk\scripts\validate_skill_contract.py container-cloud-auditor` |

## Cài vào CLI agent

Mỗi nền tảng có manifest trong [agents/](./agents/):

| Nền tảng | File | Cách dùng |
|---|---|---|
| Codex CLI | [agents/codex.yaml](./agents/codex.yaml) | Copy phần `prompt` vào slash command `re-master`, rồi chạy `/re-master <target>` |
| Gemini CLI | [agents/gemini.yaml](./agents/gemini.yaml) | Chuyển phần `prompt` sang `.gemini/commands/re-master.toml` |
| OpenAI Assistants/Responses | [agents/openai.yaml](./agents/openai.yaml) | Dùng `instructions` và function enum đã khai báo |

## Output

Workflow ghi artifact dưới thư mục `output/` hoặc thư mục truyền qua `--out`:

- `REPORT.md`: tóm tắt phạm vi, phương pháp, kết quả chính.
- `mission.json`: dữ liệu máy đọc được cho từng phase.
- `ARCHITECTURE.md`, `FINDINGS.md`, `REMEDIATION.md`: tạo khi workflow hoặc agent có đủ dữ liệu.
- `recovered-structure/`: cấu trúc nguồn khôi phục khi được uỷ quyền và có thể xác minh.

Giá trị nhạy cảm phải được redacted trong báo cáo; chỉ ghi vị trí và fingerprint khi cần điều tra nội bộ.
