# External Tooling Manifest

Các sub-skill phụ thuộc vào tooling **bên ngoài Python**. Cài trước khi chạy orchestrator hoặc gọi từng skill riêng.

## Bắt buộc

| Tool | Phục vụ skill | Cài đặt (Windows) | Cài đặt (Linux/macOS) |
|---|---|---|---|
| **Node.js ≥ 18** | electron-* (ASAR) | `winget install OpenJS.NodeJS.LTS` | `brew install node` / `apt install nodejs` |
| **@electron/asar** | electron-builder-unpacker, electron-builder-repacker | `npm install -g @electron/asar` | same |
| **UPX** | binary-identifier, binary-patcher | `winget install UPX.UPX` | `apt install upx-ucl` / `brew install upx` |
| **Python ≥ 3.10** | tất cả | `winget install Python.Python.3.12` | distro pkg manager |

## Khuyến nghị (workflow Native RE)

| Tool | Phục vụ | Ghi chú |
|---|---|---|
| **pyinstxtractor** | binary-identifier (Python PyInstaller) | `pip install pyinstxtractor-ng` |
| **dnSpyEx** | binary-identifier (.NET) | https://github.com/dnSpyEx/dnSpy/releases (GUI, Windows) |
| **x64dbg** | binary-patcher | https://x64dbg.com (GUI, Windows) |
| **Ghidra** | binary-patcher (cross-arch) | https://ghidra-sre.org |
| **IDA Free** | binary-patcher | https://hex-rays.com/ida-free |

## Tự kiểm tra

Chạy script kiểm tra sau khi cài để verify môi trường:

```powershell
# PowerShell
python --version
node --version
npx asar --version
upx --version
pip show requests pyyaml
```

```bash
# bash / WSL / Linux / macOS
python3 --version && node --version && npx asar --version && upx --version
pip show requests pyyaml
```

Nếu thiếu tool nào, sub-skill tương ứng sẽ báo lỗi rõ ràng và pivot sang phương pháp thay thế (theo MASTER_POLICY.md "Persistent Execution").
