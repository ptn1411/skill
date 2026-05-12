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
| **IDA Pro + MCP** | ida-nuitka-reconstructor, binary-patcher | MCP server: `http://127.0.0.1:13337/mcp` — xem [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) |
| **pyinstxtractor-ng** | pyinstaller-unpacker | `pip install pyinstxtractor-ng` |
| **pycdc / uncompyle6** | pyinstaller-unpacker (decompile .pyc) | `pip install uncompyle6` / build [pycdc](https://github.com/zrax/pycdc) |
| **ilspycmd** | dotnet-decompiler | `dotnet tool install -g ilspycmd` |
| **de4dot** | dotnet-decompiler (deobfuscation) | https://github.com/de4dot/de4dot/releases |
| **dnSpyEx** | dotnet-decompiler, dotnet-patcher (GUI debugger + IL edit) | https://github.com/dnSpyEx/dnSpy/releases (GUI, Windows) |
| **peverify** | dotnet-patcher (verify patched assemblies) | Included with .NET SDK / Visual Studio |
| **pycryptodome** | dotnet-keygen (RSA-signed licenses) | `pip install pycryptodome` |
| **msieve / yafu** | dotnet-keygen (factor weak RSA keys) | https://sourceforge.net/projects/msieve/ |
| **mitmproxy** | network-interceptor | `pip install mitmproxy` |
| **ProcDump** | memory-dumper (Sysinternals) | https://learn.microsoft.com/sysinternals/downloads/procdump |
| **frida-tools** | frida-hooker | `pip install frida-tools` |
| **x64dbg** | binary-patcher | https://x64dbg.com (GUI, Windows) |
| **Ghidra** | binary-patcher (cross-arch) | https://ghidra-sre.org |
| **IDA Free** | binary-patcher | https://hex-rays.com/ida-free |
| **rustfilt** | rust-binary-analyzer (symbol demangling) | `pip install rustfilt` or `cargo install rustfilt` |
| **brotli** | tauri-unpacker (decompress embedded assets) | `pip install brotli` |
| **CFR** | java-decompiler (best overall decompiler) | Download [cfr.jar](https://github.com/leibnitz27/cfr/releases), set `CFR_JAR` env |
| **Procyon** | java-decompiler (complex generics) | Download [procyon-decompiler.jar](https://github.com/mstrobel/procyon/releases), set `PROCYON_JAR` env |
| **FernFlower** | java-decompiler (IntelliJ-style) | Download [fernflower.jar](https://github.com/fesh0r/fernflower/releases), set `FERNFLOWER_JAR` env |
| **JADX** | java-decompiler (best for Android APK) | https://github.com/skylot/jadx/releases |
| **dex2jar** | java-decompiler (DEX → JAR conversion) | https://github.com/pxb1988/dex2jar/releases |
| **Android SDK Platform Tools** | android-apk-pentester (adb install, root, remount, device control) | Android Studio SDK Manager or `winget install Google.PlatformTools` |
| **Android Emulator** | android-apk-pentester (AVD startup and lab device setup) | Android Studio SDK Manager |
| **bundletool.jar** | android-apk-pentester (`.apks` install) | https://github.com/google/bundletool/releases; set `BUNDLETOOL_JAR` |

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
