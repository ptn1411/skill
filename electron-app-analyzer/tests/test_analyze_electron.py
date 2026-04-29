import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "analyze_electron.py"


def load_module():
    spec = importlib.util.spec_from_file_location("analyze_electron", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ElectronAnalyzerTests(unittest.TestCase):
    def test_detects_insecure_browserwindow_settings_and_redacts_urls(self):
        analyze_electron = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"name": "sample", "main": "main.js", "dependencies": {"electron": "^28.0.0"}}),
                encoding="utf-8",
            )
            (root / "main.js").write_text(
                """
                const { BrowserWindow } = require('electron');
                new BrowserWindow({
                  webPreferences: {
                    nodeIntegration: true,
                    contextIsolation: false,
                    enableRemoteModule: true,
                    preload: __dirname + '/preload.js'
                  }
                });
                fetch("https://api.example.com/v1/users?token=abc123");
                """,
                encoding="utf-8",
            )
            (root / "preload.js").write_text(
                "const { contextBridge, ipcRenderer } = require('electron'); window.api = ipcRenderer;",
                encoding="utf-8",
            )

            result = analyze_electron.analyze_path(root)
            as_json = json.dumps(result, sort_keys=True)

            self.assertIn("package.json", result["files"])
            self.assertIn("nodeIntegration enabled", result["findings"])
            self.assertIn("contextIsolation disabled", result["findings"])
            self.assertIn("enableRemoteModule enabled", result["findings"])
            self.assertIn("ipcRenderer exposed broadly", result["findings"])
            self.assertIn("https://api.example.com/v1/users?token=<redacted>", result["endpoints"])
            self.assertNotIn("abc123", as_json)

    def test_detects_asar_and_update_config(self):
        analyze_electron = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.asar").write_bytes(b"not a real asar")
            (root / "app-update.yml").write_text("provider: generic\nurl: https://updates.example.com/app\n", encoding="utf-8")

            result = analyze_electron.analyze_path(root)

            self.assertIn("app.asar", result["artifacts"])
            self.assertIn("auto-update config", result["findings"])
            self.assertIn("https://updates.example.com/app", result["endpoints"])


if __name__ == "__main__":
    unittest.main()
