import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "unpack_electron_builder.py"


def load_module():
    spec = importlib.util.spec_from_file_location("unpack_electron_builder", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_pickle_string(text: str) -> bytes:
    raw = text.encode("utf-8")
    payload = struct.pack("<I", len(raw)) + raw
    payload += b"\x00" * ((4 - (len(payload) % 4)) % 4)
    return struct.pack("<I", len(payload)) + payload


def make_fake_asar(files: dict[str, bytes]) -> bytes:
    offset = 0
    header_files = {}
    data = bytearray()
    for name, content in files.items():
        header_files[name] = {"size": len(content), "offset": str(offset)}
        data.extend(content)
        offset += len(content)

    header = json.dumps({"files": header_files}, separators=(",", ":"))
    header_pickle = make_pickle_string(header)
    size_pickle = struct.pack("<II", 4, len(header_pickle))
    return size_pickle + header_pickle + bytes(data)


class ElectronBuilderUnpackerTests(unittest.TestCase):
    def test_extracts_app_asar_and_writes_manifest(self):
        unpacker = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "SampleApp"
            resources = root / "resources"
            resources.mkdir(parents=True)
            (resources / "app.asar").write_bytes(
                make_fake_asar(
                    {
                        "package.json": b'{"name":"sample","main":"main.js"}',
                        "main.js": b"console.log('hello');",
                    }
                )
            )
            out_dir = Path(tmp) / "out"

            result = unpacker.unpack_path(root, out_dir)

            self.assertIn("resources/app.asar", result["asar_archives"])
            extracted_root = out_dir / "app_asar"
            self.assertTrue((extracted_root / "package.json").exists())
            self.assertEqual((extracted_root / "main.js").read_text(encoding="utf-8"), "console.log('hello');")
            self.assertTrue((out_dir / "unpack_manifest.json").exists())

    def test_records_unpacked_dir_and_update_config(self):
        unpacker = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "SampleApp"
            resources = root / "resources"
            unpacked = resources / "app.asar.unpacked"
            unpacked.mkdir(parents=True)
            (unpacked / "native.node").write_bytes(b"MZ")
            (root / "app-update.yml").write_text("url: https://updates.example.com/app\n", encoding="utf-8")
            out_dir = Path(tmp) / "out"

            result = unpacker.unpack_path(root, out_dir)

            self.assertIn("resources/app.asar.unpacked", result["unpacked_dirs"])
            self.assertIn("app-update.yml", result["update_configs"])
            self.assertTrue((out_dir / "unpacked" / "resources" / "app.asar.unpacked" / "native.node").exists())


if __name__ == "__main__":
    unittest.main()
