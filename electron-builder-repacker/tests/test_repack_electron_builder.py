import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "repack_electron_builder.py"
UNPACKER_PATH = ROOT.parents[0] / "electron-builder-unpacker" / "scripts" / "unpack_electron_builder.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ElectronBuilderRepackerTests(unittest.TestCase):
    def test_packs_directory_as_asar_that_unpacker_can_read(self):
        repacker = load_module(MODULE_PATH, "repack_electron_builder")
        unpacker = load_module(UNPACKER_PATH, "unpack_electron_builder")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "app"
            source.mkdir()
            (source / "package.json").write_text('{"name":"sample","main":"main.js"}', encoding="utf-8")
            (source / "main.js").write_text("console.log('ok');", encoding="utf-8")
            nested = source / "renderer"
            nested.mkdir()
            (nested / "index.html").write_text("<h1>ok</h1>", encoding="utf-8")
            asar = Path(tmp) / "app.asar"

            result = repacker.pack_asar(source, asar)
            extracted = Path(tmp) / "extract"
            unpacker.extract_asar(asar, extracted)

            self.assertEqual(result["files"], 3)
            self.assertEqual((extracted / "main.js").read_text(encoding="utf-8"), "console.log('ok');")
            self.assertEqual((extracted / "renderer" / "index.html").read_text(encoding="utf-8"), "<h1>ok</h1>")

    def test_stage_resources_copies_asar_and_unpacked_dir(self):
        repacker = load_module(MODULE_PATH, "repack_electron_builder")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "app"
            source.mkdir()
            (source / "package.json").write_text('{"name":"sample"}', encoding="utf-8")
            unpacked = Path(tmp) / "app.asar.unpacked"
            unpacked.mkdir()
            (unpacked / "native.node").write_bytes(b"MZ")
            out = Path(tmp) / "stage"

            result = repacker.repack_path(source, out, unpacked_dir=unpacked)

            self.assertTrue((out / "resources" / "app.asar").exists())
            self.assertTrue((out / "resources" / "app.asar.unpacked" / "native.node").exists())
            self.assertTrue((out / "repack_manifest.json").exists())
            self.assertEqual(result["mode"], "asar-stage")


if __name__ == "__main__":
    unittest.main()
