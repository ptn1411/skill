import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "sbom-supply-chain-auditor" / "scripts" / "analyze_supply_chain.py"


def load_module():
    spec = importlib.util.spec_from_file_location("analyze_supply_chain", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SupplyChainAuditorTests(unittest.TestCase):
    def test_detects_npm_install_script_and_unpinned_pip_requirement(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package.json").write_text(
                '{"scripts":{"postinstall":"node install.js"},"dependencies":{"left-pad":"latest"}}',
                encoding="utf-8",
            )
            (root / "requirements.txt").write_text("requests\nflask==3.0.0\n", encoding="utf-8")
            result = module.analyze_path(root)

        titles = {finding["title"] for finding in result["findings"]}
        self.assertIn("Package install script present", titles)
        self.assertIn("Unpinned Python requirement", titles)
        self.assertIn("Floating npm dependency version", titles)
        self.assertEqual(result["skill"], "sbom-supply-chain-auditor")


if __name__ == "__main__":
    unittest.main()
