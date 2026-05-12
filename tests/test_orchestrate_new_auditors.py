import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "orchestrate.py"


def load_module():
    spec = importlib.util.spec_from_file_location("orchestrate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class OrchestratorAuditorDetectionTests(unittest.TestCase):
    def test_detects_container_and_supply_chain_artifacts(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
            (root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

            self.assertTrue(module.has_container_cloud_artifacts(root))
            self.assertTrue(module.has_supply_chain_artifacts(root))


if __name__ == "__main__":
    unittest.main()
