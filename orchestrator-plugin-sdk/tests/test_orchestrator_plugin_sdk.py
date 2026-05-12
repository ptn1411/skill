import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCAFFOLD = ROOT / "orchestrator-plugin-sdk" / "scripts" / "scaffold_skill.py"
VALIDATE = ROOT / "orchestrator-plugin-sdk" / "scripts" / "validate_skill_contract.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OrchestratorPluginSdkTests(unittest.TestCase):
    def test_scaffold_creates_minimal_valid_skill(self):
        scaffold = load_module(SCAFFOLD, "scaffold_skill")
        validate = load_module(VALIDATE, "validate_skill_contract")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            skill_dir = scaffold.scaffold_skill(root, "demo-auditor", "Demo auditor skill")
            result = validate.validate_skill(skill_dir)
            self.assertTrue((skill_dir / "SKILL.md").exists())
            self.assertTrue((skill_dir / "scripts").exists())
            self.assertEqual(result["errors"], [])


if __name__ == "__main__":
    unittest.main()
