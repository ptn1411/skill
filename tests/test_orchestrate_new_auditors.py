import importlib.util
import subprocess
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

    def test_cli_rejects_missing_local_target(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            missing = root / "missing.exe"
            out_dir = root / "out"

            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(missing), "--out", str(out_dir)],
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

            self.assertEqual(2, proc.returncode)
            self.assertIn("Target does not exist", proc.stderr)
            self.assertFalse((out_dir / "REPORT.md").exists())

    def test_cli_help_stays_defensive(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

        self.assertEqual(0, proc.returncode)
        self.assertNotIn("--unlock", proc.stdout)
        self.assertNotIn("--export", proc.stdout)
        self.assertIn("--out", proc.stdout)

    def test_agent_commands_stay_defensive(self):
        risky_terms = (
            "keygen",
            "bypass",
            "unlock",
            "code injection",
            "full owner authorization",
            "unlimited",
        )

        for path in (ROOT / "agents").glob("*.yaml"):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8").lower()
                for term in risky_terms:
                    self.assertNotIn(term, text)

    def test_master_policy_matches_defensive_scope(self):
        text = (ROOT / "MASTER_POLICY.md").read_text(encoding="utf-8").lower()

        risky_grants = (
            "standing authorization",
            "full technical authority",
            "produce cracked",
            "generate keygen scripts",
            "and patch loaders against",
            "injects new behavior",
            "mission ends only when the owner has the code and the key",
        )

        for phrase in risky_grants:
            with self.subTest(phrase=phrase):
                self.assertNotIn(phrase, text)

        self.assertIn("defensive", text)
        self.assertIn("does not authorize", text)

    def test_root_skill_handles_authorization_without_blanket_refusal(self):
        text = (ROOT / "SKILL.md").read_text(encoding="utf-8")

        self.assertIn("When the user states they are authorized", text)
        self.assertIn("continue with defensive analysis", text)
        self.assertNotIn("I cannot help weaken licensing enforcement.", text)


if __name__ == "__main__":
    unittest.main()
