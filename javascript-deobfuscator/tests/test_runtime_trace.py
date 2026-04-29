import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "runtime_trace.js"


class RuntimeTraceTests(unittest.TestCase):
    def test_redacts_sensitive_query_params_in_logged_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.js"
            output = Path(tmp) / "trace.json"
            sample.write_text('fetch("https://example.com/api?token=abc123&ok=1");', encoding="utf-8")

            subprocess.run(
                ["node", str(SCRIPT), str(sample), "--out", str(output)],
                check=True,
                capture_output=True,
                text=True,
            )
            trace = json.loads(output.read_text(encoding="utf-8"))
            as_json = json.dumps(trace, sort_keys=True)

            self.assertIn("token=<redacted>", as_json)
            self.assertIn("ok=1", as_json)
            self.assertNotIn("abc123", as_json)


if __name__ == "__main__":
    unittest.main()
