import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "analyze_js.py"


def load_module():
    spec = importlib.util.spec_from_file_location("analyze_js", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AnalyzeJsTests(unittest.TestCase):
    def test_decodes_base64_and_extracts_redacted_endpoints(self):
        analyze_js = load_module()
        source = r'''
        const payload = "aHR0cHM6Ly9leGFtcGxlLmNvbS9hcGk=";
        fetch("/api/v1/users?token=abc123");
        eval(atob(payload));
        '''

        result = analyze_js.analyze_source(source, source_name="sample.js")
        as_json = json.dumps(result, sort_keys=True)

        self.assertIn("https://example.com/api", result["endpoints"])
        self.assertIn("/api/v1/users?token=<redacted>", result["endpoints"])
        self.assertNotIn("abc123", as_json)
        self.assertIn("eval", result["indicators"])
        self.assertIn("atob", result["indicators"])

    def test_decodes_js_escapes_before_endpoint_detection(self):
        analyze_js = load_module()
        source = r'var route = "\x2fadmin\u002flogin";'

        result = analyze_js.analyze_source(source, source_name="escapes.js")

        self.assertIn("/admin/login", result["endpoints"])

    def test_redacts_secret_like_values_from_strings(self):
        analyze_js = load_module()
        source = r'''
        const key = "sk_live_abcdefghijklmnopqrstuvwxyz123456";
        const cfg = "eyJhcGlLZXkiOiJzazFfdmVyeXNlY3JldHZhbHVlIn0=";
        '''

        result = analyze_js.analyze_source(source, source_name="secret.js")
        as_json = json.dumps(result, sort_keys=True)

        self.assertNotIn("sk_live_abcdefghijklmnopqrstuvwxyz123456", as_json)
        self.assertNotIn("sk1_verysecretvalue", as_json)
        self.assertIn("<redacted>", as_json)


if __name__ == "__main__":
    unittest.main()
