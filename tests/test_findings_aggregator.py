"""Tests for scripts/findings_aggregator.py and scripts/validate_findings.py.

Covers the verdict discipline added from the Cloudflare security-audit method
(scanner hits become `needs_validation` candidates; severity only on confirmed)
as well as the standalone report-envelope contract (`schema_version == "1.0"`,
`target`, `findings` with `F-NNN` IDs and `trust_boundary`).
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
TEST_SAMPLE = ROOT / "test-sample"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


agg = _load("findings_aggregator")
vf = _load("validate_findings")


class AggregatorTests(unittest.TestCase):
    def _make_out(self, tmp):
        out = Path(tmp)
        (out / "container-cloud-auditor").mkdir(parents=True)
        (out / "license-audit").mkdir(parents=True)
        (out / "container-cloud-auditor" / "findings.json").write_text(json.dumps({
            "findings": [{"id": "CC-1", "severity": "high", "category": "privileged",
                          "title": "Privileged container", "file": "compose.yml",
                          "line": 3, "evidence": "privileged: true",
                          "recommendation": "drop it"}]
        }), encoding="utf-8")
        (out / "license-audit" / "license_findings.json").write_text(json.dumps({
            "findings": [{"file": "L.cs", "line": 9, "severity": "medium",
                          "category": "client-check", "title": "Client-side license",
                          "why": "patchable", "fix": "server entitlement"}]
        }), encoding="utf-8")
        return out

    def test_harvest_marks_everything_needs_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self._make_out(tmp)
            findings = agg.harvest(out)
            self.assertEqual(len(findings), 2)
            self.assertTrue(all(f["verdict"] == "needs_validation" for f in findings))
            # No authoritative severity is ever emitted by the aggregator.
            self.assertTrue(all("severity" not in f for f in findings))
            self.assertTrue(all("candidate_severity" in f for f in findings))

    def test_output_validates_against_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self._make_out(tmp)
            path, summary = agg.write_findings(out)
            self.assertTrue(path.exists())
            self.assertEqual(summary["by_verdict"]["needs_validation"], 2)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(vf.validate(data), [])

    def test_fingerprint_stable_and_schema_safe(self):
        fp1 = agg._fingerprint("skill", "cat", "A/B.cs", 5, "title")
        fp2 = agg._fingerprint("skill", "cat", "a\\b.cs", 5, "title")
        self.assertEqual(fp1, fp2)  # path normalization → same fingerprint
        self.assertRegex(fp1, vf.FP_RE)


class ValidatorTests(unittest.TestCase):
    def test_needs_validation_with_severity_rejected(self):
        rec = [{"verdict": "needs_validation", "fingerprint": "a:1", "skill": "s",
                "title": "t", "category": "c", "severity": "high",
                "location": {"file": "f"}, "missing_fact": "m", "validation_plan": "p"}]
        self.assertTrue(any("severity" in e for e in vf.validate(rec)))

    def test_confirmed_requires_boundary_and_trace(self):
        rec = [{"verdict": "confirmed", "fingerprint": "a:1", "skill": "s", "title": "t",
                "category": "c", "severity": "high", "evidence": ["e"], "fix": "f"}]
        errs = vf.validate(rec)
        self.assertTrue(any("boundary" in e for e in errs))
        self.assertTrue(any("trace" in e for e in errs))

    def test_valid_confirmed_passes(self):
        rec = [{"verdict": "confirmed", "fingerprint": "idor:1", "skill": "s",
                "title": "t", "category": "access-control", "severity": "high",
                "boundary": {"principal": "A", "input": "id", "control": "ownership",
                             "affected": "B", "result": "A reads B"},
                "trace": [{"kind": "sink", "file": "db.js", "line": 5, "description": "no filter"}],
                "evidence": ["db.js:5"], "root_cause": "no scoping", "fix": "add filter"}]
        self.assertEqual(vf.validate(rec), [])

    def test_bad_verdict_rejected(self):
        rec = [{"verdict": "banana", "fingerprint": "a:1", "skill": "s",
                "title": "t", "category": "c"}]
        self.assertTrue(any("verdict" in e for e in vf.validate(rec)))

    def test_envelope_sample_valid_and_bad_invalid(self):
        if not TEST_SAMPLE.exists():
            self.skipTest("test-sample directory not present")
        good = json.loads((TEST_SAMPLE / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(vf.validate(good), [])
        bad = json.loads((TEST_SAMPLE / "findings-bad.json").read_text(encoding="utf-8"))
        errs = vf.validate(bad)
        self.assertEqual(len(errs), 2)
        self.assertTrue(any("severity" in e for e in errs))
        self.assertTrue(any("duplicate id" in e for e in errs))

    def test_envelope_rejects_unknown_fields(self):
        env = {
            "schema_version": "1.0",
            "target": "sample-app.js",
            "extra_top": True,
            "findings": [
                {
                    "id": "F-001",
                    "title": "t",
                    "verdict": "rejected",
                    "trust_boundary": "renderer -> main",
                    "reason": "not reachable",
                    "extra_nested": 123,
                }
            ],
        }
        errs = vf.validate(env)
        self.assertTrue(any("unknown top-level field" in e for e in errs))
        self.assertTrue(any("unknown field 'extra_nested'" in e for e in errs))


if __name__ == "__main__":
    unittest.main()
