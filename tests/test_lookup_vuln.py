"""Root integration test for vulnerability-lookup tool."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "vulnerability-lookup" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from lookup_vuln import (
    normalize_cve,
    normalize_ip,
    parse_cisa_kev,
    parse_first_epss,
    parse_nvd_response,
    parse_github_poc,
    parse_shodan_internetdb,
    format_markdown,
)


class TestRootVulnerabilityLookup(unittest.TestCase):
    def test_normalize_cve(self):
        self.assertEqual(normalize_cve("cve-2024-6387"), "CVE-2024-6387")
        self.assertEqual(normalize_cve("2021-44228"), "CVE-2021-44228")

    def test_parse_cisa_kev(self):
        sample = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-6387",
                    "vendorProject": "OpenSSH",
                    "product": "OpenSSH",
                    "dateAdded": "2024-07-08",
                    "dueDate": "2024-07-29",
                    "knownRansomwareCampaignUse": "Known",
                }
            ]
        }
        res = parse_cisa_kev(sample, "CVE-2024-6387")
        self.assertTrue(res["in_kev"])
        self.assertEqual(res["product"], "OpenSSH")

    def test_parse_first_epss(self):
        sample = {
            "data": [
                {
                    "cve": "CVE-2024-6387",
                    "epss": "0.99506",
                    "percentile": "0.99943",
                    "date": "2026-09-05",
                }
            ]
        }
        res = parse_first_epss(sample)
        self.assertIsNotNone(res)
        self.assertAlmostEqual(res["epss_score"], 0.99506, places=4)

    def test_parse_nvd(self):
        sample = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-6387",
                        "descriptions": [{"lang": "en", "value": "Test desc"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 8.1,
                                        "baseSeverity": "HIGH",
                                        "vectorString": "CVSS:3.1/...",
                                    }
                                }
                            ]
                        },
                        "weaknesses": [
                            {"description": [{"value": "CWE-362"}]}
                        ],
                    }
                }
            ]
        }
        res = parse_nvd_response(sample)
        self.assertEqual(res["cvss_score"], 8.1)
        self.assertIn("CWE-362", res["cwes"])

    def test_normalize_ip(self):
        self.assertEqual(normalize_ip("1.1.1.1"), "1.1.1.1")
        self.assertEqual(normalize_ip("8.8.8.8"), "8.8.8.8")

    def test_parse_shodan_internetdb(self):
        sample = {
            "ip": "1.1.1.1",
            "ports": [53, 80, 443],
            "cves": ["CVE-2021-44228"],
        }
        res = parse_shodan_internetdb(sample)
        self.assertEqual(res["ip"], "1.1.1.1")
        self.assertEqual(res["ports"], [53, 80, 443])
        self.assertIn("CVE-2021-44228", res["cves"])
        self.assertEqual(res["shodan_url"], "https://www.shodan.io/host/1.1.1.1")


if __name__ == "__main__":
    unittest.main()
