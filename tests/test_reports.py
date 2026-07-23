from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from juicesecops.models import Severity
from juicesecops.parsers import load_findings


class ReportParserTests(unittest.TestCase):
    def test_load_semgrep_report(self):
        with self.subTest("semgrep"), TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "semgrep.json"
            path.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "rule-1",
                                "path": "routes/test.ts",
                                "start": {"line": 12},
                                "extra": {
                                    "severity": "HIGH",
                                    "message": "example",
                                    "lines": "eval(userInput)",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            findings = load_findings(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, Severity.HIGH)
            self.assertEqual(findings[0].location.path, "routes/test.ts")

    def test_load_trivy_report(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "trivy.json"
            path.write_text(
                json.dumps(
                    {
                        "Results": [
                            {
                                "Target": "package-lock.json",
                                "Vulnerabilities": [
                                    {
                                        "VulnerabilityID": "CVE-1",
                                        "Severity": "CRITICAL",
                                        "PkgName": "demo",
                                    }
                                ]
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            findings = load_findings(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, Severity.CRITICAL)
            self.assertEqual(findings[0].category, "dependency")


if __name__ == "__main__":
    unittest.main()
