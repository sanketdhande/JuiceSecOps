from __future__ import annotations

import json
import tempfile
import subprocess
import unittest

from juicesecops.pipeline import run_pipeline
from juicesecops.policy import Policy
from juicesecops.providers import HeuristicProvider
from juicesecops.reporting import write_report


def _run(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


class PipelineTests(unittest.TestCase):
    def test_pipeline_generates_report_and_blocks_secret(self):
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            repo.mkdir()
            _run(repo, "init")
            _run(repo, "config", "user.email", "test@example.com")
            _run(repo, "config", "user.name", "Tester")

            routes = repo / "routes"
            routes.mkdir()
            target = routes / "payment.ts"
            target.write_text("export const ok = true\n", encoding="utf-8")
            _run(repo, "add", ".")
            _run(repo, "commit", "-m", "init")

            target.write_text('const jwtSecret = "weaksecret"\n', encoding="utf-8")

            report_path = root / "generic.json"
            report_path.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "tool": "demo",
                                "rule_id": "manual-1",
                                "title": "Known secret finding",
                                "description": "Synthetic secret finding",
                                "severity": "critical",
                                "category": "secret",
                                "location": {"path": "routes/payment.ts", "line": 1},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = run_pipeline(
                inputs=[report_path],
                provider=HeuristicProvider(),
                policy=Policy(),
                target_repo=repo,
                review_changes=True,
            )

            self.assertFalse(report.gate.passed)
            self.assertTrue(any(finding.tool == "llm-diff" for finding in report.findings))

            output_dir = root / "out"
            write_report(output_dir, report)
            self.assertTrue((output_dir / "report.json").exists())
            self.assertTrue((output_dir / "report.md").exists())


if __name__ == "__main__":
    unittest.main()
