from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from juicesecops.evaluation import evaluate_precision, summarize_findings
from juicesecops.models import (
    Finding,
    GateResult,
    Location,
    PipelineReport,
    Severity,
    TriageDecision,
)
from juicesecops.pipeline import run_pipeline
from juicesecops.policy import Policy
from juicesecops.providers import HeuristicProvider
from juicesecops.reporting import render_console_summary, write_report


def _run(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


class BrokenReviewProvider:
    name = "broken"
    model = "broken-model"

    def triage(self, finding: Finding, context: dict[str, str]) -> TriageDecision:
        del context
        return TriageDecision(
            finding_fingerprint=finding.fingerprint,
            disposition="accept",
            risk_score=0,
            true_positive_likelihood=finding.confidence,
            exploitability="unknown",
            summary="ok",
            rationale="ok",
            remediation=finding.remediation,
            provider=self.name,
            model=self.model,
            latency_ms=0.0,
        )

    def review_change(self, change, context):
        del change, context
        raise RuntimeError("review exploded")


class PipelineTests(unittest.TestCase):
    def test_pipeline_generates_report_and_blocks_secret(self):
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

    def test_pipeline_converts_review_provider_failure_into_gate_failure(self):
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

            target.write_text("eval(userInput)\n", encoding="utf-8")

            report_path = root / "generic.json"
            report_path.write_text(json.dumps({"findings": []}), encoding="utf-8")

            report = run_pipeline(
                inputs=[report_path],
                provider=BrokenReviewProvider(),
                policy=Policy(),
                target_repo=repo,
                review_changes=True,
            )

            self.assertFalse(report.gate.passed)
            self.assertIn("Change review provider failed", [f.title for f in report.findings])
            self.assertTrue(
                any(
                    decision.error == "RuntimeError: review exploded"
                    for decision in report.decisions
                )
            )

    def test_write_report_uses_url_when_path_is_missing(self):
        report = PipelineReport(
            schema_version="1.0",
            generated_at="2026-07-23T00:00:00+00:00",
            inputs=[],
            provider="heuristic",
            findings=[
                Finding(
                    tool="zap",
                    rule_id="10001",
                    title="Dynamic finding",
                    description="demo",
                    severity=Severity.LOW,
                    category="dynamic",
                    confidence=0.6,
                    location=Location(url="http://juice-shop.local/#/login"),
                )
            ],
            decisions=[],
            gate=GateResult(passed=True, reasons=[], blocked_fingerprints=[]),
        )
        ground_truth = [
            Finding(
                tool="ground-truth",
                rule_id="10001",
                title="Dynamic finding",
                description="verified",
                severity=Severity.LOW,
                category="dynamic",
                confidence=1.0,
                location=Location(url="http://juice-shop.local/#/login"),
                fingerprint="gt-dynamic",
            )
        ]
        report.metadata["finding_summary"] = summarize_findings(report.findings)
        report.metadata["precision_comparison"] = evaluate_precision(
            report.findings, ground_truth
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "out"
            write_report(output_dir, report)
            markdown = (output_dir / "report.md").read_text(encoding="utf-8")
            console = render_console_summary(report)
            self.assertIn("http://juice-shop.local/#/login", markdown)
            self.assertIn("### Traditional", markdown)
            self.assertIn("Precision Comparison", markdown)
            self.assertIn("Precision comparison against ground truth", console)


if __name__ == "__main__":
    unittest.main()
