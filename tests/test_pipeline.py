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
from juicesecops.providers.base import RateLimitError
from juicesecops.reporting import render_console_summary, write_report


def _run(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


class FakeProvider:
    # Deterministic stand-in for a real SecurityProvider (GroqSecurityProvider,
    # OpenRouterSecurityProvider): exercises run_pipeline()'s
    # dedup/redaction/gate logic without a real model call.
    name = "fake"
    model = "fake-model"

    def triage(self, finding: Finding, context: dict[str, str]) -> TriageDecision:
        del context
        risk = 90 if finding.category == "secret" else 40
        return TriageDecision(
            finding_fingerprint=finding.fingerprint,
            disposition="block" if risk >= 70 else "accept",
            risk_score=risk,
            true_positive_likelihood=finding.confidence,
            exploitability="unknown",
            summary="fake triage",
            rationale="fake rationale",
            remediation=finding.remediation,
            provider=self.name,
            model=self.model,
            latency_ms=0.0,
        )

    def review_change(self, change, context):
        del context
        return [
            Finding(
                tool="llm-diff",
                rule_id="fake.rule",
                title="Fake LLM finding",
                description="Synthetic finding for pipeline tests",
                severity=Severity.HIGH,
                category="code",
                confidence=0.9,
                location=Location(path=change.path, line=1),
                remediation="Review the change.",
                fingerprint=f"fake-{change.path}",
            )
        ]


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


class RateLimitedReviewProvider:
    # Every review_change() call is rate-limited; used to prove run_pipeline
    # stops sending further review calls after the first one (rather than
    # hitting the limit again for every remaining changed file) and still
    # produces a report from whatever was gathered so far.
    name = "rate-limited"
    model = "rate-limited-model"

    def __init__(self) -> None:
        self.review_calls = 0

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
        self.review_calls += 1
        raise RateLimitError("rate limited")


class RateLimitedTriageProvider:
    # review_change() finds nothing; triage() is rate-limited on the first
    # finding. Used to prove the triage loop stops calling the provider for
    # every remaining finding once the limit is hit, instead of retrying it
    # once per finding.
    name = "rate-limited-triage"
    model = "rate-limited-triage-model"

    def __init__(self) -> None:
        self.triage_calls = 0

    def triage(self, finding: Finding, context: dict[str, str]) -> TriageDecision:
        del context
        self.triage_calls += 1
        if self.triage_calls == 1:
            raise RateLimitError("rate limited")
        raise AssertionError("triage() should not be called again after a rate limit")

    def review_change(self, change, context):
        del change, context
        return []


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
                provider=FakeProvider(),
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

    def test_rate_limit_during_review_stops_further_review_calls(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            repo.mkdir()
            _run(repo, "init")
            _run(repo, "config", "user.email", "test@example.com")
            _run(repo, "config", "user.name", "Tester")

            routes = repo / "routes"
            routes.mkdir()
            for name in ("a.ts", "b.ts", "c.ts"):
                (routes / name).write_text("export const ok = true\n", encoding="utf-8")
            _run(repo, "add", ".")
            _run(repo, "commit", "-m", "init")

            for name in ("a.ts", "b.ts", "c.ts"):
                (routes / name).write_text("export const changed = true\n", encoding="utf-8")

            report_path = root / "generic.json"
            report_path.write_text(json.dumps({"findings": []}), encoding="utf-8")

            provider = RateLimitedReviewProvider()
            report = run_pipeline(
                inputs=[report_path],
                provider=provider,
                policy=Policy(),
                target_repo=repo,
                review_changes=True,
            )

            # Three files changed, but review_change() should only be called
            # once: the run stops as soon as the rate limit is hit instead of
            # retrying it for every remaining file.
            self.assertEqual(provider.review_calls, 1)
            self.assertTrue(report.metadata["rate_limited"])
            self.assertIn(
                "Change review stopped: provider rate-limited",
                [f.title for f in report.findings],
            )
            self.assertFalse(report.gate.passed)

    def test_rate_limit_during_triage_stops_further_triage_calls(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "generic.json"
            report_path.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "tool": "demo",
                                "rule_id": f"manual-{i}",
                                "title": f"Finding {i}",
                                "description": "synthetic",
                                "severity": "medium",
                                "category": "code",
                                "location": {"path": f"file{i}.ts", "line": 1},
                            }
                            for i in range(3)
                        ]
                    }
                ),
                encoding="utf-8",
            )

            provider = RateLimitedTriageProvider()
            report = run_pipeline(
                inputs=[report_path],
                provider=provider,
                policy=Policy(),
                review_changes=False,
            )

            # Three findings, but triage() should only be called once: the
            # rest get a fail-closed decision without calling the provider.
            self.assertEqual(provider.triage_calls, 1)
            self.assertTrue(report.metadata["rate_limited"])
            self.assertEqual(len(report.decisions), 3)
            self.assertTrue(all(decision.error for decision in report.decisions))
            self.assertFalse(report.gate.passed)

    def test_finding_count_is_not_capped(self):
        self.assertFalse(hasattr(Policy(), "max_findings_per_run"))
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "generic.json"
            report_path.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "tool": "demo",
                                "rule_id": f"manual-{i}",
                                "title": f"Finding {i}",
                                "description": "synthetic",
                                "severity": "low",
                                "category": "code",
                                "location": {"path": f"file{i}.ts", "line": 1},
                            }
                            # One more than the old hardcoded 300-finding cap.
                            for i in range(301)
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = run_pipeline(
                inputs=[report_path],
                provider=FakeProvider(),
                policy=Policy(),
                review_changes=False,
            )

            self.assertEqual(len(report.findings), 301)

    def test_write_report_uses_url_when_path_is_missing(self):
        report = PipelineReport(
            schema_version="1.0",
            generated_at="2026-07-23T00:00:00+00:00",
            inputs=[],
            provider="groq",
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
