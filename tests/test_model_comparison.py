from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from juicesecops.model_comparison import build_model_comparison, load_pipeline_report
from juicesecops.models import (
    Finding,
    GateResult,
    Location,
    PipelineReport,
    Severity,
    TriageDecision,
)
from juicesecops.reporting import write_report


def _make_report(model: str, disposition: str) -> PipelineReport:
    finding = Finding(
        tool="llm-diff",
        rule_id="r1",
        title="Issue",
        description="d",
        severity=Severity.HIGH,
        category="code",
        confidence=0.9,
        location=Location(path="routes/x.ts", line=1),
        fingerprint=f"fp-{model}",
        metadata={"source": "diff-review", "provider": "gguf", "model": model},
    )
    decision = TriageDecision(
        finding_fingerprint=finding.fingerprint,
        disposition=disposition,
        risk_score=80,
        true_positive_likelihood=0.8,
        exploitability="likely",
        summary="s",
        rationale="r",
        remediation="fix it",
        provider="gguf",
        model=model,
        latency_ms=12.0,
    )
    return PipelineReport(
        schema_version="1.0",
        generated_at="now",
        inputs=[],
        provider="gguf",
        findings=[finding],
        decisions=[decision],
        gate=GateResult(passed=disposition != "block", reasons=[], blocked_fingerprints=[]),
        changes=[],
        metadata={"duration_ms": 1.0},
    )


class ModelComparisonTests(unittest.TestCase):
    def test_round_trip_preserves_fingerprint_and_disposition(self):
        # Regression test: load_pipeline_report must NOT recompute Finding
        # fingerprints on load, or every TriageDecision lookup by
        # fingerprint silently breaks (dispositions all show "unknown").
        with TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "run"
            write_report(output, _make_report("model-a", "block"))
            loaded = load_pipeline_report(output / "report.json")

        self.assertEqual(len(loaded["findings"]), 1)
        self.assertEqual(loaded["findings"][0].fingerprint, "fp-model-a")
        self.assertEqual(loaded["decisions"][0].finding_fingerprint, "fp-model-a")

    def test_build_model_comparison_merges_traditional_once_and_keeps_llm_per_model(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_report(root / "a", _make_report("model-a", "block"))
            write_report(root / "b", _make_report("model-b", "review"))
            runs = {
                "model-a": load_pipeline_report(root / "a" / "report.json"),
                "model-b": load_pipeline_report(root / "b" / "report.json"),
            }

        comparison = build_model_comparison(runs)

        self.assertEqual(comparison["models"]["model-a"]["dispositions"], {"block": 1})
        self.assertEqual(comparison["models"]["model-b"]["dispositions"], {"review": 1})
        self.assertEqual(comparison["models"]["model-a"]["model"], "model-a")
        self.assertTrue(comparison["models"]["model-a"]["gate_passed"] is False)
        self.assertTrue(comparison["models"]["model-b"]["gate_passed"] is True)


if __name__ == "__main__":
    unittest.main()
