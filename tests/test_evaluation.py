from __future__ import annotations

import unittest

from juicesecops.evaluation import evaluate_precision, summarize_findings
from juicesecops.models import Finding, Location, Severity


class EvaluationTests(unittest.TestCase):
    def test_summarize_findings_splits_llm_and_traditional(self):
        findings = [
            Finding(
                tool="semgrep",
                rule_id="rule-1",
                title="Traditional finding",
                description="demo",
                severity=Severity.HIGH,
                category="code",
                location=Location(path="routes/login.ts", line=10),
                fingerprint="trad-1",
            ),
            Finding(
                tool="llm-diff",
                rule_id="llm-1",
                title="LLM finding",
                description="demo",
                severity=Severity.MEDIUM,
                category="code",
                location=Location(path="routes/login.ts", line=11),
                fingerprint="llm-1",
            ),
        ]

        summary = summarize_findings(findings)

        self.assertEqual(summary["traditional"]["count"], 1)
        self.assertEqual(summary["llm"]["count"], 1)
        self.assertEqual(summary["traditional"]["tools"]["semgrep"], 1)
        self.assertEqual(summary["llm"]["tools"]["llm-diff"], 1)

    def test_evaluate_precision_compares_sources_against_ground_truth(self):
        findings = [
            Finding(
                tool="semgrep",
                rule_id="rule-1",
                title="SQL injection",
                description="demo",
                severity=Severity.HIGH,
                category="code",
                location=Location(path="routes/login.ts", line=42),
                cwe=["CWE-89"],
                fingerprint="trad-match",
            ),
            Finding(
                tool="zap",
                rule_id="rule-2",
                title="Header missing",
                description="demo",
                severity=Severity.LOW,
                category="dynamic",
                location=Location(url="http://juice-shop.local/"),
                fingerprint="trad-miss",
            ),
            Finding(
                tool="llm-diff",
                rule_id="llm-1",
                title="Potential DOM XSS",
                description="demo",
                severity=Severity.HIGH,
                category="code",
                location=Location(path="frontend/src/app.ts", line=12),
                cwe=["CWE-79"],
                fingerprint="llm-match",
            ),
        ]
        ground_truth = [
            Finding(
                tool="ground-truth",
                rule_id="rule-1",
                title="SQL injection",
                description="verified",
                severity=Severity.HIGH,
                category="code",
                location=Location(path="routes/login.ts", line=42),
                cwe=["CWE-89"],
                fingerprint="gt-1",
            ),
            Finding(
                tool="ground-truth",
                rule_id="manual-xss",
                title="Potential DOM XSS",
                description="verified",
                severity=Severity.HIGH,
                category="code",
                location=Location(path="frontend/src/app.ts", line=12),
                cwe=["CWE-79"],
                fingerprint="gt-2",
            ),
        ]

        metrics = evaluate_precision(findings, ground_truth)

        self.assertEqual(metrics["overall"]["matched_count"], 2)
        self.assertEqual(metrics["overall"]["predicted_count"], 3)
        self.assertEqual(metrics["overall"]["precision"], 0.667)
        self.assertEqual(metrics["sources"]["traditional"]["precision"], 0.5)
        self.assertEqual(metrics["sources"]["llm"]["precision"], 1.0)
