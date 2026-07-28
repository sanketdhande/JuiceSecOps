from __future__ import annotations

import json
import sys
import types
import unittest
from unittest import mock

from juicesecops.models import CodeChange, Finding, Location, Severity
from juicesecops.providers.huggingface import DEFAULT_MODEL, HuggingFaceSecurityProvider


class DefaultModelTests(unittest.TestCase):
    def test_default_model_is_gpt_oss_20b(self):
        self.assertEqual(DEFAULT_MODEL, "openai/gpt-oss-20b")
        self.assertEqual(HuggingFaceSecurityProvider().model, DEFAULT_MODEL)


def _fake_pipe(response_content: str):
    def pipe(messages, max_new_tokens):
        del messages, max_new_tokens
        return [{"generated_text": [{"role": "assistant", "content": response_content}]}]

    return pipe


def _stub_transformers_module(pipeline_factory) -> types.ModuleType:
    # `_load_pipe()` does `from transformers import pipeline` lazily, so the
    # real `transformers`/`torch` packages don't need to be installed to
    # unit-test the surrounding logic -- inject a stand-in module into
    # sys.modules instead.
    module = types.ModuleType("transformers")
    module.pipeline = pipeline_factory
    return module


class GenerateTests(unittest.TestCase):
    def test_generate_loads_pipeline_with_expected_arguments_and_caches_it(self):
        provider = HuggingFaceSecurityProvider()
        fake_pipeline_factory = mock.MagicMock(return_value=_fake_pipe("hello"))
        with mock.patch.dict(
            sys.modules, {"transformers": _stub_transformers_module(fake_pipeline_factory)}
        ):
            result = provider._generate([{"role": "user", "content": "hi"}])
            provider._generate([{"role": "user", "content": "hi again"}])

        self.assertEqual(result, "hello")
        fake_pipeline_factory.assert_called_once_with(
            "text-generation",
            model="openai/gpt-oss-20b",
            torch_dtype="auto",
            device_map="auto",
        )

    def test_triage_parses_json_from_generated_text(self):
        provider = HuggingFaceSecurityProvider()
        payload = {
            "disposition": "block",
            "risk_score": 91,
            "true_positive_likelihood": 0.8,
            "exploitability": "likely",
            "summary": "s",
            "rationale": "r",
            "remediation": "fix it",
        }
        finding = Finding(
            tool="semgrep",
            rule_id="r1",
            title="Hardcoded secret",
            description="d",
            severity=Severity.HIGH,
            category="secret",
            confidence=0.7,
            location=Location(path="routes/x.ts", line=1),
            fingerprint="fp-1",
        )
        stub = _stub_transformers_module(
            mock.MagicMock(return_value=_fake_pipe(json.dumps(payload)))
        )
        with mock.patch.dict(sys.modules, {"transformers": stub}):
            decision = provider.triage(finding, context={})

        self.assertEqual(decision.disposition, "block")
        self.assertEqual(decision.risk_score, 91)
        self.assertEqual(decision.provider, "huggingface")
        self.assertEqual(decision.model, "openai/gpt-oss-20b")

    def test_review_change_tags_findings_with_provider_and_model(self):
        provider = HuggingFaceSecurityProvider()
        payload = {
            "findings": [
                {
                    "tool": "llm-diff",
                    "rule_id": "llm.sqli",
                    "title": "Possible SQL injection",
                    "description": "d",
                    "severity": "high",
                    "category": "code",
                    "confidence": 0.8,
                    "location": {"path": "routes/x.ts", "line": 2, "url": ""},
                    "cwe": ["CWE-89"],
                    "remediation": "parameterize",
                    "evidence": "evidence",
                }
            ]
        }
        change = CodeChange(path="routes/x.ts", status="modified", diff="+ sql")
        stub = _stub_transformers_module(
            mock.MagicMock(return_value=_fake_pipe(json.dumps(payload)))
        )
        with mock.patch.dict(sys.modules, {"transformers": stub}):
            findings = provider.review_change(change, context={})

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metadata["provider"], "huggingface")
        self.assertEqual(findings[0].metadata["model"], "openai/gpt-oss-20b")


if __name__ == "__main__":
    unittest.main()
