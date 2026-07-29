from __future__ import annotations

import json
import unittest

from juicesecops.models import CodeChange, Finding, Location, Severity
from juicesecops.providers._prompted import PromptedLLMProvider, extract_json


class FakeProvider(PromptedLLMProvider):
    # Records the messages it was called with and returns a canned response,
    # so tests can inspect the prompt without a real model call.
    name = "fake"
    model = "fake-model"

    def __init__(self, response: str) -> None:
        self.response = response
        self.last_messages: list[dict[str, str]] | None = None
        self.last_max_tokens: int | None = None

    def _generate(self, messages: list[dict[str, str]], *, max_tokens: int | None = None) -> str:
        self.last_messages = messages
        self.last_max_tokens = max_tokens
        return self.response


class ExtractJsonTests(unittest.TestCase):
    def test_raises_on_prose_only_response(self):
        # This is exactly what a weaker model does when it decides there's
        # nothing to report but wasn't told what JSON shape to use for that.
        with self.assertRaises(ValueError):
            extract_json("No security vulnerabilities were found in this file.")

    def test_parses_fenced_json(self):
        result = extract_json('Sure, here you go:\n```json\n{"findings": []}\n```')
        self.assertEqual(result, {"findings": []})


class ReviewChangePromptTests(unittest.TestCase):
    def test_system_prompt_tells_model_what_to_return_for_no_findings(self):
        # Regression test: without this instruction, models that find
        # nothing tend to answer in prose instead of {"findings": []},
        # which extract_json() can't parse -- see ReviewChangeParsingTests.
        provider = FakeProvider(json.dumps({"findings": []}))
        change = CodeChange(path="lib/is-windows.ts", status="A", diff="", snippet="")
        provider.review_change(change, {})
        system_message = provider.last_messages[0]["content"]
        self.assertIn('{"findings": []}', system_message)

    def test_review_change_requests_a_larger_token_budget_than_triage(self):
        # Regression test: review_change()'s schema can hold several
        # findings with multiple free-text fields each, so it needs much
        # more room than triage()'s single flat object -- underprovisioning
        # this caused real responses to be cut off mid-JSON on large diffs
        # (see PromptedLLMProvider.review_max_tokens).
        provider = FakeProvider(json.dumps({"findings": []}))
        change = CodeChange(path="lib/is-windows.ts", status="A", diff="", snippet="")
        provider.review_change(change, {})
        self.assertEqual(provider.last_max_tokens, PromptedLLMProvider.review_max_tokens)
        self.assertGreater(provider.last_max_tokens, 256)


class TriagePromptTests(unittest.TestCase):
    def test_system_prompt_requires_json_only_response(self):
        provider = FakeProvider(
            json.dumps(
                {
                    "disposition": "accept",
                    "risk_score": 0,
                    "true_positive_likelihood": 0.1,
                    "exploitability": "unlikely",
                    "summary": "ok",
                    "rationale": "ok",
                    "remediation": "none",
                }
            )
        )
        finding = Finding(
            tool="demo",
            rule_id="r1",
            title="t",
            description="d",
            severity=Severity.LOW,
            location=Location(path="x.ts"),
        )
        provider.triage(finding, {})
        system_message = provider.last_messages[0]["content"]
        self.assertIn("nothing else", system_message)


if __name__ == "__main__":
    unittest.main()
