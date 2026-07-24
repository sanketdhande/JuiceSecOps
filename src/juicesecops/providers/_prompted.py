from __future__ import annotations

# Shared triage()/review_change() implementation for any provider that talks
# to a chat-style LLM (system + user messages in, JSON text out). Both
# HuggingFaceSecurityProvider (transformers, huggingface.py) and
# GgufSecurityProvider (llama.cpp, gguf.py) subclass this -- they only
# implement _generate(messages) -> raw model text, so every LLM-backed
# provider asks the same questions and gets parsed/scored the same way.
import json
import re
import time
from abc import ABC, abstractmethod
from dataclasses import asdict
from typing import Any

from ..models import CodeChange, Finding, TriageDecision
from ..parsers import finding_from_mapping


def extract_json(text: str) -> Any:
    fenced = re.findall(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    candidates = fenced or [text]
    for candidate in candidates:
        candidate = candidate.strip()
        for start_char, end_char in (("{", "}"), ("[", "]")):
            start = candidate.find(start_char)
            end = candidate.rfind(end_char)
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(candidate[start : end + 1])
                except json.JSONDecodeError:
                    continue
    raise ValueError("Model output did not contain valid JSON")


class PromptedLLMProvider(ABC):
    """Base for providers that score/triage findings via a chat-style LLM.

    Subclasses set `name`/`model` and implement `_generate()`; this class
    owns the system/user prompt schemas, JSON parsing, and Finding/
    TriageDecision construction so different inference backends stay
    directly comparable.
    """

    name: str
    model: str

    @abstractmethod
    def _generate(self, messages: list[dict[str, str]]) -> str: ...

    def triage(self, finding: Finding, context: dict[str, str]) -> TriageDecision:
        # Prompts the model to score one finding (block/review/accept +
        # risk_score) as JSON, then parses that JSON back into a
        # TriageDecision. Called once per finding by pipeline.py.
        start = time.perf_counter()
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a DevSecOps security triage model. Return JSON only. "
                    "Assess one finding in a CI/CD pipeline for OWASP Juice Shop."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "task": "triage_finding",
                        "finding": finding.to_dict(),
                        "context": context,
                        "schema": {
                            "disposition": "block|review|accept",
                            "risk_score": "integer 0..100",
                            "true_positive_likelihood": "float 0..1",
                            "exploitability": "confirmed|likely|possible|unlikely|unknown",
                            "summary": "short string",
                            "rationale": "short string",
                            "remediation": "short string",
                        },
                    },
                    indent=2,
                ),
            },
        ]
        payload = extract_json(self._generate(messages))
        return TriageDecision(
            finding_fingerprint=finding.fingerprint,
            disposition=str(payload.get("disposition", "review")),
            risk_score=int(payload.get("risk_score", 50)),
            true_positive_likelihood=float(
                payload.get("true_positive_likelihood", finding.confidence)
            ),
            exploitability=str(payload.get("exploitability", "unknown")),
            summary=str(payload.get("summary", "LLM security triage")),
            rationale=str(payload.get("rationale", "No rationale provided.")),
            remediation=str(payload.get("remediation", finding.remediation)),
            provider=self.name,
            model=self.model,
            latency_ms=round((time.perf_counter() - start) * 1000, 3),
        )

    def review_change(self, change: CodeChange, context: dict[str, str]) -> list[Finding]:
        # Prompts the model to find vulnerabilities in one changed file's
        # diff, parses its JSON response into Finding objects tagged
        # tool="llm-diff". Called once per file returned by
        # diffing.collect_changes(), from pipeline.py's run_pipeline().
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a secure code reviewer for OWASP Juice Shop. "
                    "Inspect only the provided code change. "
                    "Return JSON only."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "task": "review_code_change",
                        "change": asdict(change),
                        "context": context,
                        "schema": {
                            "findings": [
                                {
                                    "tool": "llm-diff",
                                    "rule_id": "string",
                                    "title": "string",
                                    "description": "string",
                                    "severity": "critical|high|medium|low|info",
                                    "category": "code|secret|dependency|dynamic",
                                    "confidence": "float 0..1",
                                    "location": {
                                        "path": "string",
                                        "line": "integer|null",
                                        "url": "",
                                    },
                                    "cwe": ["string"],
                                    "references": ["string"],
                                    "remediation": "string",
                                    "evidence": "string",
                                    "metadata": {"source": "diff-review"},
                                }
                            ]
                        },
                    },
                    indent=2,
                ),
            },
        ]
        payload = extract_json(self._generate(messages))
        findings: list[Finding] = []
        for item in payload.get("findings", []):
            mapping = dict(item)
            mapping.setdefault("tool", "llm-diff")
            mapping.setdefault("metadata", {})
            # Tag which provider/model produced this finding so multiple
            # model runs can be merged into one report and compared
            # (see model_comparison.py).
            mapping["metadata"]["source"] = "diff-review"
            mapping["metadata"]["provider"] = self.name
            mapping["metadata"]["model"] = self.model
            findings.append(finding_from_mapping(mapping))
        return findings
