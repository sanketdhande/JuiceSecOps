from __future__ import annotations

import json
import re
import time
from dataclasses import asdict
from typing import Any

from ..models import CodeChange, Finding, TriageDecision
from ..parsers import finding_from_mapping


def _extract_json(text: str) -> Any:
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


class HuggingFaceSecurityProvider:
    name = "huggingface"

    def __init__(self, model: str = "openai/gpt-oss-120b", max_new_tokens: int = 768) -> None:
        self.model = model
        self.max_new_tokens = max_new_tokens
        self._pipe = None

    def _load_pipe(self) -> Any:
        if self._pipe is not None:
            return self._pipe
        from transformers import pipeline

        self._pipe = pipeline(
            "text-generation",
            model=self.model,
            torch_dtype="auto",
            device_map="auto",
        )
        return self._pipe

    def _generate(self, messages: list[dict[str, str]]) -> str:
        pipe = self._load_pipe()
        outputs = pipe(
            messages,
            max_new_tokens=self.max_new_tokens,
            do_sample=False,
        )
        generated = outputs[0]["generated_text"]
        if isinstance(generated, list):
            last = generated[-1]
            if isinstance(last, dict):
                return str(last.get("content", ""))
            return str(last)
        return str(generated)

    def triage(self, finding: Finding, context: dict[str, str]) -> TriageDecision:
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
        payload = _extract_json(self._generate(messages))
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
        payload = _extract_json(self._generate(messages))
        findings: list[Finding] = []
        for item in payload.get("findings", []):
            mapping = dict(item)
            mapping.setdefault("tool", "llm-diff")
            mapping.setdefault("metadata", {})
            mapping["metadata"]["source"] = "diff-review"
            findings.append(finding_from_mapping(mapping))
        return findings
