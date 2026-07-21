from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding, GateResult, Severity, TriageDecision


@dataclass(slots=True)
class Policy:
    block_severity_floor: Severity = Severity.CRITICAL
    review_severity_floor: Severity = Severity.HIGH
    block_risk_score: int = 70
    review_risk_score: int = 45
    fail_closed_on_provider_error: bool = True
    max_findings_per_run: int = 300
    redact_secrets: bool = True
    max_evidence_chars: int = 500
    max_diff_chars: int = 7000
    max_snippet_chars: int = 2500
    max_changed_files: int = 20
    include_extensions: list[str] = field(
        default_factory=lambda: [".ts", ".js", ".html", ".json", ".yml", ".yaml", ".md"]
    )
    include_paths: list[str] = field(
        default_factory=lambda: [
            "app.ts",
            "server.ts",
            "Dockerfile",
            "package.json",
            "config/",
            "lib/",
            "models/",
            "routes/",
            "frontend/src/",
        ]
    )

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        gate = data.get("gate", {})
        privacy = data.get("privacy", {})
        changes = data.get("changes", {})
        return cls(
            block_severity_floor=Severity.parse(gate.get("block_severity_floor")),
            review_severity_floor=Severity.parse(gate.get("review_severity_floor")),
            block_risk_score=int(gate.get("block_risk_score", 70)),
            review_risk_score=int(gate.get("review_risk_score", 45)),
            fail_closed_on_provider_error=bool(gate.get("fail_closed_on_provider_error", True)),
            max_findings_per_run=int(gate.get("max_findings_per_run", 300)),
            redact_secrets=bool(privacy.get("redact_secrets", True)),
            max_evidence_chars=int(privacy.get("max_evidence_chars", 500)),
            max_diff_chars=int(privacy.get("max_diff_chars", 7000)),
            max_snippet_chars=int(privacy.get("max_snippet_chars", 2500)),
            max_changed_files=int(changes.get("max_changed_files", 20)),
            include_extensions=[str(item) for item in changes.get("include_extensions", [])],
            include_paths=[str(item) for item in changes.get("include_paths", [])],
        )


def evaluate_gate(
    findings: list[Finding],
    decisions: list[TriageDecision],
    policy: Policy,
) -> GateResult:
    reasons: list[str] = []
    blocked: list[str] = []
    decision_map = {decision.finding_fingerprint: decision for decision in decisions}

    for finding in findings:
        decision = decision_map.get(finding.fingerprint)
        if finding.category == "secret":
            reasons.append(f"Secret detected: {finding.title}")
            blocked.append(finding.fingerprint)
            continue
        if finding.severity >= policy.block_severity_floor:
            reasons.append(f"Severity floor hit: {finding.severity.label()} {finding.title}")
            blocked.append(finding.fingerprint)
            continue
        if decision is None:
            continue
        if decision.error and policy.fail_closed_on_provider_error:
            reasons.append(f"Provider error for {finding.title}: {decision.error}")
            blocked.append(finding.fingerprint)
            continue
        if decision.disposition == "block":
            reasons.append(f"Provider blocked {finding.title}")
            blocked.append(finding.fingerprint)
            continue
        if decision.risk_score >= policy.block_risk_score:
            reasons.append(f"Risk score {decision.risk_score} for {finding.title}")
            blocked.append(finding.fingerprint)

    return GateResult(passed=not blocked, reasons=reasons, blocked_fingerprints=blocked)
