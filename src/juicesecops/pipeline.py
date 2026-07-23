from __future__ import annotations

import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from .diffing import collect_changes
from .models import Finding, PipelineReport, TriageDecision
from .parsers import load_findings
from .policy import Policy, evaluate_gate
from .providers.base import SecurityProvider


def _redact(text: str, max_chars: int) -> str:
    redacted = text.replace("sk_", "sk_[redacted]").replace("AIza", "AIza[redacted]")
    return redacted[:max_chars]


def _sanitize_finding(finding: Finding, policy: Policy) -> Finding:
    finding.evidence = _redact(finding.evidence, policy.max_evidence_chars)
    finding.description = _redact(finding.description, policy.max_evidence_chars)
    return finding


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for finding in findings:
        previous = unique.get(finding.fingerprint)
        if previous is None or finding.confidence > previous.confidence:
            unique[finding.fingerprint] = finding
    return sorted(
        unique.values(),
        key=lambda finding: (-int(finding.severity), finding.tool, finding.fingerprint),
    )


def run_pipeline(
    inputs: list[str | Path],
    provider: SecurityProvider,
    policy: Policy,
    target_repo: str | Path | None = None,
    context: dict[str, str] | None = None,
    base_ref: str | None = None,
    head_ref: str = "HEAD",
    review_changes: bool = True,
) -> PipelineReport:
    started = time.perf_counter()
    context = context or {}
    findings: list[Finding] = []
    for input_path in inputs:
        path = Path(input_path)
        if not path.exists():
            continue
        findings.extend(load_findings(path))

    changes = []
    if review_changes and target_repo is not None:
        changes = collect_changes(target_repo, policy, base_ref=base_ref, head_ref=head_ref)
        for change in changes:
            findings.extend(provider.review_change(change, context))

    findings = _deduplicate(findings)
    if len(findings) > policy.max_findings_per_run:
        raise ValueError(
            f"Finding count {len(findings)} exceeds policy limit {policy.max_findings_per_run}"
        )

    if policy.redact_secrets:
        findings = [_sanitize_finding(finding, policy) for finding in findings]

    decisions: list[TriageDecision] = []
    for finding in findings:
        try:
            decisions.append(provider.triage(finding, context))
        except Exception as exc:
            decisions.append(
                TriageDecision(
                    finding_fingerprint=finding.fingerprint,
                    disposition="block" if policy.fail_closed_on_provider_error else "review",
                    risk_score=100 if policy.fail_closed_on_provider_error else 50,
                    true_positive_likelihood=finding.confidence,
                    exploitability="unknown",
                    summary="Triage provider failed",
                    rationale="The provider response was not trusted because the model call failed.",
                    remediation=finding.remediation,
                    provider=provider.name,
                    model=provider.model,
                    latency_ms=0.0,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )

    gate = evaluate_gate(findings, decisions, policy)
    return PipelineReport(
        schema_version="1.0",
        generated_at=datetime.now(UTC).isoformat(),
        inputs=[str(path) for path in inputs],
        provider=provider.name,
        findings=findings,
        decisions=decisions,
        gate=gate,
        changes=changes,
        metadata={
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            "finding_count": len(findings),
            "changed_file_count": len(changes),
            "by_severity": dict(Counter(finding.severity.label() for finding in findings)),
            "by_tool": dict(Counter(finding.tool for finding in findings)),
            "context": context,
            "base_ref": base_ref or "working-tree",
            "head_ref": head_ref,
        },
    )
