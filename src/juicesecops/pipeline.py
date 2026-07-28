from __future__ import annotations

# This is the orchestrator called from cli.py: main(). The `provider` argument
# is a SecurityProvider (providers/base.py) -- GroqSecurityProvider (default,
# providers/groq.py) or OpenRouterSecurityProvider (providers/openrouter.py),
# both hosted APIs with no local model weights. The provider is used in
# exactly two places below: provider.review_change() (the LLM "finds new
# bugs in a diff" stage) and provider.triage() (the LLM "judge severity of a
# finding" stage). Everything else here (parsing scanner JSON, dedup,
# redaction, the pass/fail gate) is deterministic Python with no model
# involved.
import hashlib
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from .diffing import collect_changes
from .models import Finding, Location, PipelineReport, Severity, TriageDecision
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


def _provider_error_fingerprint(provider: SecurityProvider, path: str, exc: Exception) -> str:
    stable = "\x1f".join(
        ["provider-error", provider.name, provider.model, path, type(exc).__name__, str(exc)]
    )
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()[:20]


def _review_error_finding(
    provider: SecurityProvider,
    path: str,
    exc: Exception,
) -> Finding:
    return Finding(
        tool="llm-diff",
        rule_id="provider.review_error",
        title="Change review provider failed",
        description=(
            f"The {provider.name} provider could not review the change in {path}: "
            f"{type(exc).__name__}: {exc}"
        ),
        severity=Severity.HIGH,
        category="code",
        confidence=1.0,
        location=Location(path=path),
        remediation="Retry the model call or inspect provider configuration.",
        fingerprint=_provider_error_fingerprint(provider, path, exc),
        metadata={"source": "diff-review", "provider_error": f"{type(exc).__name__}: {exc}"},
    )


def _provider_error_decision(
    finding: Finding,
    provider: SecurityProvider,
    policy: Policy,
    exc: Exception,
) -> TriageDecision:
    return TriageDecision(
        finding_fingerprint=finding.fingerprint,
        disposition="block" if policy.fail_closed_on_provider_error else "review",
        risk_score=100 if policy.fail_closed_on_provider_error else 50,
        true_positive_likelihood=finding.confidence,
        exploitability="unknown",
        summary="Triage provider failed",
        rationale=(
            "The provider response was not trusted because the model call failed."
        ),
        remediation=finding.remediation,
        provider=provider.name,
        model=provider.model,
        latency_ms=0.0,
        error=f"{type(exc).__name__}: {exc}",
    )


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
    forced_decisions: dict[str, TriageDecision] = {}
    # Step 1: ingest scanner reports (Semgrep/Trivy/ZAP/generic JSON) as
    # "traditional" findings -- no provider/LLM involved yet.
    for input_path in inputs:
        path = Path(input_path)
        if not path.exists():
            continue
        findings.extend(load_findings(path))

    changes = []
    if review_changes and target_repo is not None:
        # Step 2: figure out which files to show the LLM (diffing.py).
        changes = collect_changes(target_repo, policy, base_ref=base_ref, head_ref=head_ref)
        # Step 3: the LLM change-review call. Each change becomes
        # zero or more Finding(tool="llm-diff", ...) objects -- this is the
        # "LLM findings" bucket you see in the report.
        for change in changes:
            try:
                findings.extend(provider.review_change(change, context))
            except Exception as exc:
                error_finding = _review_error_finding(provider, change.path, exc)
                findings.append(error_finding)
                forced_decisions[error_finding.fingerprint] = _provider_error_decision(
                    error_finding, provider, policy, exc
                )

    findings = _deduplicate(findings)
    if len(findings) > policy.max_findings_per_run:
        raise ValueError(
            f"Finding count {len(findings)} exceeds policy limit {policy.max_findings_per_run}"
        )

    if policy.redact_secrets:
        findings = [_sanitize_finding(finding, policy) for finding in findings]

    # Step 4: the LLM triage call, once per finding (both scanner
    # findings and the llm-diff findings from step 3 go through this). This
    # is what decides block/review/accept and the risk_score used by the
    # deterministic gate below -- it does not create new findings.
    decisions: list[TriageDecision] = []
    for finding in findings:
        forced = forced_decisions.get(finding.fingerprint)
        if forced is not None:
            decisions.append(forced)
            continue
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
                    rationale=(
                        "The provider response was not trusted because the model call failed."
                    ),
                    remediation=finding.remediation,
                    provider=provider.name,
                    model=provider.model,
                    latency_ms=0.0,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )

    # Step 5: deterministic pass/fail gate (policy.py) -- the LLM
    # provider is advisory input to this, never the final authority.
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
            "target_repo": str(target_repo) if target_repo is not None else "",
            "target_name": Path(target_repo).name if target_repo is not None else "",
        },
    )
