from __future__ import annotations

# Merges multiple juicesecops report.json files -- each produced by running
# `python -m juicesecops` once per --provider/--model-id against the *same*
# scanner inputs (semgrep.json/trivy.json/zap.json) -- into a single
# side-by-side comparison. Used by compare_models_cli.py, which is what the
# multi-model GitHub Actions workflow
# (.github/workflows/juice-shop-security-report-openweight.yml) runs after
# its matrix of --provider gguf jobs finishes.
import json
from pathlib import Path
from typing import Any

from .models import Finding, Location, Severity, TriageDecision


def _finding_from_report_item(item: dict[str, Any]) -> Finding:
    # Deliberately NOT parsers.reports.finding_from_mapping(): that helper
    # is for ingesting *external* scanner-shaped JSON that never had a
    # fingerprint of its own, so it recomputes one from tool/rule_id/
    # location/title. Our own report.json already carries the exact
    # fingerprint TriageDecision.finding_fingerprint was matched against
    # when the report was generated -- recomputing it here would silently
    # break that link (every decision would look "unknown").
    location = item.get("location", {}) or {}
    return Finding(
        tool=str(item.get("tool", "generic")),
        rule_id=str(item.get("rule_id", "unknown")),
        title=str(item.get("title", "Security finding")),
        description=str(item.get("description", "")),
        severity=Severity.parse(item.get("severity")),
        category=str(item.get("category", "code")),
        confidence=float(item.get("confidence", 0.5)),
        location=Location(
            path=str(location.get("path", "")),
            line=location.get("line"),
            url=str(location.get("url", "")),
        ),
        cwe=list(item.get("cwe") or []),
        references=list(item.get("references") or []),
        remediation=str(item.get("remediation", "")),
        evidence=str(item.get("evidence", "")),
        fingerprint=str(item.get("fingerprint", "")),
        metadata=dict(item.get("metadata") or {}),
    )


def load_pipeline_report(path: str | Path) -> dict[str, Any]:
    """Load one of this project's own report.json files (written by
    reporting.write_report) back into Finding/TriageDecision objects, plus
    the run's provider/gate/metadata."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = [_finding_from_report_item(item) for item in data.get("findings", [])]
    decisions = [TriageDecision(**item) for item in data.get("decisions", [])]
    return {
        "provider": str(data.get("provider", "unknown")),
        "findings": findings,
        "decisions": decisions,
        "gate": data.get("gate", {}) or {},
        "metadata": data.get("metadata", {}) or {},
    }


def _llm_findings(findings: list[Finding]) -> list[Finding]:
    return [finding for finding in findings if finding.metadata.get("source") == "diff-review"]


def _traditional_findings(findings: list[Finding]) -> list[Finding]:
    return [finding for finding in findings if finding.metadata.get("source") != "diff-review"]


def _resolved_model(run: dict[str, Any], fallback: str) -> str:
    # PipelineReport doesn't carry a single top-level "model" (provider.name
    # is recorded, not provider.model), so recover the actual resolved
    # model id (e.g. "fdtn-ai/Foundation-Sec-8B-Reasoning-GGUF:*Q4_K_M.gguf")
    # from any triage decision, which always stamps provider.model.
    for decision in run["decisions"]:
        if decision.model:
            return decision.model
    return fallback


def build_model_comparison(runs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """runs: {model_label: loaded report dict (see load_pipeline_report)}.

    Traditional (scanner) findings are assumed identical across runs -- the
    same Semgrep/Trivy/ZAP JSON was fed into every run -- so they're taken
    once from the first run rather than duplicated per model. LLM-diff
    findings and triage decisions differ per model/provider and are kept
    per-model.
    """
    if not runs:
        raise ValueError("build_model_comparison requires at least one run")

    first_label = next(iter(runs))
    traditional = _traditional_findings(runs[first_label]["findings"])

    per_model: dict[str, dict[str, Any]] = {}
    for label, run in runs.items():
        llm_findings = _llm_findings(run["findings"])
        decisions_by_fingerprint = {
            decision.finding_fingerprint: decision for decision in run["decisions"]
        }
        dispositions: dict[str, int] = {}
        severities: dict[str, int] = {}
        for finding in llm_findings:
            decision = decisions_by_fingerprint.get(finding.fingerprint)
            disposition = decision.disposition if decision else "unknown"
            dispositions[disposition] = dispositions.get(disposition, 0) + 1
            severities[finding.severity.label()] = severities.get(finding.severity.label(), 0) + 1
        per_model[label] = {
            "provider": run["provider"],
            "model": _resolved_model(run, fallback=label),
            "gate_passed": bool(run["gate"].get("passed")),
            "gate_reasons": list(run["gate"].get("reasons") or []),
            "llm_finding_count": len(llm_findings),
            "severities": severities,
            "dispositions": dispositions,
            "duration_ms": run["metadata"].get("duration_ms"),
            "findings": llm_findings,
        }

    return {
        "traditional_source": first_label,
        "traditional_findings": traditional,
        "models": per_model,
    }


def comparison_to_dict(comparison: dict[str, Any]) -> dict[str, Any]:
    return {
        "traditional_source": comparison["traditional_source"],
        "traditional_findings": [
            finding.to_dict() for finding in comparison["traditional_findings"]
        ],
        "models": {
            label: {**{k: v for k, v in info.items() if k != "findings"},
                     "findings": [finding.to_dict() for finding in info["findings"]]}
            for label, info in comparison["models"].items()
        },
    }


def _format_counts(values: dict[str, int]) -> str:
    if not values:
        return "none"
    return ", ".join(f"{key}:{count}" for key, count in sorted(values.items()))


def _location_text(finding: Finding) -> str:
    if finding.location.path:
        suffix = f":{finding.location.line}" if finding.location.line else ""
        return f"{finding.location.path}{suffix}"
    if finding.location.url:
        return finding.location.url
    return "unknown"


def render_model_comparison_markdown(comparison: dict[str, Any]) -> str:
    traditional = comparison["traditional_findings"]
    lines = [
        "# Open-Weight Model Comparison",
        "",
        "## Traditional findings (shared baseline)",
        "",
        f"- Source run: `{comparison['traditional_source']}`",
        f"- Count: `{len(traditional)}`",
        "",
        "## Per-model LLM results",
        "",
        "| Model label | Resolved model | Gate | LLM findings | Severities "
        "| Dispositions | Duration (ms) |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for label, info in comparison["models"].items():
        gate = "pass" if info["gate_passed"] else "fail"
        lines.append(
            f"| `{label}` | `{info['model']}` | {gate} | {info['llm_finding_count']} "
            f"| {_format_counts(info['severities'])} | {_format_counts(info['dispositions'])} "
            f"| {info['duration_ms']} |"
        )

    lines.extend(["", "## Findings by model", ""])
    for label, info in comparison["models"].items():
        lines.append(f"### {label} (`{info['model']}`)")
        lines.append("")
        if info["gate_reasons"]:
            lines.append("Gate reasons:")
            lines.extend(f"- {reason}" for reason in info["gate_reasons"])
            lines.append("")
        if not info["findings"]:
            lines.append("- No LLM findings produced.")
            lines.append("")
            continue
        for finding in info["findings"]:
            lines.append(
                f"- **{finding.title}** [{finding.severity.label()}] "
                f"`{_location_text(finding)}` -- "
                f"{finding.remediation or 'no remediation provided'}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
