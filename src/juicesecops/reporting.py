from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .evaluation import finding_source, summarize_findings
from .models import Finding, PipelineReport


def write_report(output_dir: str | Path, report: PipelineReport) -> None:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(
        json.dumps(report.to_dict(), indent=2),
        encoding="utf-8",
    )
    (output / "report.md").write_text(_markdown_report(report), encoding="utf-8")


def render_console_summary(report: PipelineReport) -> str:
    target_repo = str(report.metadata.get("target_repo", "")).strip()
    target_name = str(report.metadata.get("target_name", "")).strip()
    summary = _finding_summary(report)
    lines = [
        "JuiceSecOps run summary",
        f"- Target: {target_name or 'unknown'}",
        f"- Target repo: {target_repo or 'not provided'}",
        f"- Provider: {report.provider}",
        f"- Gate: {'pass' if report.gate.passed else 'fail'}",
        f"- Findings: {len(report.findings)}",
        f"- Reviewed changes: {len(report.changes)}",
        "",
    ]
    lines.extend(_source_console_lines("traditional", report.findings, summary))
    lines.extend([""])
    lines.extend(_source_console_lines("llm", report.findings, summary))

    precision = _precision_comparison(report)
    lines.extend([""])
    if precision is None:
        lines.append("Precision comparison: not computed. Add --ground-truth to evaluate it.")
    else:
        lines.extend(_precision_console_lines(precision))
    return "\n".join(lines).rstrip() + "\n"


def print_report_summary(report: PipelineReport) -> None:
    print(render_console_summary(report), end="")


def _location_text(finding: Finding) -> str:
    if finding.location.path:
        suffix = f":{finding.location.line}" if finding.location.line else ""
        return f"{finding.location.path}{suffix}"
    if finding.location.url:
        return finding.location.url
    return "unknown"


def _finding_summary(report: PipelineReport) -> dict[str, dict[str, Any]]:
    existing = report.metadata.get("finding_summary")
    if isinstance(existing, dict):
        return existing
    return summarize_findings(report.findings)


def _precision_comparison(report: PipelineReport) -> dict[str, Any] | None:
    evaluation = report.metadata.get("precision_comparison")
    return evaluation if isinstance(evaluation, dict) else None


def _format_counts(values: dict[str, int]) -> str:
    if not values:
        return "none"
    ordered = sorted(values.items())
    return ", ".join(f"{key}:{count}" for key, count in ordered)


def _source_console_lines(
    source: str,
    findings: list[Finding],
    summary: dict[str, dict[str, Any]],
) -> list[str]:
    label = "LLM" if source == "llm" else "Traditional"
    source_findings = [finding for finding in findings if finding_source(finding) == source]
    source_summary = summary.get(source, {})
    lines = [
        f"{label} findings ({source_summary.get('count', len(source_findings))}):",
        f"- Tools: {_format_counts(source_summary.get('tools', {}))}",
        f"- Severities: {_format_counts(source_summary.get('severities', {}))}",
        f"- Categories: {_format_counts(source_summary.get('categories', {}))}",
    ]
    if not source_findings:
        lines.append("- Finding list: none")
        return lines

    lines.append("- Finding list:")
    for finding in source_findings:
        lines.append(
            f"  - [{finding.severity.label()}][{finding.tool}] "
            f"{_location_text(finding)} :: {finding.title}"
        )
    return lines


def _precision_console_lines(precision: dict[str, Any]) -> list[str]:
    lines = [
        "Precision comparison against ground truth:",
        f"- Ground truth findings: {precision.get('ground_truth_count', 0)}",
        f"- Matching strategy: {precision.get('matching_strategy', 'n/a')}",
    ]
    overall = precision.get("overall", {})
    lines.append(
        "- Overall precision: "
        f"{overall.get('precision')} "
        f"({overall.get('matched_count', 0)}/{overall.get('predicted_count', 0)} matched)"
    )
    for source in ("traditional", "llm"):
        metrics = precision.get("sources", {}).get(source, {})
        label = "LLM" if source == "llm" else "Traditional"
        lines.append(
            f"- {label} precision: "
            f"{metrics.get('precision')} "
            f"({metrics.get('matched_count', 0)}/{metrics.get('predicted_count', 0)} matched)"
        )
    return lines


def _markdown_report(report: PipelineReport) -> str:
    summary = _finding_summary(report)
    precision = _precision_comparison(report)
    lines = [
        "# Juice Shop DevSecOps Security Report",
        "",
        f"- Target: `{report.metadata.get('target_name') or 'unknown'}`",
        f"- Target repo: `{report.metadata.get('target_repo') or 'not provided'}`",
        f"- Provider: `{report.provider}`",
        f"- Gate: `{'pass' if report.gate.passed else 'fail'}`",
        f"- Findings: `{len(report.findings)}`",
        f"- Reviewed changes: `{len(report.changes)}`",
        "",
        "## Gate Reasons",
        "",
    ]
    if report.gate.reasons:
        lines.extend(f"- {reason}" for reason in report.gate.reasons)
    else:
        lines.append("- No blocking reasons.")

    lines.extend(["", "## Finding Source Summary", ""])
    for source in ("traditional", "llm"):
        label = "LLM" if source == "llm" else "Traditional"
        metrics = summary.get(source, {})
        lines.extend(
            [
                f"### {label}",
                "",
                f"- Count: `{metrics.get('count', 0)}`",
                f"- Tools: `{_format_counts(metrics.get('tools', {}))}`",
                f"- Severities: `{_format_counts(metrics.get('severities', {}))}`",
                f"- Categories: `{_format_counts(metrics.get('categories', {}))}`",
                "",
            ]
        )

    lines.extend(["## Precision Comparison", ""])
    if precision is None:
        lines.append("- Not computed. Supply `--ground-truth` findings to compare precision.")
    else:
        overall = precision.get("overall", {})
        lines.extend(
            [
                f"- Ground truth findings: `{precision.get('ground_truth_count', 0)}`",
                f"- Matching strategy: `{precision.get('matching_strategy', 'n/a')}`",
                "- Overall precision: "
                f"`{overall.get('precision')}` "
                f"({overall.get('matched_count', 0)}/{overall.get('predicted_count', 0)} matched)",
            ]
        )
        for source in ("traditional", "llm"):
            metrics = precision.get("sources", {}).get(source, {})
            label = "LLM" if source == "llm" else "Traditional"
            lines.append(
                f"- {label} precision: "
                f"`{metrics.get('precision')}` "
                f"({metrics.get('matched_count', 0)}/{metrics.get('predicted_count', 0)} matched)"
            )

    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("- No findings produced.")
        return "\n".join(lines) + "\n"

    for finding in report.findings:
        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- Source: `{'llm' if finding_source(finding) == 'llm' else 'traditional'}`",
                f"- Tool: `{finding.tool}`",
                f"- Severity: `{finding.severity.label()}`",
                f"- Category: `{finding.category}`",
                f"- Location: `{_location_text(finding)}`",
                f"- Confidence: `{finding.confidence:.2f}`",
            ]
        )
        if finding.evidence:
            lines.append(f"- Evidence: `{finding.evidence[:180]}`")
        if finding.remediation:
            lines.append(f"- Remediation: {finding.remediation}")
        lines.append("")
    return "\n".join(lines) + "\n"
