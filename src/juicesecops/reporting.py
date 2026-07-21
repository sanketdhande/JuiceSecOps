from __future__ import annotations

import json
from pathlib import Path

from .models import PipelineReport


def write_report(output_dir: str | Path, report: PipelineReport) -> None:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(
        json.dumps(report.to_dict(), indent=2),
        encoding="utf-8",
    )
    (output / "report.md").write_text(_markdown_report(report), encoding="utf-8")


def _markdown_report(report: PipelineReport) -> str:
    lines = [
        "# Juice Shop DevSecOps Security Report",
        "",
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

    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("- No findings produced.")
        return "\n".join(lines) + "\n"

    for finding in report.findings:
        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- Tool: `{finding.tool}`",
                f"- Severity: `{finding.severity.label()}`",
                f"- Category: `{finding.category}`",
                f"- Location: `{finding.location.path}`"
                + (f":{finding.location.line}" if finding.location.line else ""),
                f"- Confidence: `{finding.confidence:.2f}`",
            ]
        )
        if finding.evidence:
            lines.append(f"- Evidence: `{finding.evidence[:180]}`")
        if finding.remediation:
            lines.append(f"- Remediation: {finding.remediation}")
        lines.append("")
    return "\n".join(lines) + "\n"
