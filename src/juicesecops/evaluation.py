from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .models import Finding


def finding_source(finding: Finding) -> str:
    return "llm" if finding.tool == "llm-diff" else "traditional"


def summarize_findings(findings: list[Finding]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[Finding]] = {"traditional": [], "llm": []}
    for finding in findings:
        grouped[finding_source(finding)].append(finding)

    summary: dict[str, dict[str, Any]] = {}
    for source, items in grouped.items():
        summary[source] = {
            "count": len(items),
            "tools": dict(Counter(finding.tool for finding in items)),
            "severities": dict(Counter(finding.severity.label() for finding in items)),
            "categories": dict(Counter(finding.category for finding in items)),
        }
    return summary


def _normalize_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def _match_location(finding: Finding) -> str:
    return (finding.location.path or finding.location.url).strip().lower()


def _match_keys(finding: Finding) -> list[tuple[Any, ...]]:
    keys: list[tuple[Any, ...]] = []
    if finding.fingerprint:
        keys.append(("fingerprint", finding.fingerprint.lower()))

    location = _match_location(finding)
    if not location:
        return keys

    lines = [finding.location.line]
    if finding.location.line is not None:
        lines.append(None)

    rule_id = str(finding.rule_id).strip().lower()
    if rule_id and rule_id != "unknown":
        keys.extend(("rule", location, line, rule_id) for line in lines)

    title = _normalize_text(finding.title)
    if title:
        keys.extend(("title", location, line, title) for line in lines)

    cwe_values = sorted({str(cwe).strip().lower() for cwe in finding.cwe if cwe})
    for cwe in cwe_values:
        keys.extend(("cwe", location, line, cwe) for line in lines)

    return keys


def _evaluate_subset(
    findings: list[Finding],
    ground_truth: list[Finding],
) -> dict[str, Any]:
    truth_index: dict[tuple[Any, ...], list[int]] = {}
    for index, finding in enumerate(ground_truth):
        for key in _match_keys(finding):
            truth_index.setdefault(key, []).append(index)

    matched_count = 0
    matched_truth_indexes: set[int] = set()
    matched_fingerprints: list[str] = []
    unmatched_fingerprints: list[str] = []

    for finding in findings:
        match_index: int | None = None
        for key in _match_keys(finding):
            for candidate_index in truth_index.get(key, []):
                if candidate_index not in matched_truth_indexes:
                    match_index = candidate_index
                    break
            if match_index is not None:
                break

        if match_index is None:
            unmatched_fingerprints.append(finding.fingerprint)
            continue

        matched_truth_indexes.add(match_index)
        matched_count += 1
        matched_fingerprints.append(finding.fingerprint)

    precision = round(matched_count / len(findings), 3) if findings else None
    return {
        "predicted_count": len(findings),
        "matched_count": matched_count,
        "false_positive_count": len(findings) - matched_count,
        "precision": precision,
        "matched_fingerprints": matched_fingerprints,
        "unmatched_fingerprints": unmatched_fingerprints,
    }


def evaluate_precision(
    findings: list[Finding],
    ground_truth: list[Finding],
) -> dict[str, Any]:
    sources = {
        source: _evaluate_subset(
            [finding for finding in findings if finding_source(finding) == source],
            ground_truth,
        )
        for source in ("traditional", "llm")
    }
    return {
        "ground_truth_count": len(ground_truth),
        "matching_strategy": "fingerprint > location+rule_id > location+title > location+cwe",
        "overall": _evaluate_subset(findings, ground_truth),
        "sources": sources,
    }
