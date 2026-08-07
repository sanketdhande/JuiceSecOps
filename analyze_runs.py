#!/usr/bin/env python3
"""
analyze_runs.py — regenerate every results table in Chapter 4 from raw report.json files.

Purpose
-------
Chapter 4 of the thesis must be reproducible from the CI artefacts alone. This script is
the single source of truth for every number in that chapter. Given one or more JuiceSecOps
report.json files it emits the corrected detection-yield, runtime, complementarity,
calibration and ground-truth tables as Markdown.

Two corrections applied here that a naive read of report.json does NOT apply:

  (C1) PROVIDER-ERROR RECORDS ARE EXCLUDED FROM DETECTION COUNTS.
       The orchestrator emits failed diff-review calls into `findings` as tool="llm-diff",
       title="Change review provider failed", severity="high". These are transport
       failures, not vulnerabilities. Counting them inflates the DVWA LLM yield from
       26 to 97. They are reported separately as a reliability metric.

  (C2) TARGET PATH PREFIXES ARE NORMALISED BEFORE ANY OVERLAP JOIN.
       Semgrep reports paths as "targets/<name>/routes/login.ts"; the diff-review stage
       and Trivy report "routes/login.ts". Joining the two sets without stripping the
       prefix yields an artefactual zero overlap and therefore an artefactually perfect
       complementarity claim.

Usage
-----
    python analyze_runs.py \
        --run "Juice Shop / OpenRouter=juice-shop-security-report-openrouter/report.json" \
        --run "DVWA / OpenRouter=dvwa-security-report-openrouter/report.json" \
        --ground-truth ground-truth-dvwa.json \
        --output chapter4_tables.md
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import statistics as stats
from pathlib import Path

# Records the orchestrator writes into `findings` when a provider call fails.
PROVIDER_ERROR_TITLE = "Change review provider failed"

# DVWA ships each weakness as vulnerabilities/<module>/, and each module as
# low.php / medium.php / high.php / impossible.php. impossible.php is the *hardened*
# variant, so any finding located in it is a false positive by construction.
DVWA_MODULE_CWE = {
    "sqli": "CWE-89",
    "sqli_blind": "CWE-89",
    "exec": "CWE-78",
    "fi": "CWE-98",
    "xss_r": "CWE-79",
    "xss_s": "CWE-79",
    "xss_d": "CWE-79",
    "csrf": "CWE-352",
    "upload": "CWE-434",
    "brute": "CWE-307",
    "weak_id": "CWE-330",
    "open_redirect": "CWE-601",
    "authbypass": "CWE-639",
    "bac": "CWE-284",
    "csp": "CWE-693",
    "javascript": "CWE-602",
    "captcha": "CWE-804",
}


# --------------------------------------------------------------------------- helpers

def normalise_cwe(raw) -> str | None:
    """'CWE-89: Improper Neutralization...' -> 'CWE-89'. '264' -> 'CWE-264'."""
    if not raw:
        return None
    match = re.search(r"(\d+)", str(raw))
    return f"CWE-{int(match.group(1))}" if match else None


def strip_target_prefix(path: str) -> str:
    """Correction C2. Remove any leading 'targets/<name>/' segment."""
    return re.sub(r"^targets/[^/]+/", "", path or "")


def is_provider_error(finding: dict) -> bool:
    """Correction C1."""
    return (
        finding.get("tool") == "llm-diff"
        and finding.get("title") == PROVIDER_ERROR_TITLE
    )


def split_sources(findings: list[dict]) -> tuple[list, list, list]:
    """-> (genuine LLM findings, provider-error records, traditional scanner findings)."""
    llm, errors, traditional = [], [], []
    for finding in findings:
        if finding.get("tool") == "llm-diff":
            (errors if is_provider_error(finding) else llm).append(finding)
        else:
            traditional.append(finding)
    return llm, errors, traditional


def cwe_set(findings: list[dict]) -> set[str]:
    out = set()
    for finding in findings:
        for raw in finding.get("cwe") or []:
            normalised = normalise_cwe(raw)
            if normalised:
                out.add(normalised)
    return out


def md_table(headers: list[str], rows: list[list]) -> str:
    line = "| " + " | ".join(str(h) for h in headers) + " |"
    rule = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join([line, rule, *body])


# --------------------------------------------------------------------------- tables

def table_detection_yield(runs: dict[str, dict]) -> str:
    rows = []
    for label, report in runs.items():
        llm, errors, _ = split_sources(report["findings"])
        by_tool = report["metadata"].get("by_tool", {})
        models = collections.Counter(
            d["model"] for d in report["decisions"] if d.get("model")
        )
        model = models.most_common(1)[0][0] if models else "n/a"
        rows.append([
            label, model,
            by_tool.get("semgrep", 0), by_tool.get("trivy", 0), by_tool.get("zap", 0),
            len(llm), len(errors), len(report["findings"]) - len(errors),
        ])
    return md_table(
        ["Run", "Model", "Semgrep", "Trivy", "ZAP", "LLM (genuine)",
         "LLM (provider errors, excluded)", "Total (corrected)"],
        rows,
    )


def table_runtime(runs: dict[str, dict], pr_sizes=(5, 10, 20, 50)) -> str:
    rows = []
    for label, report in runs.items():
        meta = report["metadata"]
        wall = meta["duration_ms"] / 1000
        scope = meta.get("changed_file_count") or 1
        completed = [
            d for d in report["decisions"] if d.get("latency_ms") and not d.get("error")
        ]
        triage_s = sum(d["latency_ms"] for d in completed) / 1000
        review_s = max(wall - triage_s, 0.0)
        per_file = review_s / scope
        latencies = [d["latency_ms"] / 1000 for d in completed]
        rows.append([
            label,
            f"{wall:.0f} ({wall/60:.1f} min)",
            scope,
            f"{len(completed)}/{len(report['decisions'])}",
            f"{triage_s:.0f}",
            f"{review_s:.0f}",
            f"{per_file:.1f}",
            f"{stats.median(latencies):.2f}" if latencies else "n/a",
            *[f"{n * per_file / 60:.1f}" for n in pr_sizes],
        ])
    return md_table(
        ["Run", "Stage wall-clock (s)", "Files in scope", "Triage calls completed",
         "Time in triage (s)", "Time in diff review (s)", "Cost per file (s)",
         "Median triage call (s)",
         *[f"Projected {n}-file PR (min)" for n in pr_sizes]],
        rows,
    )


def table_complementarity(runs: dict[str, dict]) -> str:
    rows = []
    for label, report in runs.items():
        llm, _, traditional = split_sources(report["findings"])
        located = [f for f in traditional if f["location"].get("path")]

        llm_cwe, trad_cwe = cwe_set(llm), cwe_set(traditional)
        llm_files = {strip_target_prefix(f["location"]["path"]) for f in llm
                     if f["location"].get("path")}
        trad_files = {strip_target_prefix(f["location"]["path"]) for f in located}

        def keyed(findings):
            return {
                (strip_target_prefix(f["location"]["path"]), f["location"].get("line"))
                for f in findings if f["location"].get("path")
            }

        rows.append([
            label,
            len(llm_cwe), len(trad_cwe),
            len(llm_cwe - trad_cwe), len(trad_cwe - llm_cwe), len(llm_cwe & trad_cwe),
            len(llm_files & trad_files),
            len(keyed(llm) & keyed(located)),
            sum(1 for f in traditional if not f["location"].get("path")),
        ])
    return md_table(
        ["Run", "Distinct CWE (LLM)", "Distinct CWE (scanners)",
         "CWE unique to LLM", "CWE unique to scanners", "CWE in both",
         "Shared files (prefix-normalised)", "Shared file:line",
         "Scanner findings with no file path (DAST)"],
        rows,
    )


def table_calibration(runs: dict[str, dict]) -> str:
    rows = []
    for label, report in runs.items():
        llm, _, _ = split_sources(report["findings"])
        confidences = [f["confidence"] for f in llm if f.get("confidence") is not None]
        completed = [d for d in report["decisions"] if not d.get("error")]
        likelihoods = [
            d["true_positive_likelihood"] for d in completed
            if d.get("true_positive_likelihood") is not None
        ]
        dispositions = collections.Counter(d.get("disposition") for d in completed)
        rows.append([
            label,
            f"{stats.mean(confidences):.3f}" if confidences else "n/a",
            f"{100 * sum(c >= 0.9 for c in confidences) / len(confidences):.0f}%"
            if confidences else "n/a",
            f"{stats.mean(likelihoods):.3f}" if likelihoods else "n/a",
            f"{100 * sum(v >= 0.9 for v in likelihoods) / len(likelihoods):.0f}%"
            if likelihoods else "n/a",
            dispositions.get("block", 0),
            dispositions.get("review", 0),
            dispositions.get("accept", 0),
        ])
    return md_table(
        ["Run", "Mean detection self-confidence", "Share >= 0.9",
         "Mean triage TP-likelihood", "Share >= 0.9",
         "block", "review", "accept"],
        rows,
    )


def table_reliability(runs: dict[str, dict]) -> str:
    """Structured-output and transport reliability, reported separately from detection."""
    rows = []
    for label, report in runs.items():
        decisions = report["decisions"]
        buckets = collections.Counter()
        for decision in decisions:
            error = decision.get("error") or ""
            if not error:
                buckets["ok"] += 1
            elif "valid JSON" in error:
                buckets["schema"] += 1
            elif "429" in error or "rate" in error.lower():
                buckets["rate_limit"] += 1
            elif "credit" in error.lower() or "PaymentRequired" in error:
                buckets["quota"] += 1
            else:
                buckets["other"] += 1
        total = len(decisions) or 1
        rows.append([
            label, total, buckets["ok"],
            f"{100 * buckets['ok'] / total:.0f}%",
            buckets["schema"], buckets["rate_limit"], buckets["quota"], buckets["other"],
        ])
    return md_table(
        ["Run", "Triage calls attempted", "Completed", "Completion rate",
         "Schema violation", "Rate limited", "Quota exhausted", "Other"],
        rows,
    )


def table_dvwa_ground_truth(report: dict) -> str:
    """Module coverage as a recall proxy, plus false positives on the hardened variant."""
    llm, _, traditional = split_sources(report["findings"])
    sources = {"LLM (diff review)": llm}
    for tool in ("semgrep", "trivy"):
        sources[tool] = [f for f in traditional if f["tool"] == tool]

    coverage, false_positives, correct_cwe = {}, {}, {}
    for name, findings in sources.items():
        modules, fps, hits = set(), 0, 0
        for finding in findings:
            path = strip_target_prefix(finding["location"].get("path") or "")
            module = re.match(r"vulnerabilities/([^/]+)/", path)
            if module and module.group(1) in DVWA_MODULE_CWE:
                modules.add(module.group(1))
                expected = DVWA_MODULE_CWE[module.group(1)]
                if expected in cwe_set([finding]):
                    hits += 1
            if path.endswith("/impossible.php"):
                fps += 1
        coverage[name], false_positives[name], correct_cwe[name] = modules, fps, hits

    total = len(DVWA_MODULE_CWE)
    rows = [
        [name,
         f"{len(mods)}/{total}",
         f"{len(mods) / total:.2f}",
         correct_cwe[name],
         false_positives[name],
         ", ".join(sorted(mods)) or "—"]
        for name, mods in coverage.items()
    ]
    table = md_table(
        ["Source", "Modules reached", "Module recall", "Findings with correct module CWE",
         "Findings on impossible.php (FP by construction)", "Modules"],
        rows,
    )
    llm_mods = coverage["LLM (diff review)"]
    sem_mods = coverage["semgrep"]
    notes = [
        "",
        f"- Reached only by the LLM stage: {sorted(llm_mods - sem_mods) or '—'}",
        f"- Reached only by Semgrep: {sorted(sem_mods - llm_mods) or '—'}",
        f"- Reached by neither: {sorted(set(DVWA_MODULE_CWE) - llm_mods - sem_mods) or '—'}",
    ]
    return table + "\n" + "\n".join(notes)


def table_agreement_detail(report: dict, label: str) -> str:
    """Per-file CWE agreement on prefix-normalised shared files: concurrent validity."""
    llm, _, traditional = split_sources(report["findings"])
    located = [f for f in traditional if f["location"].get("path")]

    def by_file(findings):
        grouped = collections.defaultdict(list)
        for finding in findings:
            grouped[strip_target_prefix(finding["location"]["path"])].append(finding)
        return grouped

    llm_files, trad_files = by_file(llm), by_file(located)
    rows = []
    for path in sorted(set(llm_files) & set(trad_files)):
        llm_cwes = sorted(c for c in cwe_set(llm_files[path]))
        trad_cwes = sorted(c for c in cwe_set(trad_files[path]))
        shared = set(llm_cwes) & set(trad_cwes)
        rows.append([
            path,
            ", ".join(llm_cwes) or "—",
            ", ".join(trad_cwes) or "—",
            "exact" if shared else ("related" if llm_cwes and trad_cwes else "no CWE"),
        ])
    if not rows:
        return f"_No shared files for {label}._"
    exact = sum(1 for r in rows if r[3] == "exact")
    header = (
        f"Shared files: {len(rows)}. Exact CWE agreement: {exact} "
        f"({100 * exact / len(rows):.0f}%).\n\n"
    )
    return header + md_table(
        ["File", "CWE assigned by LLM", "CWE assigned by scanner", "Agreement"], rows
    )


def table_dast_coverage(zap_reports: dict[str, dict]) -> str:
    """
    Crawl coverage and risk distribution from the raw ZAP report.

    The HTML report renders distinct alert *names*; the normalised finding count in
    report.json is instance-level after fingerprint deduplication. Both are reported so
    the two artefacts reconcile.
    """
    rows = []
    for label, zap in zap_reports.items():
        sites = zap.get("site") or []
        if isinstance(sites, dict):
            sites = [sites]
        site = sites[0] if sites else {}
        alerts = site.get("alerts", [])

        risk = collections.Counter()
        for alert in alerts:
            # riskdesc is "Risk (Confidence)"; take the risk half only.
            risk[(alert.get("riskdesc", "?").split("(")[0].strip())] += 1
        instances = sum(len(a.get("instances", [])) for a in alerts)

        insights = {
            str(i.get("description", "")): i.get("statistic")
            for i in zap.get("insights", []) if isinstance(i, dict)
        }

        def stat(needle, default="—"):
            for key, value in insights.items():
                if needle in key:
                    return value
            return default

        rows.append([
            label,
            site.get("@name", "?"),
            stat("Count of total endpoints"),
            f"{stat('method GET')}%",
            f"{stat('method POST', 0)}%",
            risk.get("High", 0), risk.get("Medium", 0),
            risk.get("Low", 0), risk.get("Informational", 0),
            len(alerts), instances,
        ])
    return md_table(
        ["Run", "Scanned origin", "Endpoints crawled", "GET", "POST",
         "High", "Medium", "Low", "Info", "Distinct alerts", "Alert instances"],
        rows,
    )


# --------------------------------------------------------------------------- driver

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run", action="append", required=True, metavar="LABEL=PATH",
        help="Labelled report.json, repeatable.",
    )
    parser.add_argument("--dvwa-run", metavar="LABEL",
                        help="Label of the DVWA run for the ground-truth table.")
    parser.add_argument(
        "--zap", action="append", default=[], metavar="LABEL=PATH",
        help="Labelled raw zap.json for the DAST coverage table, repeatable.",
    )
    parser.add_argument("--output", type=Path, default=Path("chapter4_tables.md"))
    args = parser.parse_args()

    runs: dict[str, dict] = {}
    for spec in args.run:
        if "=" not in spec:
            parser.error(f"--run needs LABEL=PATH, got {spec!r}")
        label, path = spec.split("=", 1)
        runs[label.strip()] = json.loads(Path(path.strip()).read_text())

    zap_reports: dict[str, dict] = {}
    for spec in args.zap:
        if "=" not in spec:
            parser.error(f"--zap needs LABEL=PATH, got {spec!r}")
        label, path = spec.split("=", 1)
        zap_reports[label.strip()] = json.loads(Path(path.strip()).read_text())

    dvwa_label = args.dvwa_run or next(
        (label for label in runs if "dvwa" in label.lower()), None
    )

    sections = [
        "# Chapter 4 results tables (generated by analyze_runs.py)",
        "",
        "Every figure below is derived from the CI `report.json` artefacts. Two corrections",
        "are applied: provider-error records are excluded from detection counts (C1), and",
        "`targets/<name>/` path prefixes are stripped before any overlap join (C2).",
        "",
        "## Table 4.1 — Detection yield by source",
        table_detection_yield(runs),
        "",
        "## Table 4.2 — Runtime cost and projected pull-request cost",
        table_runtime(runs),
        "",
        "## Table 4.3 — Complementarity between the LLM stage and the scanners",
        table_complementarity(runs),
        "",
        "## Table 4.4 — Confidence calibration",
        table_calibration(runs),
        "",
        "## Table 4.5 — Structured-output and transport reliability",
        table_reliability(runs),
        "",
    ]

    if zap_reports:
        sections += [
            "## Table 4.7 — Dynamic analysis crawl coverage and risk distribution",
            table_dast_coverage(zap_reports),
            "",
        ]

    if dvwa_label and dvwa_label in runs:
        sections += [
            "## Table 4.6 — DVWA module coverage against the ground-truth map",
            table_dvwa_ground_truth(runs[dvwa_label]),
            "",
        ]

    for label, report in runs.items():
        sections += [
            f"## Agreement detail — {label}",
            table_agreement_detail(report, label),
            "",
        ]

    args.output.write_text("\n".join(sections))
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
