from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..models import Finding, Location, Severity


class ParseError(ValueError):
    """Raised when an input is not a supported scanner report."""


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)]


def _confidence(value: Any, default: float = 0.5) -> float:
    if isinstance(value, (float, int)):
        return min(1.0, max(0.0, float(value)))
    return {"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 0.9}.get(str(value).upper(), default)


def _fingerprint(finding: Finding) -> str:
    stable = "\x1f".join(
        [
            finding.tool.lower(),
            finding.rule_id.lower(),
            finding.location.path.lower(),
            str(finding.location.line or ""),
            finding.location.url.lower(),
            finding.title.lower(),
        ]
    )
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()[:20]


def _finish(finding: Finding) -> Finding:
    finding.fingerprint = finding.fingerprint or _fingerprint(finding)
    finding.confidence = min(1.0, max(0.0, finding.confidence))
    finding.references = sorted(set(finding.references))
    finding.cwe = sorted(set(finding.cwe))
    return finding


def _parse_semgrep(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {}) or {}
        start = item.get("start", {})
        findings.append(
            _finish(
                Finding(
                    tool="semgrep",
                    rule_id=str(item.get("check_id", "unknown")),
                    title=str(metadata.get("shortlink") or item.get("check_id") or "Semgrep finding"),
                    description=str(extra.get("message", "")),
                    severity=Severity.parse(extra.get("severity")),
                    category="code",
                    confidence=_confidence(metadata.get("confidence"), 0.7),
                    location=Location(path=str(item.get("path", "")), line=start.get("line")),
                    cwe=_list(metadata.get("cwe")),
                    references=_list(metadata.get("references")),
                    remediation=str(extra.get("fix", "")),
                    evidence=str(extra.get("lines", "")),
                    metadata={"owasp": _list(metadata.get("owasp"))},
                )
            )
        )
    return findings


def _parse_trivy(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("Results", []):
        target = str(result.get("Target", ""))
        for item in result.get("Vulnerabilities") or []:
            fixed = str(item.get("FixedVersion", ""))
            remediation = f"Upgrade {item.get('PkgName', 'package')} to {fixed}." if fixed else ""
            findings.append(
                _finish(
                    Finding(
                        tool="trivy",
                        rule_id=str(item.get("VulnerabilityID", "unknown")),
                        title=str(item.get("Title") or item.get("VulnerabilityID") or "Dependency finding"),
                        description=str(item.get("Description", "")),
                        severity=Severity.parse(item.get("Severity")),
                        category="dependency",
                        confidence=0.9,
                        location=Location(path=target),
                        cwe=_list(item.get("CweIDs")),
                        references=_list(item.get("References")) + _list(item.get("PrimaryURL")),
                        remediation=remediation,
                        evidence=f"{item.get('PkgName', '')}@{item.get('InstalledVersion', '')}",
                    )
                )
            )
        for item in result.get("Secrets") or []:
            findings.append(
                _finish(
                    Finding(
                        tool="trivy",
                        rule_id=str(item.get("RuleID", "secret")),
                        title=str(item.get("Title") or "Exposed secret"),
                        description=str(item.get("Match", "Secret-like value detected")),
                        severity=Severity.parse(item.get("Severity") or "critical"),
                        category="secret",
                        confidence=0.95,
                        location=Location(path=target, line=item.get("StartLine")),
                        remediation="Revoke and rotate the credential, then remove it from Git history.",
                        evidence=str(item.get("Match", "")),
                    )
                )
            )
    return findings


def _parse_zap(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    severity_by_code = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}
    for site in data.get("site", []):
        site_name = str(site.get("@name", ""))
        for alert in site.get("alerts", []):
            instances = alert.get("instances") or [{}]
            for instance in instances:
                risk = severity_by_code.get(
                    str(alert.get("riskcode")),
                    alert.get("riskdesc", "unknown"),
                )
                findings.append(
                    _finish(
                        Finding(
                            tool="zap",
                            rule_id=str(alert.get("pluginid", "unknown")),
                            title=str(alert.get("name") or alert.get("alert") or "ZAP alert"),
                            description=str(alert.get("desc", "")),
                            severity=Severity.parse(risk),
                            category="dynamic",
                            confidence=_confidence(alert.get("confidence"), 0.7),
                            location=Location(url=str(instance.get("uri") or site_name)),
                            cwe=_list(alert.get("cweid")),
                            references=_list(alert.get("reference")),
                            remediation=str(alert.get("solution", "")),
                            evidence=str(instance.get("evidence", "")),
                            metadata={"method": str(instance.get("method", ""))},
                        )
                    )
                )
    return findings


def _parse_generic(data: dict[str, Any] | list[Any]) -> list[Finding]:
    items = data if isinstance(data, list) else data.get("findings", [])
    findings: list[Finding] = []
    for item in items:
        location = item.get("location", {}) or {}
        findings.append(
            _finish(
                Finding(
                    tool=str(item.get("tool", "generic")),
                    rule_id=str(item.get("rule_id", "unknown")),
                    title=str(item.get("title", "Security finding")),
                    description=str(item.get("description", "")),
                    severity=Severity.parse(item.get("severity")),
                    category=str(item.get("category", "code")),
                    confidence=_confidence(item.get("confidence"), 0.5),
                    location=Location(
                        path=str(location.get("path", "")),
                        line=location.get("line"),
                        url=str(location.get("url", "")),
                    ),
                    cwe=_list(item.get("cwe")),
                    references=_list(item.get("references")),
                    remediation=str(item.get("remediation", "")),
                    evidence=str(item.get("evidence", "")),
                    metadata=dict(item.get("metadata", {})),
                )
            )
        )
    return findings


def finding_from_mapping(item: dict[str, Any]) -> Finding:
    return _parse_generic([item])[0]


def load_findings(path: str | Path) -> list[Finding]:
    report_path = Path(path)
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ParseError(f"Cannot parse {report_path}: {exc}") from exc

    if isinstance(data, list):
        return _parse_generic(data)
    if not isinstance(data, dict):
        raise ParseError(f"Unsupported JSON root in {report_path}")
    if "Results" in data:
        return _parse_trivy(data)
    if "site" in data:
        return _parse_zap(data)
    if "results" in data:
        return _parse_semgrep(data)
    if "findings" in data:
        return _parse_generic(data)
    raise ParseError(f"Unrecognized scanner report format: {report_path}")
