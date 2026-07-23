from __future__ import annotations

import hashlib
import re
import time

from ..models import CodeChange, Finding, Location, Severity, TriageDecision

_BASE = {
    Severity.UNKNOWN: 0.10,
    Severity.INFO: 0.05,
    Severity.LOW: 0.20,
    Severity.MEDIUM: 0.45,
    Severity.HIGH: 0.70,
    Severity.CRITICAL: 0.90,
}
_EXPLOIT = {"confirmed": 0.18, "likely": 0.08, "possible": 0.03, "unknown": 0.0, "unlikely": -0.20}
_EXPOSURE = {"internet": 0.12, "internal": 0.03, "local": -0.10, "unknown": 0.0}

_CHANGE_PATTERNS = [
    {
        "regex": r"sequelize\.query\(.+\$\{.+\}",
        "rule_id": "llm.sqli.template",
        "title": "Potential SQL injection in raw query",
        "severity": "high",
        "category": "code",
        "remediation": "Use parameterized Sequelize replacements or ORM query builders.",
        "description": (
            "String interpolation in a raw SQL query can allow untrusted input to reach "
            "the database."
        ),
        "cwe": ["CWE-89"],
        "confidence": 0.87,
    },
    {
        "regex": r"(innerHTML\s*=|bypassSecurityTrust|sanitizeBypass)",
        "rule_id": "llm.xss.dom",
        "title": "Potential DOM XSS sink introduced",
        "severity": "high",
        "category": "code",
        "remediation": "Avoid unsafe HTML sinks and keep Angular sanitization enabled.",
        "description": (
            "A DOM sink that accepts HTML can enable cross-site scripting if attacker "
            "input reaches it."
        ),
        "cwe": ["CWE-79"],
        "confidence": 0.84,
    },
    {
        "regex": r"\b(eval|Function)\s*\(",
        "rule_id": "llm.code.exec",
        "title": "Dynamic code execution introduced",
        "severity": "high",
        "category": "code",
        "remediation": (
            "Remove dynamic evaluation and use explicit parsing or allowlisted dispatch."
        ),
        "description": "Dynamic code execution increases the risk of code injection.",
        "cwe": ["CWE-94"],
        "confidence": 0.91,
    },
    {
        "regex": r"\b(exec|spawn)\s*\(",
        "rule_id": "llm.command.exec",
        "title": "Potential command injection path",
        "severity": "high",
        "category": "code",
        "remediation": "Avoid shell execution or allowlist arguments before invoking subprocesses.",
        "description": (
            "Command execution primitives become dangerous when fed with request-"
            "controlled values."
        ),
        "cwe": ["CWE-78"],
        "confidence": 0.85,
    },
    {
        "regex": r"res\.redirect\(.+req\.(query|params|body)",
        "rule_id": "llm.open.redirect",
        "title": "Potential open redirect from request input",
        "severity": "medium",
        "category": "code",
        "remediation": "Redirect only to allowlisted internal routes or trusted hosts.",
        "description": (
            "Directly redirecting to user-controlled input can enable phishing and token "
            "leakage."
        ),
        "cwe": ["CWE-601"],
        "confidence": 0.78,
    },
    {
        "regex": r"fs\.(readFile|writeFile|createReadStream).+req\.(query|params|body)",
        "rule_id": "llm.path.traversal",
        "title": "Potential path traversal",
        "severity": "high",
        "category": "code",
        "remediation": "Normalize and allowlist paths before filesystem access.",
        "description": "Request-controlled paths can let an attacker reach unintended files.",
        "cwe": ["CWE-22"],
        "confidence": 0.82,
    },
    {
        "regex": r"(secret|password|token|jwt).{0,15}[:=].{0,5}[\"'][^\"']{1,16}[\"']",
        "rule_id": "llm.hardcoded.secret",
        "title": "Potential hardcoded or weak secret",
        "severity": "high",
        "category": "secret",
        "remediation": "Move secrets to CI/CD secret storage and rotate any exposed values.",
        "description": (
            "Committed secrets weaken the pipeline and frequently become reusable "
            "credentials."
        ),
        "cwe": ["CWE-798"],
        "confidence": 0.90,
    },
]


def _risk(finding: Finding, context: dict[str, str]) -> tuple[int, str]:
    exploitability = str(
        context.get("exploitability") or finding.metadata.get("exploitability") or "unknown"
    ).lower()
    exposure = str(context.get("exposure") or finding.metadata.get("exposure") or "unknown").lower()
    score = _BASE[finding.severity]
    score += _EXPLOIT.get(exploitability, 0.0)
    score += _EXPOSURE.get(exposure, 0.0)
    score += 0.20 * (finding.confidence - 0.5)
    if finding.category == "secret":
        score = max(score, 0.95)
    return round(min(1.0, max(0.0, score)) * 100), exploitability


def _added_lines(diff: str) -> list[tuple[int | None, str]]:
    result: list[tuple[int | None, str]] = []
    current_line: int | None = None
    for raw_line in diff.splitlines():
        if raw_line.startswith("@@"):
            match = re.search(r"\+(\d+)", raw_line)
            current_line = int(match.group(1)) if match else None
            continue
        if raw_line.startswith("+++"):
            continue
        if raw_line.startswith("+"):
            result.append((current_line, raw_line[1:]))
            if current_line is not None:
                current_line += 1
            continue
        if raw_line.startswith("-") or raw_line.startswith("---"):
            continue
        if current_line is not None:
            current_line += 1
    return result


def _finding_fingerprint(path: str, rule_id: str, line: int | None) -> str:
    stable = f"llm-diff\x1f{rule_id}\x1f{path}\x1f{line or ''}"
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()[:20]


class HeuristicProvider:
    name = "heuristic"
    model = "juice-shop-context-v1"

    def triage(self, finding: Finding, context: dict[str, str]) -> TriageDecision:
        start = time.perf_counter()
        risk, exploitability = _risk(finding, context)
        if risk >= 70:
            disposition = "block"
        elif risk >= 45:
            disposition = "review"
        else:
            disposition = "accept"
        return TriageDecision(
            finding_fingerprint=finding.fingerprint,
            disposition=disposition,
            risk_score=risk,
            true_positive_likelihood=round(finding.confidence, 3),
            exploitability=exploitability,
            summary=f"{finding.severity.label()} {finding.category} finding from {finding.tool}",
            rationale=(
                "Deterministic context score combines severity, confidence, exposure, and "
                f"{exploitability} exploitability."
            ),
            remediation=(
                finding.remediation or "Review the finding and apply a least-privilege fix."
            ),
            provider=self.name,
            model=self.model,
            latency_ms=round((time.perf_counter() - start) * 1000, 3),
        )

    def review_change(self, change: CodeChange, context: dict[str, str]) -> list[Finding]:
        del context
        findings: list[Finding] = []
        added_lines = _added_lines(change.diff)
        for line_number, line in added_lines:
            for pattern in _CHANGE_PATTERNS:
                if not re.search(pattern["regex"], line, re.IGNORECASE):
                    continue
                findings.append(
                    Finding(
                        tool="llm-diff",
                        rule_id=pattern["rule_id"],
                        title=pattern["title"],
                        description=pattern["description"],
                        severity=Severity.parse(pattern["severity"]),
                        category=pattern["category"],
                        confidence=pattern["confidence"],
                        location=Location(path=change.path, line=line_number),
                        cwe=list(pattern["cwe"]),
                        remediation=pattern["remediation"],
                        evidence=line[:200],
                        fingerprint=_finding_fingerprint(
                            change.path, pattern["rule_id"], line_number
                        ),
                        metadata={"source": "diff-review"},
                    )
                )
        return findings
