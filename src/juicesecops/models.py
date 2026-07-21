from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    UNKNOWN = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @classmethod
    def parse(cls, value: Any) -> Severity:
        if isinstance(value, cls):
            return value
        if isinstance(value, (int, float)):
            number = int(value)
            if 0 <= number <= 5:
                return cls(number)
        text = str(value or "unknown").strip().upper()
        try:
            cvss = float(text)
        except ValueError:
            pass
        else:
            if cvss >= 9.0:
                return cls.CRITICAL
            if cvss >= 7.0:
                return cls.HIGH
            if cvss >= 4.0:
                return cls.MEDIUM
            if cvss > 0:
                return cls.LOW
            return cls.INFO
        for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"):
            if text.startswith(name):
                return cls[name]
        aliases = {"WARNING": cls.MEDIUM, "ERROR": cls.HIGH, "NOTE": cls.INFO}
        return aliases.get(text, cls.UNKNOWN)

    def label(self) -> str:
        return self.name.lower()


@dataclass(slots=True)
class Location:
    path: str = ""
    line: int | None = None
    url: str = ""


@dataclass(slots=True)
class Finding:
    tool: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: str = "code"
    confidence: float = 0.5
    location: Location = field(default_factory=Location)
    cwe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    remediation: str = ""
    evidence: str = ""
    fingerprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["severity"] = self.severity.label()
        return value


@dataclass(slots=True)
class CodeChange:
    path: str
    status: str
    diff: str
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TriageDecision:
    finding_fingerprint: str
    disposition: str
    risk_score: int
    true_positive_likelihood: float
    exploitability: str
    summary: str
    rationale: str
    remediation: str
    provider: str
    model: str
    latency_ms: float
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class GateResult:
    passed: bool
    reasons: list[str]
    blocked_fingerprints: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PipelineReport:
    schema_version: str
    generated_at: str
    inputs: list[str]
    provider: str
    findings: list[Finding]
    decisions: list[TriageDecision]
    gate: GateResult
    changes: list[CodeChange] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "inputs": self.inputs,
            "provider": self.provider,
            "findings": [finding.to_dict() for finding in self.findings],
            "decisions": [decision.to_dict() for decision in self.decisions],
            "gate": self.gate.to_dict(),
            "changes": [change.to_dict() for change in self.changes],
            "metadata": self.metadata,
        }
