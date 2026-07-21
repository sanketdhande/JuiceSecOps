from __future__ import annotations

from typing import Protocol

from ..models import CodeChange, Finding, TriageDecision


class SecurityProvider(Protocol):
    name: str
    model: str

    def triage(self, finding: Finding, context: dict[str, str]) -> TriageDecision: ...

    def review_change(self, change: CodeChange, context: dict[str, str]) -> list[Finding]: ...
