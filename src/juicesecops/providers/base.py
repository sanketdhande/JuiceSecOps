from __future__ import annotations

from typing import Protocol

from ..models import CodeChange, Finding, TriageDecision


class SecurityProvider(Protocol):
    """The "LLM" interface used by pipeline.py.

    Two concrete implementations exist:
    - HeuristicProvider (heuristic.py): deterministic regex patterns, no
      model call. This is what runs in every GitHub Actions workflow.
    - HuggingFaceSecurityProvider (huggingface.py): a real call to the
      openai/gpt-oss-120b model via transformers. Local-only -- CI runners
      don't have the GPU/memory for it, so no workflow selects it.

    Both are interchangeable from pipeline.py's point of view: it just calls
    review_change() then triage() on whichever one was passed in.
    """

    name: str
    model: str

    def triage(self, finding: Finding, context: dict[str, str]) -> TriageDecision: ...

    def review_change(self, change: CodeChange, context: dict[str, str]) -> list[Finding]: ...
