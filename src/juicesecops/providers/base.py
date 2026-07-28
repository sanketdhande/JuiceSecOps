from __future__ import annotations

from typing import Protocol

from ..models import CodeChange, Finding, TriageDecision


class SecurityProvider(Protocol):
    """The "LLM" interface used by pipeline.py.

    One concrete implementation exists: HuggingFaceSecurityProvider
    (huggingface.py), which calls the `openai/gpt-oss-20b` model via the
    Hugging Face `transformers` text-generation pipeline. Any other object
    with the same `name`/`model` attributes and `triage()`/`review_change()`
    methods is interchangeable from pipeline.py's point of view (tests use
    this to stub out the model call); it just calls review_change() then
    triage() on whichever one was passed in.
    """

    name: str
    model: str

    def triage(self, finding: Finding, context: dict[str, str]) -> TriageDecision: ...

    def review_change(self, change: CodeChange, context: dict[str, str]) -> list[Finding]: ...
