from __future__ import annotations

from typing import Protocol

from ..models import CodeChange, Finding, TriageDecision


class SecurityProvider(Protocol):
    """The "LLM" interface used by pipeline.py.

    Four concrete implementations exist:
    - HeuristicProvider (heuristic.py): deterministic regex patterns, no
      model call. This is what the default report workflow runs.
    - HuggingFaceSecurityProvider (huggingface.py): a real call to the
      openai/gpt-oss-120b model via transformers. Local-only -- CI runners
      don't have the GPU/memory for it, so no workflow selects it.
    - OpenWeightSecurityProvider (openweight.py): same transformers-based
      call as HuggingFaceSecurityProvider, but defaults to a curated list of
      much smaller open-weight security/code models (e.g. Foundation-Sec-8B)
      that can realistically fit a single GPU host.
    - GgufSecurityProvider (gguf.py): quantized GGUF builds of those same
      small open-weight models via llama.cpp, sized to run CPU-only --
      this is what the multi-model comparison workflow
      (juice-shop-security-report-openweight.yml) runs in GitHub Actions.

    HuggingFaceSecurityProvider and GgufSecurityProvider share their
    triage()/review_change() prompts and JSON parsing via
    _prompted.PromptedLLMProvider, so results are directly comparable
    across inference backends. All four providers are interchangeable from
    pipeline.py's point of view: it just calls review_change() then
    triage() on whichever one was passed in.
    """

    name: str
    model: str

    def triage(self, finding: Finding, context: dict[str, str]) -> TriageDecision: ...

    def review_change(self, change: CodeChange, context: dict[str, str]) -> list[Finding]: ...
