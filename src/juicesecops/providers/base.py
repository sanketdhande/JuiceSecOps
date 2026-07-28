from __future__ import annotations

from typing import Protocol

from ..models import CodeChange, Finding, TriageDecision


class SecurityProvider(Protocol):
    """The "LLM" interface used by pipeline.py.

    Two concrete implementations exist. Both are hosted APIs -- no model
    weights are ever loaded or run on this machine:
    - GroqSecurityProvider (groq.py): calls Groq's hosted, OpenAI-compatible
      chat-completions API for `openai/gpt-oss-120b`. No GPU or download
      needed, but requires a GROQ_API_KEY and network access. This is what
      CI workflows use, and the default provider.
    - OpenRouterSecurityProvider (openrouter.py): calls OpenRouter's official
      Python SDK, defaulting to `meta-llama/llama-3.3-70b-instruct` -- a
      different model/host than Groq, useful as a comparison point or an
      alternative if Groq is unavailable. Requires an OPENROUTER_API_KEY.

    Both share their triage()/review_change() prompts and JSON parsing via
    _prompted.PromptedLLMProvider, so results are directly comparable across
    models/backends. Any other object with the same `name`/`model`
    attributes and `triage()`/`review_change()` methods is interchangeable
    from pipeline.py's point of view (tests use this to stub out the model
    call); it just calls review_change() then triage() on whichever one was
    passed in.
    """

    name: str
    model: str

    def triage(self, finding: Finding, context: dict[str, str]) -> TriageDecision: ...

    def review_change(self, change: CodeChange, context: dict[str, str]) -> list[Finding]: ...
