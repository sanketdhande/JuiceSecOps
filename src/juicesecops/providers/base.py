from __future__ import annotations

from typing import Protocol

from ..models import CodeChange, Finding, TriageDecision


class RateLimitError(RuntimeError):
    """Raised by a provider when the API itself reports a rate limit
    (HTTP 429) that its own retry/backoff couldn't clear.

    pipeline.py treats this as a distinct signal from other provider
    failures: on RateLimitError it stops sending further requests to the
    provider for the rest of the run (there's no point retrying a
    rate-limited API call by call) and finishes the report with whatever
    was gathered so far, rather than looping through every remaining
    change/finding and hitting the same limit again for each one.
    """


class SecurityProvider(Protocol):
    """The "LLM" interface used by pipeline.py.

    Five concrete implementations exist:
    - OpenAISecurityProvider (openai.py): calls OpenAI's official Python
      SDK against the Responses API for `gpt-5.6-luna` by default. Requires
      an OPENAI_API_KEY and network access.
    - GroqSecurityProvider (groq.py): calls Groq's hosted, OpenAI-compatible
      chat-completions API for `openai/gpt-oss-20b`. No GPU or download
      needed, but requires a GROQ_API_KEY and network access. This is what
      CI workflows use, and the default provider.
    - OpenRouterSecurityProvider (openrouter.py): calls OpenRouter's official
      Python SDK, defaulting to `meta-llama/llama-3.3-70b-instruct` -- a
      different model/host than Groq, useful as a comparison point or an
      alternative if Groq is unavailable. Requires an OPENROUTER_API_KEY.
    - HuggingFaceSecurityProvider (huggingface.py): calls Hugging Face's
      Inference Providers router, also defaulting to `openai/gpt-oss-20b`
      but through a different hosted backend than Groq. Requires an
      HF_TOKEN.
    - LocalSecurityProvider (local.py): the odd one out -- runs a quantized
      GGUF build of `openai/gpt-oss-20b` in-process via llama.cpp instead of
      calling any hosted API. No account/API key/credit needed, only
      CPU/RAM/disk (and a one-time model download); meant as a fallback
      once hosted-API quota/credits run out. The other three are hosted
      APIs where no model weights are ever loaded or run on this machine.

    All five share their triage()/review_change() prompts and JSON parsing
    via _prompted.PromptedLLMProvider, so results are directly comparable
    across models/backends. Any other object with the same `name`/`model`
    attributes and `triage()`/`review_change()` methods is interchangeable
    from pipeline.py's point of view (tests use this to stub out the model
    call); it just calls review_change() then triage() on whichever one was
    passed in.
    """

    name: str
    model: str

    def triage(self, finding: Finding, context: dict[str, str]) -> TriageDecision: ...

    def review_change(self, change: CodeChange, context: dict[str, str]) -> list[Finding]: ...
