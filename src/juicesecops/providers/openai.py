from __future__ import annotations

# Hosted LLM provider: calls OpenAI's official Python SDK against the
# Responses API, defaulting to gpt-5.6-luna. This keeps the same
# PromptedLLMProvider prompts/parsing used by the other providers, but
# swaps in a current OpenAI-hosted model instead of Groq/OpenRouter/HF.
#
# Requires OPENAI_API_KEY in the environment -- never pass it as
# --model-id or any other CLI argument, since argv ends up in shell
# history and CI logs are shared/retained.
import os
from typing import Any

from ._prompted import PromptedLLMProvider
from .base import RateLimitError

DEFAULT_MODEL = "gpt-5.6-luna"


class OpenAISecurityProvider(PromptedLLMProvider):
    """LLM review/triage via OpenAI's official Python SDK.

    `model` may be any OpenAI model id that supports text generation via
    the Responses API (defaults to `gpt-5.6-luna`).
    """

    name = "openai"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        max_new_tokens: int = 256,
        review_max_tokens: int = 1536,
    ) -> None:
        self.model = model
        self.max_new_tokens = max_new_tokens
        self.review_max_tokens = review_max_tokens
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Export it in the environment "
                "(e.g. `export OPENAI_API_KEY=...`) before using "
                "--provider openai -- never pass it as a CLI argument."
            )
        self._api_key = api_key
        self._client = None

    def _load_client(self) -> Any:
        # Lazily constructs the SDK client on first use (not at
        # construction time), and caches it for the rest of the run.
        if self._client is not None:
            return self._client
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError(
                "The `openai` package is not installed. Run "
                "`pip install -e '.[openai,dev]'` before using --provider openai."
            ) from exc
        self._client = OpenAI(api_key=self._api_key)
        return self._client

    def _generate(self, messages: list[dict[str, str]], *, max_tokens: int | None = None) -> str:
        # The actual model inference call, shared by triage() and
        # review_change() (both inherited from _prompted.PromptedLLMProvider).
        # review_change() passes its own (larger) max_tokens explicitly;
        # triage() omits it and gets self.max_new_tokens.
        client = self._load_client()
        try:
            response = client.responses.create(
                model=self.model,
                input=messages,
                max_output_tokens=max_tokens if max_tokens is not None else self.max_new_tokens,
                # GPT-5.6 models are reasoning models and reject `temperature`
                # outright (400: Unsupported parameter), so it is omitted here
                # unlike the other (non-reasoning) providers.
                # Security findings and diffs may contain sensitive code or
                # scanner output; do not retain these prompts by default.
                store=False,
                text={"format": {"type": "json_object"}},
            )
        except Exception as exc:
            if getattr(exc, "status_code", None) == 429:
                raise RateLimitError(str(exc)) from exc
            raise
        return _response_text(response)


def _response_text(response: Any) -> str:
    output_text = getattr(response, "output_text", None)
    if output_text:
        return str(output_text)

    for item in getattr(response, "output", []) or []:
        for content in getattr(item, "content", []) or []:
            if getattr(content, "type", None) == "output_text":
                text = getattr(content, "text", None)
                if text:
                    return str(text)

    raise RuntimeError("OpenAI response did not contain text output")
