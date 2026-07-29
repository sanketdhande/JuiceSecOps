from __future__ import annotations

# Hosted LLM provider: calls OpenRouter's official Python SDK (the
# `openrouter` PyPI package) instead of calling Groq's API directly
# (groq.py). Defaults to meta-llama/llama-3.3-70b-instruct -- unlike Groq
# (which is sunsetting its own llama-3.3-70b-versatile on 2026-08-16, see
# providers/groq.py), OpenRouter's hosting of this model is unaffected,
# since it's a different provider/host entirely. No local model weights,
# no GPU, no download -- just an API call, at the cost of depending on
# OpenRouter's uptime and an API key. The SDK retries transient failures
# (429/5xx) itself, so _generate() below doesn't need its own backoff loop.
#
# Requires OPENROUTER_API_KEY in the environment -- never pass it as
# --model-id or any other CLI argument, since argv ends up in shell
# history and CI logs are shared/retained.
import os
from typing import Any

from ._prompted import PromptedLLMProvider
from .base import RateLimitError

DEFAULT_MODEL = "meta-llama/llama-3.3-70b-instruct"


class OpenRouterSecurityProvider(PromptedLLMProvider):
    """LLM review/triage via OpenRouter's official Python SDK.

    `model` may be any OpenRouter model id (defaults to
    `meta-llama/llama-3.3-70b-instruct`).
    """

    name = "openrouter"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        max_new_tokens: int = 256,
        review_max_tokens: int = 1536,
    ) -> None:
        self.model = model
        self.max_new_tokens = max_new_tokens
        self.review_max_tokens = review_max_tokens
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENROUTER_API_KEY is not set. Export it in the environment "
                "(e.g. `export OPENROUTER_API_KEY=...`) before using "
                "--provider openrouter -- never pass it as a CLI argument."
            )
        self._api_key = api_key
        self._client = None

    def _load_client(self) -> Any:
        # Lazily constructs the SDK client on first use (not at
        # construction time), and caches it for the rest of the run.
        if self._client is not None:
            return self._client
        from openrouter import OpenRouter

        self._client = OpenRouter(api_key=self._api_key)
        return self._client

    def _generate(self, messages: list[dict[str, str]], *, max_tokens: int | None = None) -> str:
        # The actual model inference call, shared by triage() and
        # review_change() (both inherited from _prompted.PromptedLLMProvider).
        # review_change() passes its own (larger) max_tokens explicitly;
        # triage() omits it and gets self.max_new_tokens.
        client = self._load_client()
        try:
            response = client.chat.send(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens if max_tokens is not None else self.max_new_tokens,
                temperature=0,
            )
        except Exception as exc:
            # The SDK's own retries (see module docstring) are exhausted by
            # the time this surfaces, so a 429 here means the rate limit
            # persisted -- raise RateLimitError so pipeline.py stops sending
            # further requests for the rest of this run.
            if getattr(exc, "status_code", None) == 429:
                raise RateLimitError(str(exc)) from exc
            raise
        return str(response.choices[0].message.content)
