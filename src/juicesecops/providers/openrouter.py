from __future__ import annotations

# API-based LLM provider: calls OpenRouter's OpenAI-compatible chat
# completions endpoint over HTTPS instead of loading model weights locally
# (huggingface.py/gguf.py/openweight.py). This lets --provider openrouter
# reach models too large to run locally (including free-tier builds) with
# no GPU and no download, at the cost of depending on OpenRouter's uptime
# and an API key. Select it with --provider openrouter (cli.py's
# _provider()). triage()/review_change() are inherited from _prompted.py's
# PromptedLLMProvider, same as every other LLM-backed provider, so results
# stay comparable across backends.
import json
import os
import urllib.error
import urllib.request

from ._prompted import PromptedLLMProvider

API_URL = "https://openrouter.ai/api/v1/chat/completions"

# Short alias -> OpenRouter model id, restricted to models that were on
# OpenRouter's free tier (":free" suffix, $0 prompt/completion price) when
# checked against the live https://openrouter.ai/api/v1/models response on
# 2026-07-25. No meta-llama model was on the free tier at that time (all
# Llama entries were paid, $0.00000005+/token) -- if that changes, add an
# alias for it here. Free-tier availability churns as OpenRouter rotates
# which models are sponsored, so an alias below can stop being free later.
# You can always bypass this table by passing --model-id "<any-openrouter-
# model-id>" directly (paid models work too, if OPENROUTER_API_KEY has
# credit).
OPENROUTER_MODEL_CHOICES: dict[str, str] = {
    "gpt-oss-20b-free": "openai/gpt-oss-20b:free",
    "gemma-4-31b-free": "google/gemma-4-31b-it:free",
    "nemotron-nano-30b-free": "nvidia/nemotron-3-nano-30b-a3b:free",
}

DEFAULT_MODEL_ALIAS = "gpt-oss-20b-free"


def _resolve(model: str) -> str:
    """Short alias -> OpenRouter model id, or pass through anything else
    (e.g. an explicit "org/model" id, free or paid) unchanged."""
    return OPENROUTER_MODEL_CHOICES.get(model, model)


class OpenRouterSecurityProvider(PromptedLLMProvider):
    """LLM review/triage via OpenRouter's hosted chat-completions API.

    `model` may be a short alias from OPENROUTER_MODEL_CHOICES or any
    OpenRouter model id directly (e.g. "meta-llama/llama-3.1-8b-instruct").
    Requires OPENROUTER_API_KEY in the environment -- never pass the key as
    a CLI argument or commit it, since argv ends up in shell history and
    process listings, and CI logs are shared/retained.
    """

    name = "openrouter"

    def __init__(self, model: str = DEFAULT_MODEL_ALIAS, max_new_tokens: int = 768) -> None:
        self.model = _resolve(model)
        self.max_new_tokens = max_new_tokens
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENROUTER_API_KEY is not set. Export it in the environment "
                "(e.g. `export OPENROUTER_API_KEY=...`) before using "
                "--provider openrouter -- never pass it as a CLI argument."
            )
        self._api_key = api_key

    def _generate(self, messages: list[dict[str, str]]) -> str:
        # The actual model inference call, shared by triage() and
        # review_change() (both inherited from PromptedLLMProvider).
        body = json.dumps(
            {
                "model": self.model,
                "messages": messages,
                "max_tokens": self.max_new_tokens,
                "temperature": 0,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            API_URL,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"OpenRouter request failed ({exc.code}): {detail}") from exc
        return str(payload["choices"][0]["message"]["content"])
