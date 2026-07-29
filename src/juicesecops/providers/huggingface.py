from __future__ import annotations

# Hosted LLM provider: calls Hugging Face's Inference Providers router (an
# OpenAI-compatible chat-completions endpoint that fans out to whichever
# backend -- Together, Fireworks, Novita, etc. -- currently serves the
# requested model) for openai/gpt-oss-20b
# (https://huggingface.co/openai/gpt-oss-20b). Like groq.py and
# openrouter.py, this is a plain hosted API call: no local model weights,
# no GPU, no download. A prior HuggingFace provider loaded the model
# in-process via `transformers.pipeline(...)`, which needs a GPU/40GB+ RAM
# and was removed as impractical on a standard GitHub Actions runner; this
# one only needs an HF_TOKEN and network access, same as the other two
# providers.
#
# Requires an HF_TOKEN in the environment -- never pass it as --model-id or
# any other CLI argument, since argv ends up in shell history and CI logs
# are shared/retained.
import json
import os
import time
import urllib.error
import urllib.request

from ._prompted import PromptedLLMProvider
from .base import RateLimitError

API_URL = "https://router.huggingface.co/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-oss-20b"

# Mirrors groq.py: the router can return 429 under load; retry a handful of
# times with backoff before surfacing the error.
MAX_RETRIES = 3
RETRY_BASE_DELAY_SECONDS = 2.0


class HuggingFaceSecurityProvider(PromptedLLMProvider):
    """LLM review/triage via Hugging Face's hosted Inference Providers router.

    `model` may be any model id the router serves (defaults to
    `openai/gpt-oss-20b`).
    """

    name = "huggingface"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        max_new_tokens: int = 256,
        review_max_tokens: int = 1536,
    ) -> None:
        self.model = model
        self.max_new_tokens = max_new_tokens
        self.review_max_tokens = review_max_tokens
        api_key = os.environ.get("HF_TOKEN")
        if not api_key:
            raise RuntimeError(
                "HF_TOKEN is not set. Export it in the environment "
                "(e.g. `export HF_TOKEN=...`) before using "
                "--provider huggingface -- never pass it as a CLI argument."
            )
        self._api_key = api_key

    def _generate(self, messages: list[dict[str, str]], *, max_tokens: int | None = None) -> str:
        # The actual model inference call, shared by triage() and
        # review_change() (both inherited from _prompted.PromptedLLMProvider).
        # review_change() passes its own (larger) max_tokens explicitly;
        # triage() omits it and gets self.max_new_tokens.
        body = json.dumps(
            {
                "model": self.model,
                "messages": messages,
                "max_tokens": max_tokens if max_tokens is not None else self.max_new_tokens,
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
        last_error: RuntimeError | None = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                with urllib.request.urlopen(request, timeout=120) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                return str(payload["choices"][0]["message"]["content"])
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")
                if exc.code != 429:
                    raise RuntimeError(
                        f"Hugging Face request failed ({exc.code}): {detail}"
                    ) from exc
                last_error = RateLimitError(f"Hugging Face request failed ({exc.code}): {detail}")
                if attempt == MAX_RETRIES:
                    raise last_error from exc
                delay = self._retry_delay_seconds(exc, attempt)
                time.sleep(delay)
        raise last_error  # unreachable, satisfies type checkers

    @staticmethod
    def _retry_delay_seconds(exc: urllib.error.HTTPError, attempt: int) -> float:
        retry_after = exc.headers.get("Retry-After") if exc.headers else None
        if retry_after is not None:
            try:
                return max(0.0, float(retry_after))
            except ValueError:
                pass
        return RETRY_BASE_DELAY_SECONDS * (2**attempt)
