from __future__ import annotations

# Hosted LLM provider: calls Groq's OpenAI-compatible chat-completions API
# for openai/gpt-oss-20b. No local model weights, no GPU, no download --
# just an HTTPS call -- and, for this exact model, genuinely free: per
# Groq's docs (https://console.groq.com/docs/rate-limits), the free tier
# for openai/gpt-oss-20b is 30 requests/minute, 1,000 requests/day, and
# 200K tokens/day, no credit card required. OpenRouter also has a free
# (":free" suffix) tier for this exact model, but it's more limited: 20
# requests/minute and only 50 requests/day without $10+ of purchased
# credit. This is the default provider, and the one CI workflows use.
#
# Requires a GROQ_API_KEY in the environment -- never pass it as
# --model-id or any other CLI argument, since argv ends up in shell
# history and CI logs are shared/retained.
import json
import os
import time
import urllib.error
import urllib.request

from ._prompted import PromptedLLMProvider
from .base import RateLimitError

API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-oss-20b"

# Groq's API sits behind Cloudflare, and Cloudflare's "browser integrity
# check" rejects the default User-Agent urllib.request sends
# ("Python-urllib/3.x") with a 403 ("error code: 1010") before the request
# ever reaches Groq -- confirmed on Groq's own community forum
# (https://community.groq.com/t/cloudflare-blocking-urllib-request-without-user-agent/860).
# Sending a browser-like User-Agent instead clears that check; this has no
# bearing on authentication, which is still the Authorization header below.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Groq's free tier returns 429 under load; retry a handful of times with
# backoff before surfacing the error, since a single retry after a few
# seconds usually clears a transient rate limit.
MAX_RETRIES = 3
RETRY_BASE_DELAY_SECONDS = 2.0


class GroqSecurityProvider(PromptedLLMProvider):
    """LLM review/triage via Groq's hosted `openai/gpt-oss-20b` API.

    `model` may be any Groq model id (defaults to `openai/gpt-oss-20b`).
    """

    name = "groq"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        max_new_tokens: int = 256,
        review_max_tokens: int = 1536,
    ) -> None:
        self.model = model
        self.max_new_tokens = max_new_tokens
        self.review_max_tokens = review_max_tokens
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GROQ_API_KEY is not set. Export it in the environment "
                "(e.g. `export GROQ_API_KEY=...`) before using "
                "--provider groq -- never pass it as a CLI argument."
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
                "max_completion_tokens": (
                    max_tokens if max_tokens is not None else self.max_new_tokens
                ),
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
                "User-Agent": USER_AGENT,
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
                    raise RuntimeError(f"Groq request failed ({exc.code}): {detail}") from exc
                last_error = RateLimitError(f"Groq request failed ({exc.code}): {detail}")
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
