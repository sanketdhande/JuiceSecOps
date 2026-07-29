from __future__ import annotations

# CPU-only, credential-free LLM provider: runs a quantized GGUF build of
# openai/gpt-oss-20b via llama.cpp (the `llama-cpp-python` bindings)
# in-process, instead of calling a hosted API (groq.py/openrouter.py/
# huggingface.py). No account, API key, or per-request billing -- just a
# one-time (cached) download of the GGUF file from the Hugging Face Hub and
# whatever CPU/RAM the runner already has. This exists specifically for the
# case where hosted-API quota/credits (Groq, OpenRouter, or HF Inference
# Providers) run out: it needs no secret at all.
#
# Trade-off: quantized weights on CPU are much slower and lower-fidelity
# than any of the hosted providers, and the default GGUF file (~12GB, the
# same native MXFP4 quantization OpenAI ships -- there is no meaningfully
# smaller *quality* llama.cpp quant of this model) is already at the edge
# of what a standard GitHub-hosted runner's disk/RAM can hold. See
# juice-shop-security-report-local.yml / dvwa-security-report-local.yml for
# the disk-space workarounds that make it fit, and tune
# --model-id/max_changed_files (config/policy*.toml) down if a run doesn't
# finish in time.
#
# Select it with --provider local (cli.py's _provider()). triage()/
# review_change() (prompts, JSON parsing) are inherited from _prompted.py's
# PromptedLLMProvider; only _generate() (and the GGUF-specific loading/
# chat-template handling below) differs.
import os
from typing import Any

from ._prompted import PromptedLLMProvider

DEFAULT_REPO_ID = "ggml-org/gpt-oss-20b-GGUF"
DEFAULT_FILENAME = "gpt-oss-20b-MXFP4.gguf"
DEFAULT_MODEL = f"{DEFAULT_REPO_ID}:{DEFAULT_FILENAME}"


def _resolve(model: str) -> tuple[str, str]:
    """Return (repo_id, filename_glob) for a "repo_id:filename" string."""
    if ":" not in model:
        raise ValueError(
            f"Invalid --model-id {model!r} for --provider local: expected "
            f'"repo_id:filename-glob" (e.g. "{DEFAULT_MODEL}").'
        )
    repo_id, _, filename = model.partition(":")
    if not repo_id or not filename:
        raise ValueError(
            f"Invalid --model-id {model!r} for --provider local: expected "
            '"repo_id:filename-glob".'
        )
    return repo_id, filename


class LocalSecurityProvider(PromptedLLMProvider):
    """LLM review/triage via a local, in-process llama.cpp GGUF build.

    `model` is a "repo_id:filename-glob" string (defaults to the official
    llama.cpp GGUF build of openai/gpt-oss-20b). No API key needed -- the
    GGUF file is downloaded (and cached by huggingface_hub) on first use,
    not at construction time.
    """

    name = "local"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        max_new_tokens: int = 256,
        review_max_tokens: int = 1536,
        n_ctx: int = 4096,
    ) -> None:
        repo_id, filename = _resolve(model)
        self.repo_id = repo_id
        self.filename = filename
        self.model = f"{repo_id}:{filename}"
        self.max_new_tokens = max_new_tokens
        self.review_max_tokens = review_max_tokens
        self.n_ctx = n_ctx
        self._llm = None

    def _load_llm(self) -> Any:
        # Lazily downloads (cached by huggingface_hub) and loads the GGUF
        # file on first use, not at construction time, and caches the
        # loaded model for the rest of the run.
        if self._llm is not None:
            return self._llm
        from llama_cpp import Llama

        self._llm = Llama.from_pretrained(
            repo_id=self.repo_id,
            filename=self.filename,
            n_ctx=self.n_ctx,
            n_threads=os.cpu_count() or 4,
            verbose=False,
        )
        return self._llm

    def _generate(self, messages: list[dict[str, str]], *, max_tokens: int | None = None) -> str:
        # The actual model inference call, shared by triage() and
        # review_change() (both inherited from _prompted.PromptedLLMProvider).
        # review_change() passes its own (larger) max_tokens explicitly;
        # triage() omits it and gets self.max_new_tokens.
        llm = self._load_llm()
        response = llm.create_chat_completion(
            messages=_fold_system_into_user(messages),
            max_tokens=max_tokens if max_tokens is not None else self.max_new_tokens,
            temperature=0,
        )
        return str(response["choices"][0]["message"]["content"])


def _fold_system_into_user(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    # Some GGUF chat templates hard-reject a leading "system" role (e.g.
    # Gemma's raises "System role not supported" before generation starts,
    # regardless of what the message says). Folding the system text into
    # the first user turn is semantically equivalent for our single-turn
    # prompts and works whether or not the template supports a system role,
    # so do it unconditionally rather than special-casing affected models.
    if len(messages) >= 2 and messages[0]["role"] == "system" and messages[1]["role"] == "user":
        merged = {
            "role": "user",
            "content": f"{messages[0]['content']}\n\n{messages[1]['content']}",
        }
        return [merged, *messages[2:]]
    return messages
