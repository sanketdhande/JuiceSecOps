from __future__ import annotations

# CPU-friendly LLM provider: runs a quantized GGUF build of a small
# open-weight model via llama-cpp-python instead of full-precision
# transformers (huggingface.py/openweight.py, which need a GPU to be
# practical). This is the provider GitHub Actions uses for the multi-model
# comparison workflow (.github/workflows/juice-shop-security-report-
# openweight.yml) -- standard GitHub-hosted runners have no GPU, so a
# quantized model is the only way to get a real (if slower, lower-fidelity)
# LLM call to complete in CI. Select it with --provider gguf (cli.py's
# _provider()). triage()/review_change() (prompts, JSON parsing) are
# inherited from _prompted.py's PromptedLLMProvider.
import os
from typing import Any

from ._prompted import PromptedLLMProvider

# Short alias -> {repo_id, filename glob} for a quantized GGUF build on
# Hugging Face. Loaded lazily via llama_cpp.Llama.from_pretrained(), which
# downloads (and caches) the matching file straight from the repo.
#
# NOTE: this is a best-effort mapping. Community GGUF quantizations churn
# -- especially for smaller/niche security fine-tunes like
# foundation-sec-8b-reasoning or pentest-7b -- so a given repo/filename may
# be renamed, re-quantized, or simply not exist yet. Verify an entry on
# huggingface.co before depending on it for a real run; the CI workflow
# runs each model with continue-on-error so one missing quant doesn't sink
# the whole comparison. You can always bypass this table entirely by
# passing --model-id "<repo_id>:<filename-glob>" directly.
GGUF_MODEL_CHOICES: dict[str, dict[str, str]] = {
    "foundation-sec-8b-reasoning": {
        "repo_id": "fdtn-ai/Foundation-Sec-8B-Reasoning-GGUF",
        "filename": "*Q4_K_M.gguf",
    },
    "foundation-sec-8b": {
        "repo_id": "fdtn-ai/Foundation-Sec-8B-GGUF",
        "filename": "*Q4_K_M.gguf",
    },
    "pentest-7b": {
        "repo_id": "VextLabsinc/pentest-7b-GGUF",
        "filename": "*Q4_K_M.gguf",
    },
    "qwen3-coder-7b": {
        "repo_id": "bartowski/Qwen3-Coder-7B-Instruct-GGUF",
        "filename": "*Q4_K_M.gguf",
    },
    "codegemma-7b": {
        "repo_id": "bartowski/codegemma-7b-it-GGUF",
        "filename": "*Q4_K_M.gguf",
    },
}

DEFAULT_MODEL_ALIAS = "foundation-sec-8b-reasoning"


def _resolve(model: str) -> tuple[str, str]:
    """Return (repo_id, filename_glob) for an alias, an explicit
    "repo_id:filename" string, or raise for anything else."""
    choice = GGUF_MODEL_CHOICES.get(model)
    if choice is not None:
        return choice["repo_id"], choice["filename"]
    if ":" in model:
        repo_id, _, filename = model.partition(":")
        if repo_id and filename:
            return repo_id, filename
    raise ValueError(
        f"Unknown GGUF model {model!r}: pass a known alias "
        f"({', '.join(sorted(GGUF_MODEL_CHOICES))}) or an explicit "
        '"repo_id:filename-glob" string.'
    )


class GgufSecurityProvider(PromptedLLMProvider):
    """Quantized open-weight security/code models via llama.cpp (CPU-only).

    `model` may be a short alias from GGUF_MODEL_CHOICES or an explicit
    "repo_id:filename-glob" string. The resolved "repo_id:filename" is what
    gets recorded as `self.model` (and therefore in reports), so different
    quantizations of the same base model are distinguishable.
    """

    name = "gguf"

    def __init__(
        self,
        model: str = DEFAULT_MODEL_ALIAS,
        max_new_tokens: int = 768,
        n_ctx: int = 4096,
    ) -> None:
        repo_id, filename = _resolve(model)
        self.repo_id = repo_id
        self.filename = filename
        self.model = f"{repo_id}:{filename}"
        self.max_new_tokens = max_new_tokens
        self.n_ctx = n_ctx
        self._llm = None

    def _load_llm(self) -> Any:
        # Lazily downloads (cached by huggingface_hub) and loads the GGUF
        # file on first use, not at construction time.
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

    def _generate(self, messages: list[dict[str, str]]) -> str:
        # The actual model inference call, shared by triage() and
        # review_change() (both inherited from PromptedLLMProvider).
        llm = self._load_llm()
        response = llm.create_chat_completion(
            messages=messages,
            max_tokens=self.max_new_tokens,
            temperature=0,
        )
        return str(response["choices"][0]["message"]["content"])
