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
# NOTE: this is a best-effort mapping, spot-checked against huggingface.co
# search results but not by actually downloading every file. Community GGUF
# quantizations churn -- especially for smaller/niche security fine-tunes --
# so a given repo/filename may be renamed, re-quantized, or removed. The CI
# workflow runs each model with continue-on-error so one missing/broken
# quant doesn't sink the whole comparison. You can always bypass this table
# entirely by passing --model-id "<repo_id>:<filename-glob>" directly.
#
# "pentest-7b" was removed from this table: VextLabsinc/pentest-7b (see
# openweight.py, which uses it directly via transformers) has no .gguf file
# on huggingface.co at all -- confirmed via the HF API's model-info
# `siblings` list, not just a guess -- so Llama.from_pretrained() can never
# find a match and every call fails instantly. If a real GGUF quant of it
# shows up later, add it back with a repo_id that actually hosts a .gguf.
GGUF_MODEL_CHOICES: dict[str, dict[str, str]] = {
    # Single-file repos (GGUF-my-repo style) -- "*.gguf" is unambiguous
    # since each repo holds exactly one quantized file.
    "foundation-sec-8b-reasoning": {
        "repo_id": "fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF",
        "filename": "*.gguf",
    },
    "foundation-sec-8b": {
        "repo_id": "fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF",
        "filename": "*.gguf",
    },
    # Note: "Qwen3-Coder-7B-Instruct" does not exist (Qwen3-Coder only
    # ships as 30B-A3B/480B-A35B MoE models) -- this is the closest real
    # equivalent, Qwen's official dense 7B coding model.
    "qwen-coder-7b": {
        "repo_id": "Qwen/Qwen2.5-Coder-7B-Instruct-GGUF",
        "filename": "*q4_k_m.gguf",
    },
    # Multi-quant repo -- needs the specific suffix, not a bare "*.gguf".
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
            messages=_fold_system_into_user(messages),
            max_tokens=self.max_new_tokens,
            temperature=0,
        )
        return str(response["choices"][0]["message"]["content"])


def _fold_system_into_user(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    # Some GGUF chat templates -- Gemma's in particular -- hard-reject a
    # leading "system" role ("System role not supported"): the template
    # itself raises before generation starts, regardless of what the
    # message says. Folding the system text into the first user turn is
    # semantically equivalent for our single-turn prompts and works
    # whether or not the template supports a system role, so do it
    # unconditionally rather than special-casing affected models.
    if len(messages) >= 2 and messages[0]["role"] == "system" and messages[1]["role"] == "user":
        merged = {
            "role": "user",
            "content": f"{messages[0]['content']}\n\n{messages[1]['content']}",
        }
        return [merged, *messages[2:]]
    return messages
