from __future__ import annotations

# The real LLM provider: every call below goes through the Hugging Face
# `transformers` text-generation pipeline against `self.model`
# (default openai/gpt-oss-120b). Select it with --provider huggingface (see
# cli.py's _provider()). No GitHub Actions workflow does this -- it only
# runs locally via scripts/run_juice_shop_pipeline_hf.sh, because the model
# is too large for a standard CI runner. CI uses HeuristicProvider instead
# (providers/heuristic.py), which has the same review_change()/triage()
# shape but is pure regex, no model call.
#
# triage()/review_change() themselves (prompts, JSON parsing) live in
# _prompted.py's PromptedLLMProvider so the smaller GgufSecurityProvider
# (gguf.py) asks the model the same questions and stays directly comparable.
from typing import Any

from ._prompted import PromptedLLMProvider


class HuggingFaceSecurityProvider(PromptedLLMProvider):
    name = "huggingface"

    def __init__(self, model: str = "openai/gpt-oss-120b", max_new_tokens: int = 768) -> None:
        self.model = model
        self.max_new_tokens = max_new_tokens
        self._pipe = None

    def _load_pipe(self) -> Any:
        # Lazily loads the model into memory/GPU on first use (not at
        # construction time), and caches it for the rest of the run.
        if self._pipe is not None:
            return self._pipe
        from transformers import pipeline

        self._pipe = pipeline(
            "text-generation",
            model=self.model,
            torch_dtype="auto",
            device_map="auto",
        )
        return self._pipe

    def _generate(self, messages: list[dict[str, str]]) -> str:
        # The actual model inference call, shared by triage() and
        # review_change() (both inherited from PromptedLLMProvider).
        pipe = self._load_pipe()
        outputs = pipe(
            messages,
            max_new_tokens=self.max_new_tokens,
            do_sample=False,
        )
        generated = outputs[0]["generated_text"]
        if isinstance(generated, list):
            last = generated[-1]
            if isinstance(last, dict):
                return str(last.get("content", ""))
            return str(last)
        return str(generated)
