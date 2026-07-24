from __future__ import annotations

# Free, open-weight security/code models sized for a single GPU (or a
# quantized CPU build) instead of the 120B-parameter model in
# huggingface.py. Reuses HuggingFaceSecurityProvider's transformers
# pipeline, prompts, and JSON parsing as-is -- the only difference is the
# curated MODEL_CHOICES list below and a much smaller default model, so
# review_change()/triage() behave identically from pipeline.py's point of
# view. Select it with --provider openweight (see cli.py's _provider()).
from .huggingface import HuggingFaceSecurityProvider

# Short alias -> Hugging Face repo id. All of these are open-weight (freely
# downloadable, no API key) and small enough to realistically load on a
# single consumer/CI GPU, unlike openai/gpt-oss-120b.
MODEL_CHOICES: dict[str, str] = {
    # Cisco Foundation AI: open-weight, instruction- and reasoning-tuned
    # specifically for cybersecurity tasks (the closest match to this
    # project's review_change()/triage() prompts).
    "foundation-sec-8b-reasoning": "fdtn-ai/Foundation-Sec-8B-Reasoning",
    "foundation-sec-8b": "fdtn-ai/Foundation-Sec-8B",
    # Qwen2.5-7B-Instruct fine-tuned by VextLabs on pentesting/offensive
    # security examples.
    "pentest-7b": "VextLabsinc/pentest-7b",
    # General-purpose open-weight coding models, useful as a non-security
    # baseline within the "open-weight" tier. Note: "Qwen3-Coder-7B-Instruct"
    # does not exist -- Qwen3-Coder only ships as 30B-A3B/480B-A35B MoE
    # models -- so this is Qwen's official dense 7B coding model instead.
    "qwen-coder-7b": "Qwen/Qwen2.5-Coder-7B-Instruct",
    "codegemma-7b": "google/codegemma-7b-it",
}

DEFAULT_MODEL_ALIAS = "foundation-sec-8b-reasoning"


class OpenWeightSecurityProvider(HuggingFaceSecurityProvider):
    """Curated free/open-weight models, sized to actually fit a CI-class host.

    Behaves exactly like HuggingFaceSecurityProvider (same prompts, same
    JSON-parsing, same transformers pipeline) -- see that class's docstring
    in base.py for the shared review_change()/triage() contract. The only
    difference is which model gets loaded: `model` may be a short alias from
    MODEL_CHOICES or any Hugging Face repo id.
    """

    name = "openweight"

    def __init__(
        self, model: str = DEFAULT_MODEL_ALIAS, max_new_tokens: int = 768
    ) -> None:
        resolved = MODEL_CHOICES.get(model, model)
        super().__init__(model=resolved, max_new_tokens=max_new_tokens)
