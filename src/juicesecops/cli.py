from __future__ import annotations

# Entry point: `python -m juicesecops ...` (see __main__.py). Called from
# .github/workflows/juice-shop-security-report.yml and the
# scripts/run_juice_shop_pipeline*.sh scripts after the scanners
# (Semgrep/Trivy/ZAP) have already produced their JSON reports on disk.
import argparse
from pathlib import Path

from .evaluation import evaluate_precision, summarize_findings
from .parsers import load_findings
from .pipeline import run_pipeline
from .policy import Policy
from .providers import (
    GROQ_DEFAULT_MODEL,
    HUGGINGFACE_DEFAULT_MODEL,
    LOCAL_DEFAULT_MODEL,
    OPENROUTER_DEFAULT_MODEL,
    GroqSecurityProvider,
    HuggingFaceSecurityProvider,
    LocalSecurityProvider,
    OpenRouterSecurityProvider,
)
from .reporting import print_report_summary, write_report


def _parse_context(values: list[str]) -> dict[str, str]:
    context: dict[str, str] = {}
    for item in values:
        key, _, value = item.partition("=")
        if key and value:
            context[key] = value
    return context


def _provider(name: str, model_id: str | None):
    # "groq" (default), "openrouter", and "huggingface" are hosted APIs --
    # no model weights ever run on this machine, but each needs its own
    # account/credit: "groq" calls Groq's hosted API for openai/gpt-oss-20b
    # (providers/groq.py) -- requires GROQ_API_KEY. Every default GitHub
    # Actions workflow passes --provider groq (or omits it, since that's the
    # default). "openrouter" calls OpenRouter's official Python SDK instead
    # (providers/openrouter.py), defaulting to a different model
    # (meta-llama/llama-3.3-70b-instruct) -- requires OPENROUTER_API_KEY.
    # "huggingface" calls Hugging Face's Inference Providers router instead
    # (providers/huggingface.py), also defaulting to openai/gpt-oss-20b --
    # requires HF_TOKEN. "local" instead runs a quantized GGUF build of
    # openai/gpt-oss-20b in-process via llama.cpp (providers/local.py) --
    # no API key/credit needed, only CPU/RAM/disk, since it's meant as a
    # fallback once hosted-API quota/credits run out.
    if name == "openrouter":
        return OpenRouterSecurityProvider(model=model_id or OPENROUTER_DEFAULT_MODEL)
    if name == "huggingface":
        return HuggingFaceSecurityProvider(model=model_id or HUGGINGFACE_DEFAULT_MODEL)
    if name == "local":
        return LocalSecurityProvider(model=model_id or LOCAL_DEFAULT_MODEL)
    return GroqSecurityProvider(model=model_id or GROQ_DEFAULT_MODEL)


def _existing_paths(values: list[str], label: str) -> list[Path]:
    paths = [Path(value) for value in values]
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        names = ", ".join(missing)
        raise argparse.ArgumentTypeError(f"missing {label} path(s): {names}")
    return paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="juicesecops",
        description="Run a Juice Shop DevSecOps security gate with scanner fusion and LLM review.",
    )
    parser.add_argument("--input", action="append", default=[], help="JSON scanner report path")
    parser.add_argument(
        "--ground-truth",
        action="append",
        default=[],
        help="Verified finding JSON path used for optional precision comparison.",
    )
    parser.add_argument(
        "--target-repo",
        default="targets/juice-shop",
        help="Path to the OWASP Juice Shop checkout to inspect for code changes.",
    )
    parser.add_argument(
        "--policy",
        default="config/policy.toml",
        help="Policy TOML file.",
    )
    parser.add_argument(
        "--provider",
        choices=["groq", "openrouter", "huggingface", "local"],
        default="groq",
        help=(
            "Security analysis provider: 'groq' calls Groq's hosted API (needs "
            "GROQ_API_KEY); 'openrouter' calls OpenRouter's official SDK instead (needs "
            "OPENROUTER_API_KEY); 'huggingface' calls Hugging Face's Inference Providers "
            "router instead (needs HF_TOKEN); 'local' runs a quantized GGUF build "
            "in-process via llama.cpp instead -- no API key/credit needed, only CPU/RAM."
        ),
    )
    parser.add_argument(
        "--model-id",
        default=None,
        help=(
            f"Model id to use. Defaults to {GROQ_DEFAULT_MODEL} for --provider groq, "
            f"{OPENROUTER_DEFAULT_MODEL} for --provider openrouter, "
            f"{HUGGINGFACE_DEFAULT_MODEL} for --provider huggingface, or "
            f"{LOCAL_DEFAULT_MODEL} for --provider local."
        ),
    )
    parser.add_argument("--base-ref", help="Base git ref for diff-based analysis.")
    parser.add_argument("--head-ref", default="HEAD", help="Head git ref for diff-based analysis.")
    parser.add_argument("--context", action="append", default=[], help="Context key=value pair.")
    parser.add_argument("--output", default="results/latest", help="Output directory.")
    parser.add_argument(
        "--skip-change-review",
        action="store_true",
        help="Disable LLM review of changed Juice Shop files.",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Always exit zero after writing reports.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        existing_inputs = _existing_paths(args.input, "--input")
        ground_truth_paths = _existing_paths(args.ground_truth, "--ground-truth")
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    if not existing_inputs:
        parser.error("at least one existing --input report is required")

    policy = Policy.load(args.policy)
    provider = _provider(args.provider, args.model_id)
    # Everything downstream (loading scanner findings, diffing the target
    # repo, calling the provider, gating) happens inside run_pipeline()
    # (pipeline.py).
    report = run_pipeline(
        inputs=existing_inputs,
        provider=provider,
        policy=policy,
        target_repo=Path(args.target_repo),
        context=_parse_context(args.context),
        base_ref=args.base_ref,
        head_ref=args.head_ref,
        review_changes=not args.skip_change_review,
    )
    report.metadata["finding_summary"] = summarize_findings(report.findings)
    if ground_truth_paths:
        ground_truth: list = []
        for path in ground_truth_paths:
            ground_truth.extend(load_findings(path))
        report.metadata["precision_comparison"] = evaluate_precision(
            report.findings, ground_truth
        )
    write_report(args.output, report)
    print_report_summary(report)
    if report.gate.passed or args.no_fail:
        return 0
    return 1
