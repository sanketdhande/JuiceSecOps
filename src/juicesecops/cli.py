from __future__ import annotations

import argparse
from pathlib import Path

from .pipeline import run_pipeline
from .policy import Policy
from .providers import HeuristicProvider, HuggingFaceSecurityProvider
from .reporting import write_report


def _parse_context(values: list[str]) -> dict[str, str]:
    context: dict[str, str] = {}
    for item in values:
        key, _, value = item.partition("=")
        if key and value:
            context[key] = value
    return context


def _provider(name: str, model_id: str):
    if name == "huggingface":
        return HuggingFaceSecurityProvider(model=model_id)
    return HeuristicProvider()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="juicesecops",
        description="Run a Juice Shop DevSecOps security gate with scanner fusion and LLM review.",
    )
    parser.add_argument("--input", action="append", default=[], help="JSON scanner report path")
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
        choices=["heuristic", "huggingface"],
        default="heuristic",
        help="Security analysis provider.",
    )
    parser.add_argument(
        "--model-id",
        default="openai/gpt-oss-120b",
        help="Transformers model id for the Hugging Face provider.",
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
    existing_inputs = [Path(path) for path in args.input if Path(path).exists()]
    if not existing_inputs:
        parser.error("at least one existing --input report is required")

    policy = Policy.load(args.policy)
    provider = _provider(args.provider, args.model_id)
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
    write_report(args.output, report)
    if report.gate.passed or args.no_fail:
        return 0
    return 1
