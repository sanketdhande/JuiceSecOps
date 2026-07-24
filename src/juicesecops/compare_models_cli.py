from __future__ import annotations

# Entry point: `python -m juicesecops.compare_models_cli` or the
# `juicesecops-compare-models` console script (pyproject.toml). Called
# after a batch of `python -m juicesecops --provider gguf --model-id ...`
# runs (one per model, same scanner inputs) to merge their report.json
# files into one side-by-side comparison. See model_comparison.py for the
# merge logic and .github/workflows/juice-shop-security-report-
# openweight.yml for the workflow that drives this.
import argparse
import json
from pathlib import Path

from .model_comparison import (
    build_model_comparison,
    comparison_to_dict,
    load_pipeline_report,
    render_model_comparison_markdown,
)


def _parse_report_arg(value: str) -> tuple[str, Path]:
    label, sep, path = value.partition("=")
    if not sep or not label or not path:
        raise argparse.ArgumentTypeError(
            f"--report must be LABEL=path/to/report.json, got {value!r}"
        )
    report_path = Path(path)
    if not report_path.exists():
        raise argparse.ArgumentTypeError(f"report not found: {report_path}")
    return label, report_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="juicesecops-compare-models",
        description=(
            "Merge multiple juicesecops report.json files (one per LLM provider/model "
            "run against the same scanner inputs) into a single side-by-side comparison."
        ),
    )
    parser.add_argument(
        "--report",
        action="append",
        default=[],
        type=_parse_report_arg,
        metavar="LABEL=PATH",
        help=(
            "A model label and its report.json path, e.g. "
            "--report foundation-sec-8b-reasoning=results/ci/foundation-sec-8b-reasoning/"
            "report.json. Repeatable."
        ),
    )
    parser.add_argument(
        "--output",
        default="results/openweight-comparison",
        help="Output directory for comparison.json / comparison.md.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.report:
        parser.error("at least one --report LABEL=PATH is required")

    runs = {label: load_pipeline_report(path) for label, path in args.report}
    comparison = build_model_comparison(runs)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "comparison.json").write_text(
        json.dumps(comparison_to_dict(comparison), indent=2), encoding="utf-8"
    )
    (output_dir / "comparison.md").write_text(
        render_model_comparison_markdown(comparison), encoding="utf-8"
    )
    print(f"Wrote {output_dir / 'comparison.json'} and {output_dir / 'comparison.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
