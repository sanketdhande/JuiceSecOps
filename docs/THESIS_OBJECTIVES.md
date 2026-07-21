# Thesis Objective Mapping

## Objective 1

Analyze existing DevSecOps security testing techniques.

Project mapping:

- Semgrep models the SAST stage.
- Trivy models dependency, secret, and filesystem scanning.
- OWASP ZAP models DAST against the running Juice Shop instance.
- The report parser normalizes heterogeneous outputs into one internal schema.

## Objective 2

Evaluate the capabilities of Large Language Models for software vulnerability detection.

Project mapping:

- `providers/huggingface.py` integrates `openai/gpt-oss-120b`.
- The model reviews git diffs from Juice Shop and emits structured vulnerability candidates.
- The same model triages scanner findings to produce risk-oriented explanations.
- `providers/heuristic.py` supplies a non-LLM baseline for comparison.

## Objective 3

Design a DevSecOps pipeline architecture that integrates LLM-based security analysis.

Project mapping:

- The architecture is implemented directly in `pipeline.py`.
- Traditional scanners remain before and after the LLM stage.
- The LLM operates between static/dependency scanning and DAST, matching the thesis design.

## Objective 4

Implement a prototype system integrating traditional security tools and LLM-based vulnerability detection.

Project mapping:

- `scripts/run_juice_shop_pipeline.sh` demonstrates end-to-end orchestration.
- `.github/workflows/juice-shop-security.yml` provides a CI expression of the same design.
- `samples/reports/` and `scripts/run_demo.sh` allow local testing without every external dependency.

## Objective 5

Experimentally evaluate the effectiveness of the proposed system.

Project mapping:

- The project writes reproducible JSON artifacts.
- The heuristic baseline creates a clear comparison condition.
- The target application is fixed to a known Juice Shop checkout.
- The same policy and scanner inputs can be replayed across runs for thesis measurements.
