# Thesis Objective Mapping

## Primary research question

How can Large Language Models be effectively integrated into DevSecOps pipelines to improve automated security testing?

## Supporting research questions

1. How accurately can LLMs detect software vulnerabilities compared with traditional static analysis tools?
2. What types of vulnerabilities can LLM-based analysis detect that traditional tools may miss?
3. How can LLM-based vulnerability analysis be integrated into CI/CD pipelines without significantly increasing pipeline execution time?
4. What limitations and security risks arise when using LLMs for automated security testing?

## Scope

- In scope: literature review, DevSecOps pipeline design, prototype implementation, and empirical evaluation using intentionally vulnerable software.
- Out of scope: adversarial attacks on machine learning models and broader AI safety topics outside CI/CD vulnerability detection.

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
- `.github/workflows/` provides split CI workflows for linting, security reporting, Semgrep, Trivy, and ZAP.
- `samples/reports/` and `scripts/run_demo.sh` allow local testing without every external dependency.

## Objective 5

Experimentally evaluate the effectiveness of the proposed system.

Project mapping:

- The project writes reproducible JSON artifacts.
- The heuristic baseline creates a clear comparison condition.
- The target application is fixed to a known Juice Shop checkout.
- The same policy and scanner inputs can be replayed across runs for thesis measurements.

## Methodology mapping

### Literature review

- The repository documents the relationship between DevSecOps stages, scanner evidence, and LLM reasoning.
- The architecture and objective mapping files provide traceable justification for the implementation choices.

### System design

- The LLM sits beside traditional controls rather than replacing them.
- The deterministic gate remains the final enforcement layer so the pipeline can tolerate model failures and hallucinations.

### Prototype implementation

- The orchestration layer is implemented in Python.
- The CI/CD examples are implemented with GitHub Actions.
- The traditional security stages use Semgrep, Trivy, and OWASP ZAP.
- The LLM integration is pluggable so the thesis can compare heuristic and model-assisted conditions.

### Experimental evaluation

- The current repository implements OWASP Juice Shop as the primary intentionally vulnerable target.
- Report artifacts expose findings, triage outcomes, gate decisions, and runtime metadata for analysis.
- The evaluation design can be extended to DVWA or vulnerable microservices if required later in the thesis.

## Expected contributions

1. A concrete framework for placing LLM-based vulnerability analysis inside a DevSecOps pipeline.
2. A working prototype that combines traditional scanner evidence with LLM-assisted review.
3. A reproducible basis for comparing vulnerability detection coverage, false positives, and runtime.
4. Practical guidance on the benefits, limits, and operational risks of LLM use in CI/CD security testing.
