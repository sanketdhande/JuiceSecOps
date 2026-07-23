# Architecture

## Design

This prototype keeps the traditional DevSecOps tools as evidence producers and uses the LLM as an additional reasoning stage rather than a replacement for scanners.

The design is intentionally thesis-driven: it focuses on automated security testing during CI/CD, measures what the LLM adds relative to conventional scanners, and keeps the model outside the final enforcement boundary.

## Pipeline stages

1. A developer changes code in OWASP Juice Shop.
2. The CI/CD job collects code diffs from the target repository.
3. Semgrep performs SAST on the source tree.
4. Trivy performs dependency, secret, and filesystem scanning.
5. The LLM reviews changed files and generates candidate vulnerabilities from the diff.
6. The same provider triages both scanner findings and LLM-generated findings.
7. OWASP ZAP supplies DAST evidence for the running application.
8. A deterministic gate applies severity floors, secret rules, and risk thresholds.
9. A JSON and Markdown report is written for the experiment record.

## Research alignment

This architecture is intended to answer the thesis research questions in a measurable way:

1. Accuracy versus traditional tools: the pipeline preserves Semgrep, Trivy, and ZAP outputs as a baseline while recording LLM-originated findings separately.
2. Incremental vulnerability coverage: diff-review findings from the LLM can be compared against scanner findings to identify additional contextual detections.
3. CI/CD runtime impact: the report metadata records end-to-end duration so the extra cost of the LLM stage can be measured.
4. Limitations and risks: provider failures, hallucinations, and untrusted input boundaries are explicitly modeled rather than hidden.

## Rationale for Juice Shop

OWASP Juice Shop is appropriate for this thesis because it is intentionally vulnerable, actively maintained, broad in vulnerability coverage, and practical for both source-code and running-application testing.

The local helper script fetches a fresh shallow checkout into `targets/juice-shop`. A checkout cloned on July 21, 2026 identified the target version used for this prototype as Juice Shop `20.1.1`.

## Component map

| Component | Role |
|---|---|
| `scripts/fetch_juice_shop.sh` | Fetches the target application into `targets/juice-shop/` |
| `parsers/reports.py` | Normalizes Semgrep, Trivy, ZAP, and generic JSON |
| `diffing.py` | Extracts changed Juice Shop files from git |
| `providers/heuristic.py` | Offline baseline for experiments and tests |
| `providers/huggingface.py` | `openai/gpt-oss-120b` integration |
| `pipeline.py` | Orchestration for change review, triage, and gating |
| `policy.py` | Deterministic control layer |
| `reporting.py` | JSON and Markdown evidence output |

## Trust boundaries

- Scanner reports are untrusted input.
- Git diffs are untrusted input.
- The LLM provider is partially trusted and may fail or hallucinate.
- The policy gate is trusted and final.
- Reports are auditable artifacts for the thesis experiment log.

## Evaluation path

The prototype supports two experimental conditions:

1. `heuristic`: deterministic baseline without the large model.
2. `huggingface`: LLM-assisted review and triage using `openai/gpt-oss-120b`.

This separation makes it possible to compare latency, gate decisions, and potential gains in contextual detection.

The CI workflow also runs local code quality checks and the Python test suite before security scanning so the DevSecOps pipeline covers both software correctness and security analysis.

## Scope boundaries

- In scope: source-code review, scanner fusion, CI/CD integration, vulnerability triage, and experimental reporting on intentionally vulnerable applications.
- Out of scope: adversarial attacks against the LLM itself, model red teaming, and full production hardening of the CI/CD environment.
