# Juice Shop LLM DevSecOps Thesis Prototype

This project is a new thesis-oriented prototype that uses [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) as the vulnerable target application and adds an LLM-based security analysis stage to a conventional DevSecOps pipeline.

The target application is fetched into `targets/juice-shop` on demand. A local checkout cloned on July 21, 2026 identified the upstream package as Juice Shop `20.1.1`, and the upstream project documents support for Node.js `22` through `26`.

## Thesis objectives covered

1. Analyze existing DevSecOps security testing techniques by combining SAST, dependency scanning, secret detection, and DAST report ingestion.
2. Evaluate LLM capability for vulnerability detection by reviewing code changes and triaging scanner findings.
3. Design a DevSecOps pipeline architecture that inserts an LLM-based security analyzer after traditional scanning stages.
4. Implement a prototype that integrates Semgrep, Trivy, OWASP ZAP, and a Hugging Face `openai/gpt-oss-120b` review stage.
5. Support experimental evaluation through repeatable reports, sample inputs, and a deterministic heuristic baseline for comparison.

## Architecture

```text
Developer Commit
        |
        v
CI/CD Pipeline Trigger
        |
        v
Build Stage
        |
        v
Static Security Analysis (Semgrep)
        |
        v
Dependency / Secret / Container Scanning (Trivy)
        |
        v
LLM-Based Security Analyzer
  - reviews changed Juice Shop files
  - triages normalized scanner findings
        |
        v
Dynamic Security Testing (OWASP ZAP)
        |
        v
Security Report + Deterministic Gate
```

## Implementation summary

- `src/juicesecops/`: Python package for parsing scanner reports, collecting Juice Shop git diffs, running LLM or heuristic analysis, and generating reports.
- `scripts/fetch_juice_shop.sh`: clones OWASP Juice Shop into `targets/juice-shop` when needed.
- `config/policy.toml`: deterministic gate and scope controls.
- `samples/reports/`: synthetic Semgrep, Trivy, and ZAP reports for offline demonstration.
- `scripts/run_demo.sh`: quick local demo without heavyweight external scanners.
- `scripts/run_juice_shop_pipeline.sh`: full pipeline example for Semgrep, Trivy, ZAP, and `juicesecops` with configurable provider/model.
- `scripts/run_juice_shop_pipeline_hf.sh`: full pipeline example using the Hugging Face LLM provider.
- `.github/workflows/juice-shop-security.yml`: CI example matching the thesis architecture.

## Hugging Face model integration

The primary LLM provider in this project uses the exact model family you requested:

```python
from transformers import pipeline
import torch

model_id = "openai/gpt-oss-120b"

pipe = pipeline(
    "text-generation",
    model=model_id,
    torch_dtype="auto",
    device_map="auto",
)
```

The implementation lives in `src/juicesecops/providers/huggingface.py`. It uses this model in two ways:

1. Review changed Juice Shop files and emit candidate vulnerabilities as structured JSON.
2. Triage normalized scanner findings into `block`, `review`, or `accept` decisions.

The heuristic provider stays available so the thesis pipeline can still be tested on machines without enough GPU memory for a 120B model.

## Quick start

```bash
cd juice-shop-llm-devsecops
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'

./scripts/run_demo.sh
```

This writes reports beneath `results/demo/`.

## Run with the Hugging Face provider

Install the optional dependencies on a machine that can host the model:

```bash
python -m pip install -e '.[hf,dev]'
./scripts/fetch_juice_shop.sh
```

Then run the local Hugging Face evaluation:

```bash
./scripts/run_juice_shop_pipeline_hf.sh
```

Or use the generic pipeline script with a selected provider and model:

```bash
./scripts/run_juice_shop_pipeline.sh targets/juice-shop huggingface openai/gpt-oss-120b
```

If you want the LLM to inspect actual code changes, edit files inside `targets/juice-shop/` first or pass `--base-ref` and `--head-ref` from a real branch comparison.

## CI/CD behavior

The GitHub Actions workflows run the deterministic baseline and scanner stages on `main`.
The current report workflow uses the heuristic provider for stable CI execution, because the full `openai/gpt-oss-120b` model is too large for standard GitHub-hosted runners.

For local LLM evaluation, use the Hugging Face provider with `./scripts/run_juice_shop_pipeline_hf.sh` or `./scripts/run_juice_shop_pipeline.sh ... huggingface ...`.

The workflow clones OWASP Juice Shop during CI instead of expecting the target application to be committed into this repository.

## Notes

- The deterministic gate is the final authority. The LLM is advisory but integrated into the decision pipeline.
- `targets/juice-shop` is intentionally ignored by git so this thesis repository can be published cleanly on GitHub.
- The full 120B model is expensive and hardware-intensive. The heuristic provider is the local fallback for thesis development and tests.

## Further documentation

- `docs/ARCHITECTURE.md`
- `docs/THESIS_OBJECTIVES.md`
