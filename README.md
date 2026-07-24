# Juice Shop LLM DevSecOps Thesis Prototype

This project is a new thesis-oriented prototype that uses [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) as the vulnerable target application and adds an LLM-based security analysis stage to a conventional DevSecOps pipeline.

The target application is fetched into `targets/juice-shop` on demand. A local checkout cloned on July 21, 2026 identified the upstream package as Juice Shop `20.1.1`, and the upstream project documents support for Node.js `22` through `26`.

## Thesis scope

This repository is scoped to the thesis question:

> How can Large Language Models be integrated into DevSecOps pipelines to improve automated security testing and vulnerability detection during CI/CD processes?

The implementation focuses on code analysis and vulnerability detection inside CI/CD workflows. It does not study adversarial attacks against machine learning models themselves.

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

## Research questions

This prototype is designed to support the following thesis questions:

1. How accurately can LLMs detect software vulnerabilities compared with traditional static analysis tools?
2. What types of vulnerabilities can LLM-based analysis detect that traditional tools may miss?
3. How can LLM-based vulnerability analysis be integrated into CI/CD pipelines without significantly increasing execution time?
4. What limitations and security risks arise when using LLMs for automated security testing?

The implementation exposes comparable scanner findings, LLM-generated findings, gate decisions, and runtime metadata so those questions can be evaluated experimentally.

## Implementation summary

- `src/juicesecops/`: Python package for parsing scanner reports, collecting Juice Shop git diffs, running LLM or heuristic analysis, and generating reports.
- `scripts/fetch_juice_shop.sh`: clones OWASP Juice Shop into `targets/juice-shop` when needed.
- `config/policy.toml`: deterministic gate and scope controls.
- `samples/reports/`: synthetic Semgrep, Trivy, and ZAP reports for offline demonstration.
- `scripts/run_demo.sh`: quick local demo without heavyweight external scanners.
- `scripts/run_juice_shop_pipeline.sh`: full pipeline example for Semgrep, Trivy, ZAP, and `juicesecops` with configurable provider/model.
- `scripts/run_juice_shop_pipeline_hf.sh`: full pipeline example using the Hugging Face LLM provider (`openai/gpt-oss-120b`).
- `scripts/run_juice_shop_pipeline_openweight.sh`: full pipeline example using a small, free open-weight security model (default `Foundation-Sec-8B-Reasoning`).
- `scripts/fetch_dvwa.sh`, `scripts/run_dvwa_pipeline*.sh`, `config/policy-dvwa.toml`: the same set of tooling for the DVWA target -- see [DVWA target](#dvwa-target) below.
- `.github/workflows/`: split CI workflows for linting, reporting, Semgrep, Trivy, and ZAP stages.

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

## Open-weight model provider

`src/juicesecops/providers/openweight.py` (`--provider openweight`) reuses `HuggingFaceSecurityProvider`'s prompts and `transformers` call, but defaults to a small, free, open-weight security model instead of `openai/gpt-oss-120b`. This gives a middle ground between the zero-model heuristic baseline and the 120B model: a real LLM that can plausibly run on a single GPU (or a quantized CPU build) rather than requiring server-class hardware.

`--model-id` accepts either a short alias or any Hugging Face repo id:

| Alias | Hugging Face repo | Notes |
| --- | --- | --- |
| `foundation-sec-8b-reasoning` (default) | `fdtn-ai/Foundation-Sec-8B-Reasoning` | Cisco Foundation AI, open-weight, reasoning-tuned specifically for cybersecurity tasks |
| `foundation-sec-8b` | `fdtn-ai/Foundation-Sec-8B` | Same family, non-reasoning base model |
| `pentest-7b` | `VextLabsinc/pentest-7b` | Qwen2.5-7B-Instruct fine-tuned on pentesting/offensive-security examples |
| `qwen-coder-7b` | `Qwen/Qwen2.5-Coder-7B-Instruct` | General-purpose open-weight coding model (non-security baseline). Note: "Qwen3-Coder-7B-Instruct" does not exist -- Qwen3-Coder only ships as 30B-A3B/480B-A35B MoE models -- so this uses Qwen's official dense 7B coder instead |
| `codegemma-7b` | `google/codegemma-7b-it` | General-purpose open-weight coding model (non-security baseline) |

```bash
python -m pip install -e '.[hf,dev]'
python -m juicesecops \
  --input samples/reports/semgrep.json \
  --provider openweight \
  --model-id foundation-sec-8b-reasoning \
  --output results/openweight
```

Or use the bundled script, which also runs Semgrep/Trivy/ZAP first:

```bash
./scripts/run_juice_shop_pipeline_openweight.sh targets/juice-shop pentest-7b
```

This still needs `pip install -e '.[hf,dev]'` and enough local GPU/CPU memory to host an ~7-8B model, so like the `huggingface` provider it does not run in GitHub Actions -- CI stays on `--provider heuristic`.

## Quantized (GGUF) provider and the multi-model CI workflow

`src/juicesecops/providers/gguf.py` (`--provider gguf`) runs a quantized GGUF build of the same small open-weight models via `llama-cpp-python` (CPU-only, via `llama.cpp`) instead of full-precision `transformers`. This is the provider that can actually complete on a standard GitHub-hosted runner, which has no GPU.

`--model-id` accepts a short alias from `GGUF_MODEL_CHOICES` (`foundation-sec-8b-reasoning`, `foundation-sec-8b`, `qwen-coder-7b`, `codegemma-7b` -- a subset of the `openweight` provider table above; `pentest-7b` is excluded here because `VextLabsinc/pentest-7b` has no `.gguf` file on huggingface.co, confirmed via the HF API's `siblings` list) or an explicit `"repo_id:filename-glob"` string:

```bash
python -m pip install -e '.[gguf,dev]'
python -m juicesecops \
  --input samples/reports/semgrep.json \
  --provider gguf \
  --model-id foundation-sec-8b-reasoning \
  --output results/gguf
```

**`GGUF_MODEL_CHOICES` is a best-effort mapping.** Community GGUF quantizations churn, and niche security fine-tunes in particular may not have one at all. Verify an alias's `repo_id`/`filename` on huggingface.co before relying on it, or bypass the table with an explicit `--model-id "org/repo:*Q4_K_M.gguf"`.

### `.github/workflows/juice-shop-security-report-openweight.yml`

A manual-only (`workflow_dispatch`) workflow that runs **every** model in `GGUF_MODEL_CHOICES` in CI and merges the results into one comparison report:

1. `scan` runs Semgrep/Trivy/ZAP once and uploads the JSON reports as an artifact.
2. `prepare-matrix` reads `GGUF_MODEL_CHOICES` straight from the Python package, so the matrix can't drift out of sync with the code.
3. `llm-review` is a matrix job, one leg per model, each running `--provider gguf --model-id <alias>` against the shared scanner reports, scoped with `--policy config/policy-openweight.toml` (same as `policy.toml` but `max_changed_files = 20` instead of 150 -- CPU inference costs one serial LLM call per file per model, so the full 150-file scope took over 5 hours per model and was still running when it hit GitHub's default 6-hour job ceiling). `continue-on-error` is set at the job level: a renamed/missing GGUF quantization for one model does not fail the whole workflow, it's just absent from the final comparison. `timeout-minutes: 120` makes a stuck/too-slow leg fail fast and visibly instead of silently riding out that 6-hour default.
4. `combine` downloads whichever per-model reports succeeded and runs the new `juicesecops-compare-models` CLI (`src/juicesecops/compare_models_cli.py`) to merge them into `comparison.md` / `comparison.json`, with the shared traditional (scanner) findings listed once and each model's LLM findings, severities, dispositions, and gate result listed side by side.

You can run the same merge locally against any set of `report.json` files produced with different `--provider`/`--model-id` combinations:

```bash
python -m juicesecops.compare_models_cli \
  --report foundation-sec-8b-reasoning=results/foundation-sec-8b-reasoning/report.json \
  --report qwen-coder-7b=results/qwen-coder-7b/report.json \
  --output results/comparison
```

## DVWA target

The pipeline also supports [DVWA (Damn Vulnerable Web Application)](https://github.com/digininja/DVWA) as a second target, alongside Juice Shop. `--target-repo` and `--policy` are already generic in `cli.py`/`pipeline.py`, so no package code changes were needed -- DVWA gets its own fetch script, policy file, pipeline scripts, and CI workflows mirroring the Juice Shop ones exactly:

| Juice Shop | DVWA |
| --- | --- |
| `scripts/fetch_juice_shop.sh` | `scripts/fetch_dvwa.sh` |
| `config/policy.toml` | `config/policy-dvwa.toml` |
| `scripts/run_juice_shop_pipeline.sh` / `_hf.sh` / `_openweight.sh` | `scripts/run_dvwa_pipeline.sh` / `_hf.sh` / `_openweight.sh` |
| `.github/workflows/juice-shop-security-report.yml` | `.github/workflows/dvwa-security-report.yml` |
| `.github/workflows/juice-shop-security-report-openweight.yml` | `.github/workflows/dvwa-security-report-openweight.yml` |

`config/policy-dvwa.toml` scopes the LLM diff-review stage to DVWA's PHP layout (`vulnerabilities/`, `hackable/`, `includes/`, `login.php`, `setup.php`, `config/`) instead of Juice Shop's TypeScript one.

### Why DVWA needs extra steps Juice Shop doesn't

Juice Shop is a single Node container with no setup step (`docker run bkimminich/juice-shop`). DVWA is a PHP app with a MariaDB backend and ships its own `compose.yml` (web + `db` services) in the cloned repo, so the pipeline scripts/workflows run that instead of a bare `docker run`. DVWA also has no working login or challenge pages until its database exists -- there's no user table to log in against on a fresh container -- so `setup.php` is deliberately reachable pre-auth. Every DVWA script/workflow does this once before scanning:

1. `docker compose up -d` from the cloned `targets/dvwa` checkout.
2. Poll `http://127.0.0.1:4280/login.php` until it responds.
3. `GET /setup.php`, scrape the CSRF `user_token` out of the HTML, and `POST` the "Create / Reset Database" form with it.
4. Run ZAP's baseline scan against `http://127.0.0.1:4280` with `--network host` (so the ZAP container reaches the same host loopback port `compose.yml` published, without depending on docker compose's internal network naming).

This only sets up the database -- it does not automate DVWA's own login or its per-session "security level" cookie (low/medium/high/impossible), so the ZAP baseline scan runs unauthenticated, the same as Juice Shop's.

```bash
./scripts/run_dvwa_pipeline.sh targets/dvwa heuristic
# or, for a real LLM instead of the regex heuristic:
./scripts/run_dvwa_pipeline_openweight.sh targets/dvwa foundation-sec-8b-reasoning
```

CI: `dvwa-security-report.yml` mirrors the default heuristic Juice Shop workflow (runs on push to `main` and `workflow_dispatch`); `dvwa-security-report-openweight.yml` mirrors the multi-model GGUF comparison workflow (`workflow_dispatch` only, since it's the slowest one).

## LLM and scanner comparison

The CLI now prints findings grouped as:

- `traditional`: findings from Semgrep, Trivy, ZAP, or other non-LLM scanners
- `llm`: findings generated by the diff-review stage (`llm-diff`)

This makes it easier to inspect what the LLM added beyond the traditional pipeline.

If you provide verified findings with `--ground-truth`, the report also computes an overlap-based precision comparison for:

- all findings combined
- traditional findings only
- LLM findings only

Example:

```bash
python -m juicesecops \
  --input samples/reports/semgrep.json \
  --input samples/reports/trivy.json \
  --ground-truth samples/reports/ground-truth.json \
  --provider heuristic \
  --output results/eval
```

The precision comparison is intended for thesis evaluation. It is only meaningful when the `--ground-truth` file contains manually verified findings in the normalized `findings` format or another supported JSON report format.

For the bundled demo, the comparison is tied to the Juice Shop target:

- target repository: `targets/juice-shop`
- scanner samples: `samples/reports/semgrep.json`, `trivy.json`, `zap.json`
- verified comparison set: `samples/reports/ground-truth.json`

The full pipeline and GitHub workflows also run Semgrep, Trivy, ZAP, and the Python security gate against `targets/juice-shop`.

## Methodology alignment

The repository is structured around the thesis methodology:

- Literature review support: `docs/ARCHITECTURE.md` and `docs/THESIS_OBJECTIVES.md` map the prototype to DevSecOps, LLM-assisted code analysis, and evaluation concerns.
- System design: the pipeline preserves traditional SAST, dependency/container scanning, and DAST stages while inserting LLM review in the middle of the CI/CD path.
- Prototype implementation: GitHub Actions workflows, Docker-compatible scanning scripts, and the Python orchestration package provide the experimental system.
- Experimental evaluation: repeatable JSON/Markdown artifacts, a heuristic baseline, and fixed vulnerable targets support comparison of detection coverage, false positives, and runtime.

The primary implemented target is OWASP Juice Shop, and DVWA is bundled as a second target (see [DVWA target](#dvwa-target) above) to demonstrate the approach generalizes across intentionally vulnerable systems rather than being Juice-Shop-specific. It can be extended further to other targets such as vulnerable microservices the same way DVWA was: a fetch script, a scoped policy file, and pipeline scripts/workflows pointing `--target-repo`/`--policy` at the new checkout.

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

`targets/juice-shop` is a fresh, unmodified clone, so a plain `git diff HEAD` between its working tree and `HEAD` is always empty and the LLM change-review stage would find nothing to review. To avoid that, the CI workflow and both `run_juice_shop_pipeline*.sh` scripts pass `--base-ref` set to git's well-known empty-tree object (`4b825dc642cb6eb9a060e54bf8d69288fbee4904`) together with `--head-ref HEAD`. That makes every in-scope file look "added", so the provider reviews a one-time baseline scan of the checkout instead of a real diff. `max_changed_files` and the priority order of `include_paths` in `config/policy.toml` control which files are spent from that budget first (backend `lib/`, `models/`, `routes/` before `frontend/src/`, which is much larger). If you instead want the LLM to inspect a real code change, edit files inside `targets/juice-shop/` first, or pass `--base-ref`/`--head-ref` from an actual branch comparison, and drop the empty-tree flags.

## CI/CD behavior

The GitHub Actions workflows run the deterministic baseline and scanner stages on `main`.
The current report workflow uses the heuristic provider for stable CI execution, because the full `openai/gpt-oss-120b` model is too large for standard GitHub-hosted runners.

For local LLM evaluation, use the Hugging Face provider with `./scripts/run_juice_shop_pipeline_hf.sh` or `./scripts/run_juice_shop_pipeline.sh ... huggingface ...`.

The workflow clones OWASP Juice Shop during CI instead of expecting the target application to be committed into this repository. The same applies to the DVWA workflows (`dvwa-security-report.yml`, `dvwa-security-report-openweight.yml`), which clone DVWA into `targets/dvwa` and default to the heuristic provider for the same reason.

## Notes

- The deterministic gate is the final authority. The LLM is advisory but integrated into the decision pipeline.
- `targets/juice-shop` and `targets/dvwa` are intentionally ignored by git so this thesis repository can be published cleanly on GitHub.
- The full 120B model is expensive and hardware-intensive. The heuristic provider is the local fallback for thesis development and tests.
- The current prototype is optimized for reproducible thesis experiments rather than production deployment hardening.

## Further documentation

- `docs/ARCHITECTURE.md`
- `docs/THESIS_OBJECTIVES.md`
