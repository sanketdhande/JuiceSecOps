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
4. Implement a prototype that integrates Semgrep, Trivy, OWASP ZAP, and an LLM review stage, run entirely through hosted APIs (Groq for `openai/gpt-oss-20b`, or OpenRouter for `meta-llama/llama-3.3-70b-instruct`) -- no model weights ever run on the local machine.
5. Support experimental evaluation through repeatable reports and sample inputs.

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

- `src/juicesecops/`: Python package for parsing scanner reports, collecting Juice Shop git diffs, running the LLM analysis, and generating reports.
- `scripts/fetch_juice_shop.sh`: clones OWASP Juice Shop into `targets/juice-shop` when needed.
- `config/policy.toml`: deterministic gate and scope controls.
- `samples/reports/`: synthetic Semgrep, Trivy, and ZAP reports for offline demonstration.
- `scripts/run_demo.sh`: local demo against the bundled sample reports (defaults to `--provider groq`).
- `scripts/run_juice_shop_pipeline.sh`: full pipeline example for Semgrep, Trivy, ZAP, and `juicesecops` with a configurable `--provider`/`--model-id`.
- `scripts/fetch_dvwa.sh`, `scripts/run_dvwa_pipeline.sh`, `config/policy-dvwa.toml`: the same set of tooling for the DVWA target -- see [DVWA target](#dvwa-target) below.
- `.github/workflows/`: split CI workflows for linting, Semgrep, Trivy, ZAP, and one reporting workflow per target/provider combination (see [CI/CD behavior](#cicd-behavior) below).

## LLM providers

The first three providers are hosted APIs -- **no model weights ever run on the local machine or in CI** for them -- and all four share the same `triage()`/`review_change()` prompts and JSON parsing (`providers/_prompted.py`), so results stay directly comparable:

| Provider | `--provider` | Model | Runs where | Needs |
| --- | --- | --- | --- | --- |
| [`GroqSecurityProvider`](src/juicesecops/providers/groq.py) (default) | `groq` | `openai/gpt-oss-20b` | Groq's hosted, OpenAI-compatible API | `pip install -e '.[dev]'` (stdlib only), a `GROQ_API_KEY` |
| [`OpenRouterSecurityProvider`](src/juicesecops/providers/openrouter.py) | `openrouter` | `meta-llama/llama-3.3-70b-instruct` | OpenRouter's official Python SDK | `pip install -e '.[openrouter,dev]'`, an `OPENROUTER_API_KEY` |
| [`HuggingFaceSecurityProvider`](src/juicesecops/providers/huggingface.py) | `huggingface` | `openai/gpt-oss-20b` | Hugging Face's hosted Inference Providers router | `pip install -e '.[dev]'` (stdlib only), an `HF_TOKEN` |
| [`LocalSecurityProvider`](src/juicesecops/providers/local.py) | `local` | `openai/gpt-oss-20b` (quantized GGUF) | In-process via llama.cpp, CPU only | `pip install -e '.[local,dev]'`, no API key -- just CPU/RAM/disk |

`--model-id` overrides the default for any of them, so e.g. `--provider openrouter --model-id openai/gpt-oss-20b` works too (any model each provider's respective host serves).

### Hosted: Groq's API

`GroqSecurityProvider` calls Groq's hosted, OpenAI-compatible chat-completions API (`https://api.groq.com/openai/v1/chat/completions`) for `openai/gpt-oss-20b` -- no local weights, no GPU, no download, just an HTTPS call over the standard library (`urllib`). This is the default provider, and the one CI workflows use.

For this specific model, Groq's free tier is more generous than OpenRouter's: **30 requests/minute and 1,000 requests/day** for `openai/gpt-oss-20b`, no credit card required (per [Groq's rate-limit docs](https://console.groq.com/docs/rate-limits)). OpenRouter also has a free (`:free` suffix) tier for this exact model, but it's capped at 20 requests/minute and only 50 requests/day without $10+ of purchased credit.

Requires `GROQ_API_KEY` in the environment (never pass it as `--model-id` or any other CLI argument -- argv ends up in shell history and CI logs):

```bash
export GROQ_API_KEY="gsk_..."
python -m pip install -e '.[dev]'
python -m juicesecops \
  --input samples/reports/semgrep.json \
  --provider groq \
  --output results/groq
```

Or use the bundled script:

```bash
./scripts/run_juice_shop_pipeline.sh targets/juice-shop groq
```

### Hosted: OpenRouter's SDK

`OpenRouterSecurityProvider` uses [OpenRouter's official Python SDK](https://pypi.org/project/openrouter/) (the `openrouter` PyPI package, not raw HTTP calls) to call `meta-llama/llama-3.3-70b-instruct` by default:

```python
from openrouter import OpenRouter
import os

with OpenRouter(api_key=os.getenv("OPENROUTER_API_KEY")) as client:
    response = client.chat.send(
        model="meta-llama/llama-3.3-70b-instruct",
        messages=[
            {"role": "user", "content": "Explain quantum computing in one sentence."}
        ],
    )
    print(response.choices[0].message.content)
```

This is a different model/host than Groq -- useful as a comparison point, or as an alternative if Groq is unavailable. The SDK handles retries for transient failures (429/5xx) itself, so `OpenRouterSecurityProvider` doesn't implement its own backoff loop the way the old raw-`urllib` OpenRouter provider used to.

**Why not run Llama 3.3 70B on Groq instead?** Groq is sunsetting its own `llama-3.3-70b-versatile` on 2026-08-16 (announced 2026-06-17, recommending `openai/gpt-oss-120b` as the replacement -- see [Groq's deprecations page](https://console.groq.com/docs/deprecations)), so it isn't a durable choice there. OpenRouter's hosting of the model is unaffected, since it's an entirely separate provider.

Requires the `openrouter` package (`pip install -e '.[openrouter,dev]'`) and `OPENROUTER_API_KEY` in the environment (never pass it as `--model-id` or any other CLI argument):

```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
python -m pip install -e '.[openrouter,dev]'
python -m juicesecops \
  --input samples/reports/semgrep.json \
  --provider openrouter \
  --output results/openrouter
```

Or use the bundled script:

```bash
./scripts/run_juice_shop_pipeline.sh targets/juice-shop openrouter
```

### Hosted: Hugging Face's Inference Providers router

`HuggingFaceSecurityProvider` calls Hugging Face's hosted, OpenAI-compatible Inference Providers router (`https://router.huggingface.co/v1/chat/completions`) for `openai/gpt-oss-20b` -- no local weights, no GPU, no download, just an HTTPS call over the standard library (`urllib`), the same style as `GroqSecurityProvider`. The router fans the request out to whichever backend (Together, Fireworks, Novita, etc.) currently serves the requested model, so it's a different hosted path to the same model Groq serves -- useful as a comparison point.

An earlier `HuggingFaceSecurityProvider` loaded `openai/gpt-oss-20b` in-process via `transformers.pipeline(...)`; that needs a GPU and ~40GB+ of RAM/VRAM and was removed as impractical on a standard GitHub-hosted runner. This provider only needs an `HF_TOKEN` and network access, like the other two.

Requires `HF_TOKEN` in the environment (never pass it as `--model-id` or any other CLI argument -- argv ends up in shell history and CI logs):

```bash
export HF_TOKEN="hf_..."
python -m pip install -e '.[dev]'
python -m juicesecops \
  --input samples/reports/semgrep.json \
  --provider huggingface \
  --output results/huggingface
```

Or use the bundled script:

```bash
./scripts/run_juice_shop_pipeline.sh targets/juice-shop huggingface
```

### Local: llama.cpp GGUF (CPU only, no API key)

`LocalSecurityProvider` runs a quantized GGUF build of `openai/gpt-oss-20b` in-process via [`llama-cpp-python`](https://pypi.org/project/llama-cpp-python/) instead of calling any hosted API. It exists specifically as a fallback for when hosted-API quota/credits (Groq, OpenRouter, or Hugging Face Inference Providers) run out: no account, no API key, no per-request billing -- only a one-time (cached) ~12GB model download from the Hugging Face Hub and whatever CPU/RAM the machine already has.

This is a real trade-off, not a free upgrade: quantized weights on CPU are much slower and lower-fidelity than any hosted provider, and the default GGUF file is already at the edge of what a standard GitHub-hosted runner's disk/RAM can hold (see the "Free disk space" step in the CI workflows below). If a run doesn't finish in time, lower `max_changed_files` in `config/policy.toml`/`config/policy-dvwa.toml`, or pass `--skip-change-review`.

No environment variable is required:

```bash
python -m pip install -e '.[local,dev]'
python -m juicesecops \
  --input samples/reports/semgrep.json \
  --provider local \
  --output results/local
```

Or use the bundled script:

```bash
./scripts/run_juice_shop_pipeline.sh targets/juice-shop local
```

`--model-id` accepts any `"repo_id:filename-glob"` string if you want a different GGUF build/quantization than the default.

## DVWA target

The pipeline also supports [DVWA (Damn Vulnerable Web Application)](https://github.com/digininja/DVWA) as a second target, alongside Juice Shop. `--target-repo` and `--policy` are already generic in `cli.py`/`pipeline.py`, so no package code changes were needed -- DVWA gets its own fetch script, policy file, pipeline script, and CI workflows mirroring the Juice Shop ones exactly:

| Juice Shop | DVWA |
| --- | --- |
| `scripts/fetch_juice_shop.sh` | `scripts/fetch_dvwa.sh` |
| `config/policy.toml` | `config/policy-dvwa.toml` |
| `scripts/run_juice_shop_pipeline.sh` | `scripts/run_dvwa_pipeline.sh` |
| `.github/workflows/juice-shop-security-report.yml` (Groq) | `.github/workflows/dvwa-security-report.yml` (Groq) |
| `.github/workflows/juice-shop-security-report-openrouter.yml` | `.github/workflows/dvwa-security-report-openrouter.yml` |
| `.github/workflows/juice-shop-security-report-huggingface.yml` | `.github/workflows/dvwa-security-report-huggingface.yml` |
| `.github/workflows/juice-shop-security-report-local.yml` | `.github/workflows/dvwa-security-report-local.yml` |

`config/policy-dvwa.toml` scopes the LLM diff-review stage to DVWA's PHP layout (`vulnerabilities/`, `hackable/`, `includes/`, `login.php`, `setup.php`, `config/`) instead of Juice Shop's TypeScript one.

### Why DVWA needs extra steps Juice Shop doesn't

Juice Shop is a single Node container with no setup step (`docker run bkimminich/juice-shop`). DVWA is a PHP app with a MariaDB backend and ships its own `compose.yml` (web + `db` services) in the cloned repo, so the pipeline script/workflow run that instead of a bare `docker run`. DVWA also has no working login or challenge pages until its database exists -- there's no user table to log in against on a fresh container -- so `setup.php` is deliberately reachable pre-auth. The DVWA script/workflow does this once before scanning:

1. `docker compose up -d` from the cloned `targets/dvwa` checkout.
2. Poll `http://127.0.0.1:4280/login.php` until it responds.
3. `GET /setup.php`, scrape the CSRF `user_token` out of the HTML, and `POST` the "Create / Reset Database" form with it.
4. Run ZAP's baseline scan against `http://127.0.0.1:4280` with `--network host` (so the ZAP container reaches the same host loopback port `compose.yml` published, without depending on docker compose's internal network naming).

This only sets up the database -- it does not automate DVWA's own login or its per-session "security level" cookie (low/medium/high/impossible), so the ZAP baseline scan runs unauthenticated, the same as Juice Shop's.

```bash
./scripts/run_dvwa_pipeline.sh targets/dvwa groq
```

CI: `dvwa-security-report.yml`/`dvwa-security-report-openrouter.yml`/`dvwa-security-report-huggingface.yml`/`dvwa-security-report-local.yml` mirror `juice-shop-security-report.yml`/`juice-shop-security-report-openrouter.yml`/`juice-shop-security-report-huggingface.yml`/`juice-shop-security-report-local.yml` (run on `workflow_dispatch`) -- see [CI/CD behavior](#cicd-behavior) below for why there are 8 separate workflows and which API key/token each one uses.

## LLM and scanner comparison

The CLI prints findings grouped as:

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
- Experimental evaluation: repeatable JSON/Markdown artifacts and fixed vulnerable targets support comparison of detection coverage, false positives, and runtime.

The primary implemented target is OWASP Juice Shop, and DVWA is bundled as a second target (see [DVWA target](#dvwa-target) above) to demonstrate the approach generalizes across intentionally vulnerable systems rather than being Juice-Shop-specific. It can be extended further to other targets such as vulnerable microservices the same way DVWA was: a fetch script, a scoped policy file, and a pipeline script/workflow pointing `--target-repo`/`--policy` at the new checkout.

## Quick start

```bash
cd juice-shop-llm-devsecops
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'

./scripts/run_demo.sh
```

This writes reports beneath `results/demo/`. `run_demo.sh` defaults to `--provider groq`, so triaging the sample findings calls Groq's hosted API for `openai/gpt-oss-20b` (export `GROQ_API_KEY` first) -- pass `openrouter` as the first argument to use OpenRouter's SDK instead (needs `pip install -e '.[openrouter,dev]'` and `OPENROUTER_API_KEY`), `huggingface` to use Hugging Face's Inference Providers router instead (needs `HF_TOKEN`), or `local` to run a quantized GGUF build via llama.cpp instead (needs `pip install -e '.[local,dev]'`, no API key, CPU only). None of the hosted providers needs a GPU or downloads any model weights; `local` is the exception -- it downloads and runs the GGUF file itself.

`targets/juice-shop` is a fresh, unmodified clone, so a plain `git diff HEAD` between its working tree and `HEAD` is always empty and the LLM change-review stage would find nothing to review. To avoid that, the CI workflow and `run_juice_shop_pipeline.sh` pass `--base-ref` set to git's well-known empty-tree object (`4b825dc642cb6eb9a060e54bf8d69288fbee4904`) together with `--head-ref HEAD`. That makes every in-scope file look "added", so the provider reviews a one-time baseline scan of the checkout instead of a real diff. `max_changed_files` and the priority order of `include_paths` in `config/policy.toml` control which files are spent from that budget first (backend `lib/`, `models/`, `routes/` before `frontend/src/`, which is much larger). If you instead want the LLM to inspect a real code change, edit files inside `targets/juice-shop/` first, or pass `--base-ref`/`--head-ref` from an actual branch comparison, and drop the empty-tree flags.

## CI/CD behavior

There are **8 reporting workflows**, one per target/provider combination, each fully self-contained (its own Semgrep/Trivy/ZAP scan, not shared with its siblings):

| Workflow | Target | Provider | Model |
| --- | --- | --- | --- |
| `juice-shop-security-report.yml` | Juice Shop | Groq | `openai/gpt-oss-20b` |
| `juice-shop-security-report-openrouter.yml` | Juice Shop | OpenRouter | `meta-llama/llama-3.3-70b-instruct` |
| `juice-shop-security-report-huggingface.yml` | Juice Shop | Hugging Face | `openai/gpt-oss-20b` |
| `juice-shop-security-report-local.yml` | Juice Shop | Local (llama.cpp) | `openai/gpt-oss-20b` (GGUF) |
| `dvwa-security-report.yml` | DVWA | Groq | `openai/gpt-oss-20b` |
| `dvwa-security-report-openrouter.yml` | DVWA | OpenRouter | `meta-llama/llama-3.3-70b-instruct` |
| `dvwa-security-report-huggingface.yml` | DVWA | Hugging Face | `openai/gpt-oss-20b` |
| `dvwa-security-report-local.yml` | DVWA | Local (llama.cpp) | `openai/gpt-oss-20b` (GGUF) |

They're separate workflow files rather than multiple steps in one workflow so the Groq, OpenRouter, Hugging Face, and local runs are **independent GitHub Actions jobs that run in parallel** instead of one job doing every pass sequentially (which roughly doubled wall-clock time when just Groq and OpenRouter were combined). Only the "local" workflows load a model on the runner itself (a quantized GGUF build, CPU-only, via llama.cpp) -- the other three are hosted APIs, so standard GitHub-hosted runners' lack of a GPU is a non-issue for them. Each workflow runs on `workflow_dispatch`, and uploads its own artifact (`juice-shop-security-report`, `juice-shop-security-report-openrouter`, `juice-shop-security-report-huggingface`, `juice-shop-security-report-local`, `dvwa-security-report`, `dvwa-security-report-openrouter`, `dvwa-security-report-huggingface`, `dvwa-security-report-local`).

The Juice Shop and DVWA workflows intentionally use **separate API keys/tokens** so the two targets don't share one account's rate-limit budget. The "local" workflows need no secret at all:

| Secret | Used by |
| --- | --- |
| `GROQ_API_KEY` | `juice-shop-security-report.yml` |
| `OPENROUTER_API_KEY` | `juice-shop-security-report-openrouter.yml` |
| `HF_TOKEN` | `juice-shop-security-report-huggingface.yml` |
| _(none)_ | `juice-shop-security-report-local.yml` |
| `GROQ_API_KEY2` | `dvwa-security-report.yml` |
| `OPENROUTER_API_KEY2` | `dvwa-security-report-openrouter.yml` |
| `HF_TOKEN2` | `dvwa-security-report-huggingface.yml` |
| _(none)_ | `dvwa-security-report-local.yml` |

All six secrets above are repository secrets (Settings -> Secrets and variables -> Actions -> New repository secret). Without the relevant one, that workflow's gate step fails immediately with the `RuntimeError` `GroqSecurityProvider.__init__`/`OpenRouterSecurityProvider.__init__`/`HuggingFaceSecurityProvider.__init__` raises when the key is missing -- the other workflows are unaffected, since they're independent runs. The "local" workflows can't hit this failure mode at all (no key to be missing), at the cost of the CPU-only speed/fidelity trade-off described in [LLM providers](#llm-providers) above.

The workflows clone OWASP Juice Shop / DVWA during CI instead of expecting the target application to be committed into this repository.

## Notes

- The deterministic gate is the final authority. The LLM is advisory but integrated into the decision pipeline.
- `targets/juice-shop` and `targets/dvwa` are intentionally ignored by git so this thesis repository can be published cleanly on GitHub.
- `openai/gpt-oss-20b` (via Groq, Hugging Face's Inference Providers router, or a quantized GGUF build run locally via llama.cpp) is the primary model; `meta-llama/llama-3.3-70b-instruct` (via OpenRouter) is available as an alternative -- see [LLM providers](#llm-providers) above. Groq, OpenRouter, and Hugging Face are hosted APIs; the local llama.cpp provider is the only one that loads model weights on the machine running it, and exists as a no-API-key fallback for when hosted quota/credits run out.
- The current prototype is optimized for reproducible thesis experiments rather than production deployment hardening.

## Further documentation

- `docs/ARCHITECTURE.md`
- `docs/THESIS_OBJECTIVES.md`
