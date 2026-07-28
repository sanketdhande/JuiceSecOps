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
4. Implement a prototype that integrates Semgrep, Trivy, OWASP ZAP, and an LLM review stage, run entirely through hosted APIs (Groq for `openai/gpt-oss-120b`, or OpenRouter for `meta-llama/llama-3.3-70b-instruct`) -- no model weights ever run on the local machine.
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
- `.github/workflows/`: split CI workflows for linting, reporting, Semgrep, Trivy, and ZAP stages.

## LLM providers

Both providers are hosted APIs -- **no model weights ever run on the local machine or in CI**, and both share the same `triage()`/`review_change()` prompts and JSON parsing (`providers/_prompted.py`), so results stay directly comparable:

| Provider | `--provider` | Model | Runs where | Needs |
| --- | --- | --- | --- | --- |
| [`GroqSecurityProvider`](src/juicesecops/providers/groq.py) (default) | `groq` | `openai/gpt-oss-120b` | Groq's hosted, OpenAI-compatible API | `pip install -e '.[dev]'` (stdlib only), a `GROQ_API_KEY` |
| [`OpenRouterSecurityProvider`](src/juicesecops/providers/openrouter.py) | `openrouter` | `meta-llama/llama-3.3-70b-instruct` | OpenRouter's official Python SDK | `pip install -e '.[openrouter,dev]'`, an `OPENROUTER_API_KEY` |

`--model-id` overrides the default for either, so e.g. `--provider openrouter --model-id openai/gpt-oss-120b` works too (any model both providers' respective hosts serve).

### Hosted: Groq's API

`GroqSecurityProvider` calls Groq's hosted, OpenAI-compatible chat-completions API (`https://api.groq.com/openai/v1/chat/completions`) for `openai/gpt-oss-120b` -- no local weights, no GPU, no download, just an HTTPS call over the standard library (`urllib`). This is the default provider, and the one CI workflows use.

For this specific model, Groq's free tier is genuinely free: **30 requests/minute and 1,000 requests/day** for `openai/gpt-oss-120b`, no credit card required (per [Groq's rate-limit docs](https://console.groq.com/docs/rate-limits)). OpenRouter has no free variant of this model at all -- `openai/gpt-oss-120b` is paid-only there (~$0.03/$0.17 per 1M input/output tokens); only the smaller `openai/gpt-oss-20b` has an OpenRouter `:free` tier (and even that is capped at 20 requests/minute and 50 requests/day without $10+ of purchased credit).

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

## DVWA target

The pipeline also supports [DVWA (Damn Vulnerable Web Application)](https://github.com/digininja/DVWA) as a second target, alongside Juice Shop. `--target-repo` and `--policy` are already generic in `cli.py`/`pipeline.py`, so no package code changes were needed -- DVWA gets its own fetch script, policy file, pipeline script, and CI workflow mirroring the Juice Shop ones exactly:

| Juice Shop | DVWA |
| --- | --- |
| `scripts/fetch_juice_shop.sh` | `scripts/fetch_dvwa.sh` |
| `config/policy.toml` | `config/policy-dvwa.toml` |
| `scripts/run_juice_shop_pipeline.sh` | `scripts/run_dvwa_pipeline.sh` |
| `.github/workflows/juice-shop-security-report.yml` | `.github/workflows/dvwa-security-report.yml` |

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

CI: `dvwa-security-report.yml` mirrors `juice-shop-security-report.yml` (runs on push to `main` and `workflow_dispatch`, `--provider groq`).

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

This writes reports beneath `results/demo/`. `run_demo.sh` defaults to `--provider groq`, so triaging the sample findings calls Groq's hosted API for `openai/gpt-oss-120b` (export `GROQ_API_KEY` first) -- pass `openrouter` as the first argument to use OpenRouter's SDK instead (needs `pip install -e '.[openrouter,dev]'` and `OPENROUTER_API_KEY`). Neither provider needs a GPU or downloads any model weights.

`targets/juice-shop` is a fresh, unmodified clone, so a plain `git diff HEAD` between its working tree and `HEAD` is always empty and the LLM change-review stage would find nothing to review. To avoid that, the CI workflow and `run_juice_shop_pipeline.sh` pass `--base-ref` set to git's well-known empty-tree object (`4b825dc642cb6eb9a060e54bf8d69288fbee4904`) together with `--head-ref HEAD`. That makes every in-scope file look "added", so the provider reviews a one-time baseline scan of the checkout instead of a real diff. `max_changed_files` and the priority order of `include_paths` in `config/policy.toml` control which files are spent from that budget first (backend `lib/`, `models/`, `routes/` before `frontend/src/`, which is much larger). If you instead want the LLM to inspect a real code change, edit files inside `targets/juice-shop/` first, or pass `--base-ref`/`--head-ref` from an actual branch comparison, and drop the empty-tree flags.

## CI/CD behavior

The GitHub Actions workflows (`juice-shop-security-report.yml`, `dvwa-security-report.yml`) run the scanner stages and the `openai/gpt-oss-120b` LLM stage on push to `main` and on `workflow_dispatch`, using `--provider groq` (Groq's hosted API) rather than loading the model locally -- standard GitHub-hosted runners have no GPU, so this avoids that limitation entirely instead of working around it. Both workflows need a **`GROQ_API_KEY` repository secret** (Settings -> Secrets and variables -> Actions -> New repository secret); without it, the `llm-review`/gate step fails immediately with the `RuntimeError` `GroqSecurityProvider.__init__` raises when the key is missing.

The workflows clone OWASP Juice Shop / DVWA during CI instead of expecting the target application to be committed into this repository.

## Notes

- The deterministic gate is the final authority. The LLM is advisory but integrated into the decision pipeline.
- `targets/juice-shop` and `targets/dvwa` are intentionally ignored by git so this thesis repository can be published cleanly on GitHub.
- `openai/gpt-oss-120b` (via Groq) is the primary model; `meta-llama/llama-3.3-70b-instruct` (via OpenRouter) is available as an alternative -- see [LLM providers](#llm-providers) above. Both are hosted APIs; there is no local-inference or non-LLM fallback provider.
- The current prototype is optimized for reproducible thesis experiments rather than production deployment hardening.

## Further documentation

- `docs/ARCHITECTURE.md`
- `docs/THESIS_OBJECTIVES.md`
