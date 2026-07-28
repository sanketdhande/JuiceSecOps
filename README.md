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
4. Implement a prototype that integrates Semgrep, Trivy, OWASP ZAP, and a Hugging Face `openai/gpt-oss-20b` review stage.
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
- `scripts/run_demo.sh`: local demo against the bundled sample reports.
- `scripts/run_juice_shop_pipeline.sh`: full pipeline example for Semgrep, Trivy, ZAP, and `juicesecops` with a configurable `--model-id`.
- `scripts/fetch_dvwa.sh`, `scripts/run_dvwa_pipeline.sh`, `config/policy-dvwa.toml`: the same set of tooling for the DVWA target -- see [DVWA target](#dvwa-target) below.
- `.github/workflows/`: split CI workflows for linting, reporting, Semgrep, Trivy, and ZAP stages.

## Hugging Face model integration

The only LLM provider in this project ([`HuggingFaceSecurityProvider`](src/juicesecops/providers/huggingface.py)) uses [`openai/gpt-oss-20b`](https://huggingface.co/openai/gpt-oss-20b) exactly as shown on the model card:

```python
from transformers import pipeline

model_id = "openai/gpt-oss-20b"

pipe = pipeline(
    "text-generation",
    model=model_id,
    torch_dtype="auto",
    device_map="auto",
)

messages = [
    {"role": "user", "content": "Explain quantum mechanics clearly and concisely."},
]

outputs = pipe(
    messages,
    max_new_tokens=256,
)
print(outputs[0]["generated_text"][-1])
```

It uses this model in two ways:

1. Review changed Juice Shop files and emit candidate vulnerabilities as structured JSON.
2. Triage normalized scanner findings into `block`, `review`, or `accept` decisions.

`torch`/`transformers`/`accelerate` are required dependencies (`pyproject.toml`) -- there is no non-LLM fallback provider, so `pip install -e '.[dev]'` always pulls them in and every `python -m juicesecops` run loads the model.

```bash
python -m pip install -e '.[dev]'
./scripts/fetch_juice_shop.sh
python -m juicesecops \
  --input samples/reports/semgrep.json \
  --model-id openai/gpt-oss-20b \
  --output results/huggingface
```

Or use the bundled script, which also runs Semgrep/Trivy/ZAP first:

```bash
./scripts/run_juice_shop_pipeline.sh targets/juice-shop openai/gpt-oss-20b
```

`--model-id` accepts any Hugging Face `transformers`-compatible text-generation model id -- pass a smaller checkpoint if a machine can't host the 20B-parameter default.

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
./scripts/run_dvwa_pipeline.sh targets/dvwa openai/gpt-oss-20b
```

CI: `dvwa-security-report.yml` mirrors `juice-shop-security-report.yml` (runs on push to `main` and `workflow_dispatch`).

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

This writes reports beneath `results/demo/`. Because `torch`/`transformers`/`accelerate` are required dependencies and there is no non-LLM fallback, this loads `openai/gpt-oss-20b` to triage the sample findings -- it needs enough GPU/CPU memory to host the model and is not a lightweight, model-free demo.

`targets/juice-shop` is a fresh, unmodified clone, so a plain `git diff HEAD` between its working tree and `HEAD` is always empty and the LLM change-review stage would find nothing to review. To avoid that, the CI workflow and `run_juice_shop_pipeline.sh` pass `--base-ref` set to git's well-known empty-tree object (`4b825dc642cb6eb9a060e54bf8d69288fbee4904`) together with `--head-ref HEAD`. That makes every in-scope file look "added", so the provider reviews a one-time baseline scan of the checkout instead of a real diff. `max_changed_files` and the priority order of `include_paths` in `config/policy.toml` control which files are spent from that budget first (backend `lib/`, `models/`, `routes/` before `frontend/src/`, which is much larger). If you instead want the LLM to inspect a real code change, edit files inside `targets/juice-shop/` first, or pass `--base-ref`/`--head-ref` from an actual branch comparison, and drop the empty-tree flags.

## CI/CD behavior

The GitHub Actions workflows (`juice-shop-security-report.yml`, `dvwa-security-report.yml`) run the scanner stages and the `openai/gpt-oss-20b` LLM stage on push to `main` and on `workflow_dispatch`. Standard GitHub-hosted runners have no GPU, so this is a real, CPU-bound ~20B-parameter model load in CI -- expect a slow run, and pass a smaller `--model-id` if it doesn't fit the job's time/memory budget.

The workflows clone OWASP Juice Shop / DVWA during CI instead of expecting the target application to be committed into this repository.

## Notes

- The deterministic gate is the final authority. The LLM is advisory but integrated into the decision pipeline.
- `targets/juice-shop` and `targets/dvwa` are intentionally ignored by git so this thesis repository can be published cleanly on GitHub.
- The `openai/gpt-oss-20b` model is the only analysis provider; there is no non-LLM fallback for machines without enough GPU/CPU memory to host it.
- The current prototype is optimized for reproducible thesis experiments rather than production deployment hardening.

## Further documentation

- `docs/ARCHITECTURE.md`
- `docs/THESIS_OBJECTIVES.md`
