#!/usr/bin/env bash
# Local equivalent of .github/workflows/juice-shop-security-report.yml:
# clone Juice Shop -> Semgrep -> Trivy -> ZAP -> `python -m juicesecops`
# (src/juicesecops/), which is where the LLM diff-review + triage stages
# run (see pipeline.py). PROVIDER may be groq/openai/openrouter/
# huggingface/local. OpenAI, Groq, OpenRouter, and Hugging Face are hosted
# APIs -- no model weights ever run on this machine for them. The optional
# third argument overrides the provider's own default model id.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_REPO="${1:-${ROOT_DIR}/targets/juice-shop}"
PROVIDER="${2:-groq}"
MODEL_ID="${3:-}"
OUTPUT_DIR="${ROOT_DIR}/results/juice-shop"
NETWORK_NAME="juice-shop-net"
MODEL_ARG=()

if [ -n "${MODEL_ID}" ]; then
  MODEL_ARG=(--model-id "${MODEL_ID}")
fi

mkdir -p "${OUTPUT_DIR}"
chmod 777 "${OUTPUT_DIR}"

if [ ! -d "${TARGET_REPO}/.git" ] && [ ! -f "${TARGET_REPO}/package.json" ]; then
  "${ROOT_DIR}/scripts/fetch_juice_shop.sh" "${TARGET_REPO}"
fi

if ! command -v semgrep >/dev/null 2>&1; then
  echo "semgrep is required for the full pipeline"
  exit 1
fi

if ! command -v trivy >/dev/null 2>&1; then
  echo "trivy is required for the full pipeline"
  exit 1
fi

semgrep --config p/owasp-top-ten --json --output "${OUTPUT_DIR}/semgrep.json" "${TARGET_REPO}"
trivy fs --scanners vuln,secret --format json --output "${OUTPUT_DIR}/trivy.json" "${TARGET_REPO}"

docker network inspect "${NETWORK_NAME}" >/dev/null 2>&1 || docker network create "${NETWORK_NAME}" >/dev/null
docker rm -f thesis-juice-shop >/dev/null 2>&1 || true
docker run -d --name thesis-juice-shop --network "${NETWORK_NAME}" -p 3000:3000 bkimminich/juice-shop >/dev/null
trap 'docker rm -f thesis-juice-shop >/dev/null 2>&1 || true' EXIT

docker run --rm \
  --network "${NETWORK_NAME}" \
  -v "${OUTPUT_DIR}:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://thesis-juice-shop:3000 -J zap.json 2>&1 | tee "${OUTPUT_DIR}/zap-baseline.log" || true

echo "Contents of ${OUTPUT_DIR} after ZAP:"
ls -la "${OUTPUT_DIR}" || true

ZAP_INPUT=""
if [ -f "${OUTPUT_DIR}/zap.json" ]; then
  ZAP_INPUT="--input ${OUTPUT_DIR}/zap.json"
else
  echo "ZAP report not found, skipping ZAP input"
fi

# TARGET_REPO is a fresh clone with no working-tree edits, so a plain
# `git diff HEAD` is always empty and the LLM change-review stage never
# runs. Diff against git's well-known empty-tree object instead, so every
# in-scope file is treated as "added" and reviewed as a baseline scan.
EMPTY_TREE=4b825dc642cb6eb9a060e54bf8d69288fbee4904

PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}" python3 -m juicesecops \
  --input "${OUTPUT_DIR}/semgrep.json" \
  --input "${OUTPUT_DIR}/trivy.json" \
  $ZAP_INPUT \
  --provider "${PROVIDER}" \
  "${MODEL_ARG[@]}" \
  --target-repo "${TARGET_REPO}" \
  --base-ref "${EMPTY_TREE}" \
  --head-ref HEAD \
  --output "${OUTPUT_DIR}"
