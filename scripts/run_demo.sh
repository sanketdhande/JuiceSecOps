#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/results/demo"
TARGET_REPO="${ROOT_DIR}/targets/juice-shop"

mkdir -p "${OUTPUT_DIR}"

if [ ! -d "${TARGET_REPO}/.git" ] && [ ! -f "${TARGET_REPO}/package.json" ]; then
  "${ROOT_DIR}/scripts/fetch_juice_shop.sh" "${TARGET_REPO}"
fi

PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}" python3 -m juicesecops \
  --input "${ROOT_DIR}/samples/reports/semgrep.json" \
  --input "${ROOT_DIR}/samples/reports/trivy.json" \
  --input "${ROOT_DIR}/samples/reports/zap.json" \
  --ground-truth "${ROOT_DIR}/samples/reports/ground-truth.json" \
  --provider heuristic \
  --target-repo "${TARGET_REPO}" \
  --skip-change-review \
  --output "${OUTPUT_DIR}" \
  --no-fail

printf 'Wrote demo report to %s\n' "${OUTPUT_DIR}"
