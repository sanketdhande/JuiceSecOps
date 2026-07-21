#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/results/demo"

mkdir -p "${OUTPUT_DIR}"

PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}" python3 -m juicesecops \
  --input "${ROOT_DIR}/samples/reports/semgrep.json" \
  --input "${ROOT_DIR}/samples/reports/trivy.json" \
  --input "${ROOT_DIR}/samples/reports/zap.json" \
  --provider heuristic \
  --target-repo "${ROOT_DIR}/targets/juice-shop" \
  --skip-change-review \
  --output "${OUTPUT_DIR}" \
  --no-fail

printf 'Wrote demo report to %s\n' "${OUTPUT_DIR}"
