#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_REPO="${1:-${ROOT_DIR}/targets/juice-shop}"
OUTPUT_DIR="${ROOT_DIR}/results/juice-shop"
NETWORK_NAME="juice-shop-net"

mkdir -p "${OUTPUT_DIR}"

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
  zap-baseline.py -t http://thesis-juice-shop:3000 -J zap.json >/dev/null || true

PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}" python3 -m juicesecops \
  --input "${OUTPUT_DIR}/semgrep.json" \
  --input "${OUTPUT_DIR}/trivy.json" \
  --input "${OUTPUT_DIR}/zap.json" \
  --provider heuristic \
  --target-repo "${TARGET_REPO}" \
  --output "${OUTPUT_DIR}"
