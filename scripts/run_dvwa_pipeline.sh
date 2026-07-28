#!/usr/bin/env bash
# DVWA counterpart to run_juice_shop_pipeline.sh: clone DVWA -> Semgrep ->
# Trivy -> ZAP -> `python -m juicesecops` (src/juicesecops/), which is where
# the LLM diff-review + triage stages run (see pipeline.py). Both providers
# are hosted APIs -- no model weights ever run on this machine. PROVIDER
# selects groq (default: calls Groq's hosted API for MODEL_ID,
# providers/groq.py -- needs `pip install -e '.[dev]'` and a GROQ_API_KEY
# in the environment) or openrouter (calls OpenRouter's official SDK
# instead, providers/openrouter.py -- needs
# `pip install -e '.[openrouter,dev]'` and an OPENROUTER_API_KEY in the
# environment).
#
# Unlike Juice Shop (a single Node container with no setup step), DVWA is a
# PHP app with a MariaDB backend and ships its own docker-compose stack
# (targets/dvwa/compose.yml) plus a one-time "Create / Reset Database" step
# that must be triggered via setup.php before the app is usable -- both are
# handled below instead of a plain `docker run`.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_REPO="${1:-${ROOT_DIR}/targets/dvwa}"
PROVIDER="${2:-groq}"
MODEL_ID="${3:-openai/gpt-oss-20b}"
OUTPUT_DIR="${ROOT_DIR}/results/dvwa"
DVWA_URL="http://127.0.0.1:4280"

mkdir -p "${OUTPUT_DIR}"
chmod 777 "${OUTPUT_DIR}"

if [ ! -d "${TARGET_REPO}/.git" ] && [ ! -f "${TARGET_REPO}/compose.yml" ]; then
  "${ROOT_DIR}/scripts/fetch_dvwa.sh" "${TARGET_REPO}"
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

COOKIE_JAR="$(mktemp)"
cleanup() {
  rm -f "${COOKIE_JAR}"
  (cd "${TARGET_REPO}" && docker compose down --volumes >/dev/null 2>&1) || true
}
trap cleanup EXIT

(cd "${TARGET_REPO}" && docker compose down --volumes >/dev/null 2>&1) || true
(cd "${TARGET_REPO}" && docker compose up -d)

echo "Waiting for DVWA to accept connections..."
for _ in $(seq 1 30); do
  if curl -fsS "${DVWA_URL}/login.php" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

# DVWA has no working login or challenges until its database is created.
# setup.php is reachable pre-auth for exactly this reason (there is no user
# table to log in against yet) -- pull its CSRF token and submit the
# "Create / Reset Database" form once so the app is actually scannable.
echo "Initializing the DVWA database..."
SETUP_PAGE="$(curl -fsS -c "${COOKIE_JAR}" "${DVWA_URL}/setup.php" || true)"
SETUP_TOKEN="$(printf '%s' "${SETUP_PAGE}" | grep -oP "user_token'\s+value='\K[^']+" | head -n1 || true)"
if [ -n "${SETUP_TOKEN}" ]; then
  curl -fsS -b "${COOKIE_JAR}" -c "${COOKIE_JAR}" \
    --data-urlencode "create_db=Create / Reset Database" \
    --data-urlencode "user_token=${SETUP_TOKEN}" \
    "${DVWA_URL}/setup.php" >/dev/null || echo "Database setup request failed, continuing anyway"
else
  echo "Could not find setup.php's CSRF token, continuing without database setup"
fi

# ZAP runs with --network host (Linux-only, true of every runner this
# project targets) so it can reach DVWA on the host loopback the same way
# the curl calls above did, without depending on docker compose's internal
# network naming.
docker run --rm \
  --network host \
  -v "${OUTPUT_DIR}:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "${DVWA_URL}" -J zap.json 2>&1 | tee "${OUTPUT_DIR}/zap-baseline.log" || true

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
  --model-id "${MODEL_ID}" \
  --target-repo "${TARGET_REPO}" \
  --policy "${ROOT_DIR}/config/policy-dvwa.toml" \
  --base-ref "${EMPTY_TREE}" \
  --head-ref HEAD \
  --output "${OUTPUT_DIR}"
