#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_REPO="${1:-${ROOT_DIR}/targets/dvwa}"
TARGET_PARENT="$(dirname "${TARGET_REPO}")"

mkdir -p "${TARGET_PARENT}"

if [ -d "${TARGET_REPO}/.git" ] || [ -f "${TARGET_REPO}/compose.yml" ]; then
  printf 'DVWA already present at %s\n' "${TARGET_REPO}"
  exit 0
fi

git clone --depth 1 https://github.com/digininja/DVWA.git "${TARGET_REPO}"
printf 'Cloned DVWA to %s\n' "${TARGET_REPO}"
