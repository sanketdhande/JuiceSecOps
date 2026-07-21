#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_REPO="${1:-${ROOT_DIR}/targets/juice-shop}"
TARGET_PARENT="$(dirname "${TARGET_REPO}")"

mkdir -p "${TARGET_PARENT}"

if [ -d "${TARGET_REPO}/.git" ] || [ -f "${TARGET_REPO}/package.json" ]; then
  printf 'Juice Shop already present at %s\n' "${TARGET_REPO}"
  exit 0
fi

git clone --depth 1 https://github.com/juice-shop/juice-shop.git "${TARGET_REPO}"
printf 'Cloned OWASP Juice Shop to %s\n' "${TARGET_REPO}"
