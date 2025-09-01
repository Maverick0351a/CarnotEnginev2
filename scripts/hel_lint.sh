#!/usr/bin/env bash
set -euo pipefail
CFG=${1:-ops/hel_allowlist.txt}
echo "[*] HEL lint ${CFG}"
test -f "${CFG}" || { echo "allowlist not found"; exit 1; }
grep -E '^(#|$|https?://|tcp://|dns:)' "${CFG}" >/dev/null || { echo "invalid entries"; exit 1; }
echo "OK"
