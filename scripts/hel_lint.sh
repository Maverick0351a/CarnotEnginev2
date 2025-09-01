#!/usr/bin/env bash
set -euo pipefail
CFG=${1:-ops/hel_allowlist.txt}
PINS=${2:-ops/spki_pins.txt}

echo "[*] HEL lint ${CFG}"
if [ ! -f "${CFG}" ]; then
  echo "allowlist not found"
  exit 1
fi
# Allow comments/blank or explicit schemes host entries (http/https/tcp/dns)
if ! grep -E '^(#|$|https?://|http://|tcp://|dns:)' "${CFG}" >/dev/null; then
  echo "invalid entries"
  exit 1
fi

echo "[*] SPKI pins lint ${PINS}"
if [ -f "${PINS}" ]; then
  # Allow comments/blank or 'host sha256/<base64>'
  if grep -Ev '^(#|$|[A-Za-z0-9_.:-]+[[:space:]]+sha256/[A-Za-z0-9+/=]+)$' "${PINS}" | grep -q .; then
    echo "invalid spki pins entries"
    exit 1
  fi
  echo "pins OK"
else
  echo "pins file not present; skipping"
fi

echo "OK"
